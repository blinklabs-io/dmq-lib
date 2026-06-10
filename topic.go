// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dmq

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blinklabs-io/gouroboros/cbor"
	pcommon "github.com/blinklabs-io/gouroboros/protocol/common"
)

type topicRuntime struct {
	name   string
	cfg    TopicConfig
	logger *slog.Logger
	clock  Clock

	mu          sync.Mutex
	closed      bool
	queue       []DmqMessage
	seen        map[string]time.Time
	subscribers map[uint64]chan Message
	nextSubID   atomic.Uint64

	peerSelector *PeerSelector
}

func newTopicRuntime(name string, cfg TopicConfig, logger *slog.Logger, clock Clock) *topicRuntime {
	if cfg.Authentication.Required && cfg.Authentication.Authenticator == nil {
		cfg.Authentication.Authenticator = pcommon.NewMessageAuthenticator(logger)
		pcommon.ApplyDefaultKESVerifier(cfg.Authentication.Authenticator)
	}
	rt := &topicRuntime{
		name:        name,
		cfg:         cfg,
		logger:      logger,
		clock:       clock,
		queue:       make([]DmqMessage, 0, cfg.Queue.MaxMessages),
		seen:        make(map[string]time.Time),
		subscribers: make(map[uint64]chan Message),
		peerSelector: NewPeerSelector(PeerSelectionConfig{
			TopologyQuota:  cfg.Discovery.TopologyQuota,
			PeerShareQuota: cfg.Discovery.PeerSharingQuota,
			LedgerQuota:    cfg.Discovery.LedgerPeers.Target,
			BigLedgerQuota: cfg.Discovery.LedgerPeers.BigLedgerTarget,
		}),
	}
	rt.peerSelector.AddPeers(TopologyPeers(cfg.Discovery.Topology))
	rt.peerSelector.AddPeers(cfg.Discovery.StaticPeers)
	return rt
}

func (t *topicRuntime) publish(ctx context.Context, body []byte) (*DmqMessage, error) {
	if t.cfg.Signer == nil {
		return nil, ErrSignerRequired
	}
	payload, err := NewMessagePayload(t.clock.Now(), t.cfg.TTL.DefaultTTL, body)
	if err != nil {
		return nil, err
	}
	msg, err := t.cfg.Signer.Sign(ctx, t.name, payload)
	if err != nil {
		return nil, err
	}
	if err := t.submitSigned(ctx, msg, MessageSourceLocal, nil); err != nil {
		return nil, err
	}
	return msg, nil
}

func (t *topicRuntime) submitSigned(ctx context.Context, msg *DmqMessage, source MessageSource, peer *Peer) error {
	if msg == nil {
		return errors.New("message is nil")
	}
	if err := normalizeAndValidateMessage(msg); err != nil {
		t.callRejected(ctx, msg, rejectReasonFromError(err))
		return err
	}
	if err := validateMessageTTL(msg, t.clock.Now(), t.cfg.TTL); err != nil {
		t.callRejected(ctx, msg, rejectReasonFromError(err))
		return err
	}
	if t.cfg.Authentication.Required {
		auth := t.cfg.Authentication.Authenticator
		if err := auth.VerifyMessage(msg); err != nil {
			t.callRejected(ctx, msg, pcommon.InvalidReason{Message: err.Error()})
			return err
		}
	}

	now := t.clock.Now()
	envelope := Message{
		Topic:      t.name,
		Message:    cloneMessage(*msg),
		ID:         cloneBytes(msg.ID()),
		Body:       cloneBytes(msg.Payload.MessageBody),
		Source:     source,
		Peer:       clonePeerPtr(peer),
		ReceivedAt: now,
	}

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrManagerClosed
	}
	t.pruneSeenLocked(now)
	t.pruneQueueLocked(now)
	key := string(msg.ID())
	if _, ok := t.seen[key]; ok {
		t.mu.Unlock()
		t.callRejected(ctx, msg, pcommon.AlreadyReceivedReason{})
		return ErrDuplicateMessage
	}
	if len(t.queue) >= t.cfg.Queue.MaxMessages {
		t.mu.Unlock()
		t.callRejected(ctx, msg, pcommon.OtherReason{Message: ErrQueueFull.Error()})
		return ErrQueueFull
	}
	t.seen[key] = now
	t.queue = append(t.queue, cloneMessage(*msg))
	for _, ch := range t.subscribers {
		select {
		case ch <- envelope:
		default:
			t.logger.Debug("subscriber buffer full; dropping notification")
		}
	}
	t.mu.Unlock()

	if t.cfg.Hooks.OnMessageAccepted != nil {
		t.cfg.Hooks.OnMessageAccepted(ctx, envelope)
	}
	return nil
}

func (t *topicRuntime) messageIDs(max int) []MessageIDAndSize {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock.Now()
	t.pruneQueueLocked(now)
	ids := make([]MessageIDAndSize, 0, len(t.queue))
	for i := range t.queue {
		msg := &t.queue[i]
		if err := validateMessageTTL(msg, now, t.cfg.TTL); err != nil {
			continue
		}
		msgCBOR, err := cbor.Encode(*msg)
		if err != nil {
			t.logger.Warn("failed to encode DMQ message for size calculation", "error", err)
			continue
		}
		ids = append(ids, MessageIDAndSize{
			MessageID:   cloneBytes(msg.ID()),
			SizeInBytes: uint32(len(msgCBOR)), // #nosec G115 -- queue/message size is bounded by config.
		})
		if max > 0 && len(ids) >= max {
			break
		}
	}
	return ids
}

func (t *topicRuntime) messagesByIDs(ids [][]byte) []DmqMessage {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock.Now()
	t.pruneQueueLocked(now)
	wanted := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		wanted[string(id)] = struct{}{}
	}
	messages := make([]DmqMessage, 0, len(ids))
	for _, msg := range t.queue {
		if _, ok := wanted[string(msg.ID())]; !ok {
			continue
		}
		if err := validateMessageTTL(&msg, now, t.cfg.TTL); err != nil {
			continue
		}
		messages = append(messages, cloneMessage(msg))
	}
	return messages
}

func (t *topicRuntime) subscribe() *Subscription {
	id := t.nextSubID.Add(1)
	ch := make(chan Message, t.cfg.Queue.SubscriberBuffer)
	sub := &Subscription{
		C:     ch,
		topic: t,
		id:    id,
	}
	t.mu.Lock()
	if t.closed {
		close(ch)
		sub.closed.Store(true)
	} else {
		t.subscribers[id] = ch
	}
	t.mu.Unlock()
	return sub
}

func (t *topicRuntime) close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	for id, ch := range t.subscribers {
		close(ch)
		delete(t.subscribers, id)
	}
	t.mu.Unlock()
}

func (t *topicRuntime) unsubscribe(id uint64) {
	t.mu.Lock()
	ch, ok := t.subscribers[id]
	if ok {
		delete(t.subscribers, id)
		close(ch)
	}
	t.mu.Unlock()
}

func (t *topicRuntime) pruneSeenLocked(now time.Time) {
	ttl := t.cfg.Queue.DuplicateTTL
	if ttl <= 0 {
		return
	}
	for id, seenAt := range t.seen {
		if now.Sub(seenAt) > ttl {
			delete(t.seen, id)
		}
	}
}

func (t *topicRuntime) pruneQueueLocked(now time.Time) {
	filtered := t.queue[:0]
	for i := range t.queue {
		if validateMessageTTL(&t.queue[i], now, t.cfg.TTL) == nil {
			filtered = append(filtered, t.queue[i])
		}
	}
	clear(t.queue[len(filtered):])
	t.queue = filtered
}

func (t *topicRuntime) callRejected(ctx context.Context, msg *DmqMessage, reason RejectReason) {
	if t.cfg.Hooks.OnMessageRejected != nil {
		t.cfg.Hooks.OnMessageRejected(ctx, t.name, msg, reason)
	}
}

func (t *topicRuntime) callError(ctx context.Context, err error) {
	if err != nil && t.cfg.Hooks.OnError != nil {
		t.cfg.Hooks.OnError(ctx, t.name, err)
	}
}

// Subscription is a local fanout subscription to a topic, created by
// Manager.Subscribe or TopicNode.Subscribe.
type Subscription struct {
	// C delivers accepted messages. It is closed when the subscription or its
	// topic is closed. Messages are dropped (not blocked on) when the channel
	// buffer is full.
	C <-chan Message

	topic  *topicRuntime
	id     uint64
	closed atomic.Bool
}

// Close detaches the subscription from its topic and closes C. It returns
// ErrSubscriptionClosed when called more than once.
func (s *Subscription) Close() error {
	if s == nil || s.topic == nil {
		return nil
	}
	if !s.closed.CompareAndSwap(false, true) {
		return ErrSubscriptionClosed
	}
	s.topic.unsubscribe(s.id)
	return nil
}

func normalizeAndValidateMessage(msg *DmqMessage) error {
	if err := ValidateMessageBody(msg.Payload.MessageBody); err != nil {
		return err
	}
	id := msg.ID()
	computed, err := pcommon.ComputeDmqMessageID(msg.Payload)
	if err != nil {
		return fmt.Errorf("compute message ID: %w", err)
	}
	if len(id) == 0 {
		msg.SetMessageID(computed)
		return nil
	}
	if !bytes.Equal(id, computed) {
		return fmt.Errorf("%w: expected %s got %s", ErrMessageIDMismatch, hex.EncodeToString(computed), hex.EncodeToString(id))
	}
	msg.SetMessageID(id)
	return nil
}

func rejectReasonFromError(err error) RejectReason {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrDuplicateMessage):
		return pcommon.AlreadyReceivedReason{}
	case errors.Is(err, ErrMessageExpired):
		return pcommon.ExpiredReason{}
	case errors.Is(err, ErrQueueFull), errors.Is(err, ErrManagerClosed):
		return pcommon.OtherReason{Message: err.Error()}
	default:
		return pcommon.InvalidReason{Message: err.Error()}
	}
}

func validateMessageTTL(msg *DmqMessage, now time.Time, policy TTLPolicy) error {
	if policy.Disable {
		return nil
	}
	err := pcommon.NewTTLValidator(policy.MaxTTL, nil).ValidateMessageTTLAt(msg, now)
	return wrapTTLValidationError(err)
}

func wrapTTLValidationError(err error) error {
	if err == nil {
		return nil
	}
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "has expired"):
		return fmt.Errorf("%w: %w", ErrMessageExpired, err)
	case strings.Contains(errMsg, "too far in future"):
		return fmt.Errorf("%w: %w", ErrMessageTTLTooFar, err)
	default:
		return err
	}
}

func cloneMessage(msg DmqMessage) DmqMessage {
	ret := msg
	ret.SetMessageID(msg.ID())
	ret.Payload.MessageBody = cloneBytes(msg.Payload.MessageBody)
	ret.KESSignature = cloneBytes(msg.KESSignature)
	ret.OperationalCertificate.KESVerificationKey = cloneBytes(msg.OperationalCertificate.KESVerificationKey)
	ret.OperationalCertificate.ColdSignature = cloneBytes(msg.OperationalCertificate.ColdSignature)
	ret.ColdVerificationKey = cloneBytes(msg.ColdVerificationKey)
	return ret
}

func cloneBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
