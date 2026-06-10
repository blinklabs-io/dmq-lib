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
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"

	pcommon "github.com/blinklabs-io/gouroboros/protocol/common"
)

// Manager owns a set of DMQ topics and their node-to-node services. It
// provides publish, submit, and subscribe operations per topic and shuts the
// whole set down as one unit. All methods are safe for concurrent use.
type Manager struct {
	logger *slog.Logger
	clock  Clock
	signer Signer
	auth   *pcommon.MessageAuthenticator

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.RWMutex
	topics   map[string]*topicRuntime
	services map[*NodeToNodeService]struct{}
	closed   bool
}

// NewManager creates a Manager. Topics must be registered with RegisterTopic
// before use, and the Manager should be released with Shutdown.
func NewManager(cfg ManagerConfig) *Manager {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	clock := cfg.Clock
	if clock == nil {
		clock = realClock{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		logger:   logger,
		clock:    clock,
		signer:   cfg.Signer,
		auth:     cfg.Authenticator,
		ctx:      ctx,
		cancel:   cancel,
		topics:   make(map[string]*topicRuntime),
		services: make(map[*NodeToNodeService]struct{}),
	}
}

// RegisterTopic creates a topic with the given configuration. Zero-valued
// config fields are replaced with defaults, and the Manager's signer and
// authenticator fill in when the topic does not provide its own. It returns
// ErrTopicExists when the topic is already registered.
func (m *Manager) RegisterTopic(topic string, cfg TopicConfig) error {
	if topic == "" {
		return errors.New("topic is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrManagerClosed
	}
	if _, ok := m.topics[topic]; ok {
		return ErrTopicExists
	}
	cfg = defaultTopicConfig(cfg)
	if cfg.Signer == nil {
		cfg.Signer = m.signer
	}
	if cfg.Authentication.Required && cfg.Authentication.Authenticator == nil {
		cfg.Authentication.Authenticator = m.auth
	}
	rt := newTopicRuntime(topic, cfg, m.logger.With("topic", topic), m.clock)
	m.topics[topic] = rt
	return nil
}

// Publish signs a message body with the topic's Signer and submits the result
// to the topic queue. It applies the topic's default TTL and returns the
// signed message on success, or ErrSignerRequired when no signer is
// configured.
func (m *Manager) Publish(ctx context.Context, topic string, body []byte) (*DmqMessage, error) {
	rt, err := m.topic(topic)
	if err != nil {
		return nil, err
	}
	return rt.publish(ctx, body)
}

// SubmitSigned submits an already signed CIP-0137 message to the topic queue
// as a local message. The message is validated for body size, deterministic
// message ID, TTL, duplicates, and (when required) authentication before it
// is queued and fanned out to subscribers.
func (m *Manager) SubmitSigned(ctx context.Context, topic string, msg *DmqMessage) error {
	rt, err := m.topic(topic)
	if err != nil {
		return err
	}
	return rt.submitSigned(ctx, msg, MessageSourceLocal, nil)
}

// SubmitRemote submits a signed message received from a remote peer to the
// topic queue. It performs the same validation as SubmitSigned but records
// the message source and originating peer in the subscriber envelope.
func (m *Manager) SubmitRemote(ctx context.Context, topic string, msg *DmqMessage, peer *Peer) error {
	rt, err := m.topic(topic)
	if err != nil {
		return err
	}
	return rt.submitSigned(ctx, msg, MessageSourceRemote, peer)
}

// Subscribe registers a local fanout subscription on the topic. Accepted
// messages are delivered on the returned Subscription's channel; release the
// subscription with its Close method.
func (m *Manager) Subscribe(topic string) (*Subscription, error) {
	rt, err := m.topic(topic)
	if err != nil {
		return nil, err
	}
	return rt.subscribe(), nil
}

// TopicPeers returns the topic's current peer set, refreshing ledger peers
// through the configured snapshot provider when ledger discovery is enabled.
func (m *Manager) TopicPeers(ctx context.Context, topic string) ([]Peer, error) {
	rt, err := m.topic(topic)
	if err != nil {
		return nil, err
	}
	return rt.discoverPeers(ctx)
}

// Shutdown stops all node-to-node services, closes all topics and their
// subscriptions, and marks the Manager closed. It is idempotent and returns
// early with ctx.Err() if the context ends first; subsequent operations
// return ErrManagerClosed.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.cancel()
	topics := make([]*topicRuntime, 0, len(m.topics))
	for _, rt := range m.topics {
		topics = append(topics, rt)
	}
	services := make([]*NodeToNodeService, 0, len(m.services))
	for service := range m.services {
		services = append(services, service)
	}
	m.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		var errs []error
		for _, service := range services {
			if err := service.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		for _, rt := range topics {
			rt.close()
		}
		done <- errors.Join(errs...)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (m *Manager) registerService(service *NodeToNodeService) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrManagerClosed
	}
	m.services[service] = struct{}{}
	return nil
}

func (m *Manager) unregisterService(service *NodeToNodeService) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services, service)
}

func (m *Manager) topic(topic string) (*topicRuntime, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrManagerClosed
	}
	rt, ok := m.topics[topic]
	if !ok {
		return nil, ErrTopicNotFound
	}
	return rt, nil
}
