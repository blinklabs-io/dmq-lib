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
	"sync"
	"time"

	pcommon "github.com/blinklabs-io/gouroboros/protocol/common"
	"github.com/blinklabs-io/gouroboros/protocol/localmessagenotification"
	"github.com/blinklabs-io/gouroboros/protocol/localmessagesubmission"
	"github.com/blinklabs-io/gouroboros/protocol/messagesubmission"
)

// LocalMessageSubmissionConfig returns a gOuroboros CIP-0137
// local-message-submission config wired to the topic.
func (m *Manager) LocalMessageSubmissionConfig(topic string) (localmessagesubmission.Config, error) {
	rt, err := m.topic(topic)
	if err != nil {
		return localmessagesubmission.Config{}, err
	}
	return localmessagesubmission.NewConfig(
		localmessagesubmission.WithAuthenticator(pcommon.NewNoOpAuthenticator(rt.logger)),
		localmessagesubmission.WithTTLValidator(pcommon.NewNoOpTTLValidator(rt.logger)),
		localmessagesubmission.WithSubmitMessageFunc(func(_ localmessagesubmission.CallbackContext, msg *DmqMessage) RejectReason {
			err := rt.submitSigned(context.Background(), msg, MessageSourceLocal, nil)
			return rejectReasonFromError(err)
		}),
	), nil
}

// LocalMessageNotificationConfig returns a gOuroboros CIP-0137
// local-message-notification config that accepts messages into the topic.
func (m *Manager) LocalMessageNotificationConfig(topic string) (localmessagenotification.Config, error) {
	rt, err := m.topic(topic)
	if err != nil {
		return localmessagenotification.Config{}, err
	}
	return localmessagenotification.NewConfig(
		localmessagenotification.WithAuthenticator(pcommon.NewNoOpAuthenticator(rt.logger)),
		localmessagenotification.WithTTLValidator(pcommon.NewNoOpTTLValidator(rt.logger)),
		localmessagenotification.WithMaxQueueSize(rt.cfg.Queue.MaxMessages),
		localmessagenotification.WithReplyMessagesFunc(func(_ localmessagenotification.CallbackContext, messages []DmqMessage, _ bool) {
			for i := range messages {
				if err := rt.submitSigned(context.Background(), &messages[i], MessageSourceRemote, nil); err != nil {
					rt.callError(context.Background(), err)
				}
			}
		}),
	), nil
}

// MessageSubmissionConfig returns a gOuroboros CIP-0137 message-submission
// config wired to the topic queue.
func (m *Manager) MessageSubmissionConfig(topic string) (messagesubmission.Config, error) {
	cfg, _, err := m.messageSubmissionConfig(m.ctx, topic, nil, submissionFlowOptions{})
	return cfg, err
}

type submissionFlowOptions struct {
	// requestCount is the number of message IDs requested per round. Zero uses
	// defaultNodeToNodeRequestCount.
	requestCount uint16
	// holdInterval is how often a held blocking request rechecks the queue.
	// Zero uses defaultNodeToNodeRequestInterval.
	holdInterval time.Duration
}

// submissionFlows holds one submissionFlow per connection. A returned
// messagesubmission.Config can serve several connections, so the state cannot
// live in the config's closures alone.
type submissionFlows struct {
	rt   *topicRuntime
	peer *Peer
	ctx  context.Context
	opts submissionFlowOptions

	mu    sync.Mutex
	flows map[string]*submissionFlow
}

// forConnection returns the flow for a connection, creating it on first use.
// The entry is dropped when stop closes or the manager context ends.
func (fs *submissionFlows) forConnection(id string, stop <-chan struct{}) *submissionFlow {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if f, ok := fs.flows[id]; ok {
		return f
	}
	f := &submissionFlow{
		rt:        fs.rt,
		peer:      fs.peer,
		ctx:       fs.ctx,
		opts:      fs.opts,
		stop:      stop,
		announced: make(map[string]struct{}),
	}
	fs.flows[id] = f
	go func() {
		select {
		case <-stop:
		case <-fs.ctx.Done():
		}
		fs.mu.Lock()
		delete(fs.flows, id)
		fs.mu.Unlock()
	}()
	return f
}

// submissionFlow carries the per-connection state that the message-submission
// protocol requires: which IDs were announced to the peer, and how many IDs
// the peer announced that are not yet acknowledged.
type submissionFlow struct {
	rt   *topicRuntime
	peer *Peer
	ctx  context.Context
	opts submissionFlowOptions
	stop <-chan struct{}

	mu          sync.Mutex
	announced   map[string]struct{}
	outstanding uint16
}

// start issues the first blocking request. Later requests follow each reply.
func (f *submissionFlow) start(server *messagesubmission.Server) error {
	return f.requestIDs(server)
}

// requestIDs acknowledges every ID announced so far and blocks for new ones.
// The flow always requests every announced message, so nothing remains
// unacknowledged and the protocol only permits a blocking request.
func (f *submissionFlow) requestIDs(server *messagesubmission.Server) error {
	f.mu.Lock()
	ack := f.outstanding
	f.outstanding = 0
	f.mu.Unlock()
	count := f.opts.requestCount
	if count == 0 {
		count = defaultNodeToNodeRequestCount
	}
	return server.RequestMessageIdsBlocking(ack, count)
}

// newIDs returns queued IDs not yet announced on this connection, up to max.
func (f *submissionFlow) newIDs(max int) []MessageIDAndSize {
	queued := f.rt.messageIDs(0)
	f.mu.Lock()
	defer f.mu.Unlock()
	live := make(map[string]struct{}, len(queued))
	ids := make([]MessageIDAndSize, 0, len(queued))
	for _, id := range queued {
		key := string(id.MessageID)
		live[key] = struct{}{}
		if _, ok := f.announced[key]; ok || len(ids) >= max {
			continue
		}
		ids = append(ids, id)
	}
	for key := range f.announced {
		if _, ok := live[key]; !ok {
			delete(f.announced, key)
		}
	}
	for _, id := range ids {
		f.announced[string(id.MessageID)] = struct{}{}
	}
	return ids
}

// replyIDs answers a peer's ID request. A blocking request must not receive an
// empty reply, so the reply is held off the protocol goroutine until a new
// message is queued.
func (f *submissionFlow) replyIDs(client *messagesubmission.Client, blocking bool, count uint16) {
	go func() {
		interval := f.opts.holdInterval
		if interval <= 0 {
			interval = defaultNodeToNodeRequestInterval
		}
		for {
			ids := f.newIDs(int(count))
			if len(ids) > 0 || !blocking {
				if err := client.ReplyMessageIds(ids); err != nil {
					f.rt.callError(f.ctx, err)
				}
				return
			}
			select {
			case <-f.ctx.Done():
				return
			case <-f.stop:
				return
			case <-time.After(interval):
			}
		}
	}()
}

func (m *Manager) messageSubmissionConfig(ctx context.Context, topic string, peer *Peer, opts submissionFlowOptions) (messagesubmission.Config, *submissionFlows, error) {
	rt, err := m.topic(topic)
	if err != nil {
		return messagesubmission.Config{}, nil, err
	}
	flows := &submissionFlows{
		rt:    rt,
		peer:  peer,
		ctx:   ctx,
		opts:  opts,
		flows: make(map[string]*submissionFlow),
	}
	cfg := messagesubmission.NewConfig(
		messagesubmission.WithAuthenticator(pcommon.NewNoOpAuthenticator(rt.logger)),
		messagesubmission.WithTTLValidator(pcommon.NewNoOpTTLValidator(rt.logger)),
		messagesubmission.WithMaxQueueSize(rt.cfg.Queue.MaxMessages),
		messagesubmission.WithRequestMessageIdsFunc(func(cb messagesubmission.CallbackContext, blocking bool, _ uint16, requestCount uint16) {
			if cb.Client == nil {
				return
			}
			flows.forConnection(cb.ConnectionId.String(), cb.Client.StopChan()).
				replyIDs(cb.Client, blocking, requestCount)
		}),
		messagesubmission.WithRequestMessagesFunc(func(cb messagesubmission.CallbackContext, ids [][]byte) {
			if cb.Client == nil {
				return
			}
			if err := cb.Client.ReplyMessages(rt.messagesByIDs(ids)); err != nil {
				rt.callError(ctx, err)
			}
		}),
		messagesubmission.WithReplyMessageIdsFunc(func(cb messagesubmission.CallbackContext, ids []MessageIDAndSize) {
			if cb.Server == nil {
				return
			}
			flow := flows.forConnection(cb.ConnectionId.String(), cb.Server.StopChan())
			flow.mu.Lock()
			flow.outstanding = uint16(len(ids)) // #nosec G115 -- bounded by the request count.
			flow.mu.Unlock()
			wanted := make([][]byte, 0, len(ids))
			for _, id := range ids {
				if !rt.hasSeen(id.MessageID) {
					wanted = append(wanted, cloneBytes(id.MessageID))
				}
			}
			var err error
			if len(wanted) > 0 {
				err = cb.Server.RequestMessages(wanted)
			} else {
				err = flow.requestIDs(cb.Server)
			}
			if err != nil {
				rt.callError(ctx, err)
			}
		}),
		messagesubmission.WithReplyMessagesFunc(func(cb messagesubmission.CallbackContext, messages []DmqMessage) {
			for i := range messages {
				if err := rt.submitSigned(ctx, &messages[i], MessageSourceRemote, peer); err != nil {
					rt.callError(ctx, err)
				}
			}
			if cb.Server == nil {
				return
			}
			flow := flows.forConnection(cb.ConnectionId.String(), cb.Server.StopChan())
			if err := flow.requestIDs(cb.Server); err != nil {
				rt.callError(ctx, err)
			}
		}),
	)
	return cfg, flows, nil
}
