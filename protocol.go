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
	return m.messageSubmissionConfig(m.ctx, topic, nil)
}

func (m *Manager) messageSubmissionConfig(ctx context.Context, topic string, peer *Peer) (messagesubmission.Config, error) {
	rt, err := m.topic(topic)
	if err != nil {
		return messagesubmission.Config{}, err
	}
	return messagesubmission.NewConfig(
		messagesubmission.WithAuthenticator(pcommon.NewNoOpAuthenticator(rt.logger)),
		messagesubmission.WithTTLValidator(pcommon.NewNoOpTTLValidator(rt.logger)),
		messagesubmission.WithMaxQueueSize(rt.cfg.Queue.MaxMessages),
		messagesubmission.WithRequestMessageIdsFunc(func(cb messagesubmission.CallbackContext, _ bool, _ uint16, requestCount uint16) {
			if cb.Client == nil {
				return
			}
			if err := cb.Client.ReplyMessageIds(rt.messageIDs(int(requestCount))); err != nil {
				rt.callError(ctx, err)
			}
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
			if cb.Server == nil || len(ids) == 0 {
				return
			}
			messageIDs := make([][]byte, 0, len(ids))
			for _, id := range ids {
				messageIDs = append(messageIDs, cloneBytes(id.MessageID))
			}
			if err := cb.Server.RequestMessages(messageIDs); err != nil {
				rt.callError(ctx, err)
			}
		}),
		messagesubmission.WithReplyMessagesFunc(func(_ messagesubmission.CallbackContext, messages []DmqMessage) {
			for i := range messages {
				if err := rt.submitSigned(ctx, &messages[i], MessageSourceRemote, peer); err != nil {
					rt.callError(ctx, err)
				}
			}
		}),
	), nil
}
