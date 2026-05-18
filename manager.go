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

type Manager struct {
	logger *slog.Logger
	clock  Clock
	signer Signer
	auth   *pcommon.MessageAuthenticator

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.RWMutex
	topics map[string]*topicRuntime
	closed bool
}

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
		logger: logger,
		clock:  clock,
		signer: cfg.Signer,
		auth:   cfg.Authenticator,
		ctx:    ctx,
		cancel: cancel,
		topics: make(map[string]*topicRuntime),
	}
}

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

func (m *Manager) Publish(ctx context.Context, topic string, body []byte) (*DmqMessage, error) {
	rt, err := m.topic(topic)
	if err != nil {
		return nil, err
	}
	return rt.publish(ctx, body)
}

func (m *Manager) SubmitSigned(ctx context.Context, topic string, msg *DmqMessage) error {
	rt, err := m.topic(topic)
	if err != nil {
		return err
	}
	return rt.submitSigned(ctx, msg, MessageSourceLocal, nil)
}

func (m *Manager) SubmitRemote(ctx context.Context, topic string, msg *DmqMessage, peer *Peer) error {
	rt, err := m.topic(topic)
	if err != nil {
		return err
	}
	return rt.submitSigned(ctx, msg, MessageSourceRemote, peer)
}

func (m *Manager) Subscribe(topic string) (*Subscription, error) {
	rt, err := m.topic(topic)
	if err != nil {
		return nil, err
	}
	return rt.subscribe(), nil
}

func (m *Manager) TopicPeers(ctx context.Context, topic string) ([]Peer, error) {
	rt, err := m.topic(topic)
	if err != nil {
		return nil, err
	}
	return rt.discoverPeers(ctx)
}

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
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		for _, rt := range topics {
			rt.close()
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
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
