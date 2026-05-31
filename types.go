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
	"log/slog"
	"time"

	dtopology "github.com/blinklabs-io/dingo/topology"
	pcommon "github.com/blinklabs-io/gouroboros/protocol/common"
)

type (
	DmqMessage             = pcommon.DmqMessage
	DmqMessagePayload      = pcommon.DmqMessagePayload
	OperationalCertificate = pcommon.OperationalCertificate
	MessageIDAndSize       = pcommon.MessageIDAndSize
	RejectReason           = pcommon.RejectReason
	InvalidReason          = pcommon.InvalidReason
	AlreadyReceivedReason  = pcommon.AlreadyReceivedReason
	ExpiredReason          = pcommon.ExpiredReason
	OtherReason            = pcommon.OtherReason
)

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

type ManagerConfig struct {
	Logger *slog.Logger
	Clock  Clock

	// Signer is the default signer used by topics that do not provide one.
	Signer Signer

	// Authenticator is used only when TopicConfig.Authentication.Required is
	// true and the topic does not provide its own authenticator.
	Authenticator *pcommon.MessageAuthenticator
}

type TopicConfig struct {
	NetworkMagic uint32

	Discovery      DiscoveryConfig
	Queue          QueueConfig
	TTL            TTLPolicy
	Reconnect      ReconnectConfig
	Authentication AuthenticationConfig
	Hooks          Hooks

	Signer Signer
}

type QueueConfig struct {
	MaxMessages      int
	SubscriberBuffer int
	DuplicateTTL     time.Duration
}

type TTLPolicy struct {
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	Disable    bool
}

type AuthenticationConfig struct {
	// Required enables gOuroboros MessageAuthenticator verification in addition
	// to deterministic message-id and TTL validation. It is off by default
	// because production SPO validation needs the caller to configure active
	// pool registration state and a KES verifier.
	Required bool

	Authenticator *pcommon.MessageAuthenticator
}

type ReconnectConfig struct {
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

type NodeToNodeConfig struct {
	// ListenAddress enables a DMQ node-to-node TCP listener. Empty disables
	// inbound connections.
	ListenAddress string

	// Peers are additional node-to-node peers to dial. Peers configured on the
	// topic's Discovery config are also dialed when the service starts.
	Peers []Peer

	// RequestInterval controls how often each connected peer is polled for
	// message IDs. Zero uses the default.
	RequestInterval time.Duration

	// RequestCount controls how many message IDs are requested per poll. Zero
	// uses the default.
	RequestCount uint16

	// DialTimeout controls outbound peer dial timeout. Zero uses the default.
	DialTimeout time.Duration

	// Reconnect controls outbound peer reconnect backoff. Zero fields use
	// defaults.
	Reconnect ReconnectConfig

	Hooks NodeToNodeHooks
}

type NodeToNodeHooks struct {
	OnPeerConnected    func(context.Context, string, Peer)
	OnPeerDisconnected func(context.Context, string, Peer, error)
	OnError            func(context.Context, string, error)
}

type Hooks struct {
	OnMessageAccepted func(context.Context, Message)
	OnMessageRejected func(context.Context, string, *DmqMessage, RejectReason)
	OnPeerDiscovered  func(context.Context, string, []Peer)
	OnError           func(context.Context, string, error)
}

type Message struct {
	Topic      string
	Message    DmqMessage
	ID         []byte
	Body       []byte
	Source     MessageSource
	Peer       *Peer
	ReceivedAt time.Time
}

type MessageSource string

const (
	MessageSourceLocal  MessageSource = "local"
	MessageSourceRemote MessageSource = "remote"
)

type Signer interface {
	Sign(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error)
}

type SignerFunc func(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error)

func (f SignerFunc) Sign(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error) {
	return f(ctx, topic, payload)
}

func defaultTopicConfig(cfg TopicConfig) TopicConfig {
	if cfg.Queue.MaxMessages <= 0 {
		cfg.Queue.MaxMessages = 100
	}
	if cfg.Queue.SubscriberBuffer <= 0 {
		cfg.Queue.SubscriberBuffer = 16
	}
	if cfg.Queue.DuplicateTTL <= 0 {
		cfg.Queue.DuplicateTTL = 10 * time.Minute
	}
	if cfg.TTL.DefaultTTL <= 0 {
		cfg.TTL.DefaultTTL = DefaultMessageTTL
	}
	if cfg.TTL.MaxTTL <= 0 {
		cfg.TTL.MaxTTL = MaxMessageTTL
	}
	if cfg.TTL.MaxTTL < cfg.TTL.DefaultTTL {
		cfg.TTL.MaxTTL = cfg.TTL.DefaultTTL
	}
	cfg.Reconnect = defaultReconnectConfig(cfg.Reconnect)
	cfg.Discovery = defaultDiscoveryConfig(cfg.Discovery)
	return cfg
}

func defaultReconnectConfig(cfg ReconnectConfig) ReconnectConfig {
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 2 * time.Minute
	}
	if cfg.MaxBackoff < cfg.InitialBackoff {
		cfg.MaxBackoff = cfg.InitialBackoff
	}
	return cfg
}

func ParseTopologyFile(path string) (*dtopology.TopologyConfig, error) {
	return dtopology.NewTopologyConfigFromFile(path)
}
