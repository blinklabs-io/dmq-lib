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

// Aliases for the gOuroboros CIP-0137 DMQ wire types, so callers can use this
// package without importing gOuroboros protocol packages directly.
type (
	// DmqMessage is a signed CIP-0137 DMQ message.
	DmqMessage = pcommon.DmqMessage
	// DmqMessagePayload is the signed portion of a DMQ message: the message
	// body, deterministic message ID, KES period, and expiration.
	DmqMessagePayload = pcommon.DmqMessagePayload
	// OperationalCertificate is the SPO operational certificate embedded in a
	// DMQ message.
	OperationalCertificate = pcommon.OperationalCertificate
	// MessageIDAndSize identifies a queued message and its wire size, as
	// exchanged by the message-submission protocol.
	MessageIDAndSize = pcommon.MessageIDAndSize
	// RejectReason describes why a submitted message was rejected.
	RejectReason = pcommon.RejectReason
	// InvalidReason is the RejectReason for messages that failed validation.
	InvalidReason = pcommon.InvalidReason
	// AlreadyReceivedReason is the RejectReason for duplicate messages.
	AlreadyReceivedReason = pcommon.AlreadyReceivedReason
	// ExpiredReason is the RejectReason for messages past their TTL.
	ExpiredReason = pcommon.ExpiredReason
	// OtherReason is the RejectReason for rejections that fit no other
	// category, such as a full queue.
	OtherReason = pcommon.OtherReason
)

// Clock supplies the current time. Provide a fake implementation in tests to
// control TTL and duplicate-suppression behavior.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

// ManagerConfig configures a Manager. The zero value is usable: logs are
// discarded, the system clock is used, and no default signer or authenticator
// is set.
type ManagerConfig struct {
	// Logger receives diagnostic output. Nil discards all log output.
	Logger *slog.Logger

	// Clock overrides the time source. Nil uses the system clock.
	Clock Clock

	// Signer is the default signer used by topics that do not provide one.
	Signer Signer

	// Authenticator is used only when TopicConfig.Authentication.Required is
	// true and the topic does not provide its own authenticator.
	Authenticator *pcommon.MessageAuthenticator
}

// TopicConfig configures a single DMQ topic registered with a Manager. Zero
// values for queue, TTL, reconnect, and discovery settings are replaced with
// sensible defaults at registration time.
type TopicConfig struct {
	// NetworkMagic identifies the Cardano network for node-to-node
	// handshakes. It is required before calling Manager.StartNodeToNode.
	NetworkMagic uint32

	// Discovery configures topology, static, and ledger peer sources.
	Discovery DiscoveryConfig

	// Queue configures the topic's in-memory message queue.
	Queue QueueConfig

	// TTL configures message expiration policy.
	TTL TTLPolicy

	// Reconnect configures outbound peer reconnect backoff.
	Reconnect ReconnectConfig

	// Authentication configures gOuroboros message authentication.
	Authentication AuthenticationConfig

	// Hooks are optional lifecycle callbacks for this topic.
	Hooks Hooks

	// Signer signs locally published message bodies. Nil falls back to the
	// Manager's default signer.
	Signer Signer
}

// QueueConfig bounds a topic's in-memory message queue. Zero values are
// replaced with defaults: 100 messages, a 16-message subscriber buffer, and a
// 10-minute duplicate-suppression window.
type QueueConfig struct {
	// MaxMessages is the maximum number of unexpired messages held in the
	// topic queue. Submissions beyond this limit fail with ErrQueueFull.
	MaxMessages int

	// SubscriberBuffer is the channel buffer size for each Subscription.
	// Notifications are dropped (not blocked on) when a buffer is full.
	SubscriberBuffer int

	// DuplicateTTL is how long accepted message IDs are remembered for
	// duplicate suppression.
	DuplicateTTL time.Duration
}

// TTLPolicy controls message expiration. Zero values are replaced with
// DefaultMessageTTL and MaxMessageTTL.
type TTLPolicy struct {
	// DefaultTTL is the lifetime applied to locally published messages.
	DefaultTTL time.Duration

	// MaxTTL is the maximum time in the future a message's ExpiresAt may be.
	MaxTTL time.Duration

	// Disable skips TTL validation entirely when true.
	Disable bool
}

// AuthenticationConfig controls cryptographic verification of submitted
// messages.
type AuthenticationConfig struct {
	// Required enables gOuroboros MessageAuthenticator verification in addition
	// to deterministic message-id and TTL validation. It is off by default
	// because production SPO validation needs the caller to configure active
	// pool registration state and a KES verifier.
	Required bool

	// Authenticator verifies messages when Required is true. Nil falls back
	// to the Manager's authenticator, then to a default KES-only verifier.
	Authenticator *pcommon.MessageAuthenticator

	// AllowUnauthenticated opts a topic in to running node-to-node networking
	// without message verification. Manager.StartNodeToNode fails with
	// ErrAuthenticationRequired unless either Required or AllowUnauthenticated
	// is set, so unauthenticated operation is always a deliberate choice. It is
	// ignored when Required is true. When it takes effect, the unauthenticated
	// node-to-node warning is still logged.
	AllowUnauthenticated bool
}

// ReconnectConfig controls exponential backoff for outbound peer reconnects.
// Zero values are replaced with a 1-second initial and 2-minute maximum
// backoff.
type ReconnectConfig struct {
	// InitialBackoff is the delay before the first reconnect attempt.
	InitialBackoff time.Duration

	// MaxBackoff caps the exponentially growing reconnect delay.
	MaxBackoff time.Duration
}

// NodeToNodeConfig configures the DMQ node-to-node networking service started
// by Manager.StartNodeToNode or TopicNode.
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

	// Hooks are optional node-to-node lifecycle callbacks.
	Hooks NodeToNodeHooks
}

// NodeToNodeHooks are optional callbacks invoked by a NodeToNodeService. Each
// receives the topic name. Nil fields are skipped. Hooks are called
// synchronously, so implementations should return quickly.
type NodeToNodeHooks struct {
	// OnPeerConnected is called after a peer connection completes its
	// handshake.
	OnPeerConnected func(context.Context, string, Peer)

	// OnPeerDisconnected is called when a peer connection ends, with the
	// error that terminated it (nil for a clean close).
	OnPeerDisconnected func(context.Context, string, Peer, error)

	// OnError is called for connection and protocol errors.
	OnError func(context.Context, string, error)
}

// Hooks are optional per-topic callbacks. String arguments carry the topic
// name. Nil fields are skipped. Hooks are called synchronously, so
// implementations should return quickly.
type Hooks struct {
	// OnMessageAccepted is called after a message is admitted to the queue.
	OnMessageAccepted func(context.Context, Message)

	// OnMessageRejected is called when a submitted message is rejected.
	OnMessageRejected func(context.Context, string, *DmqMessage, RejectReason)

	// OnPeerDiscovered is called with the full peer set after ledger peer
	// discovery refreshes it.
	OnPeerDiscovered func(context.Context, string, []Peer)

	// OnError is called for asynchronous errors on the topic.
	OnError func(context.Context, string, error)
}

// Message is the envelope delivered to subscribers for each accepted DMQ
// message. Its byte slices are private copies safe for the subscriber to
// retain.
type Message struct {
	// Topic is the topic the message was accepted on.
	Topic string

	// Message is the full signed DMQ wire message.
	Message DmqMessage

	// ID is the deterministic CIP-0137 message ID.
	ID []byte

	// Body is the message body.
	Body []byte

	// Source records whether the message was submitted locally or received
	// from a remote peer.
	Source MessageSource

	// Peer is the remote peer the message arrived from, when known.
	Peer *Peer

	// ReceivedAt is when the message was accepted into the queue.
	ReceivedAt time.Time
}

// MessageSource identifies where an accepted message entered the queue.
type MessageSource string

const (
	// MessageSourceLocal marks messages published or submitted by this
	// process.
	MessageSourceLocal MessageSource = "local"
	// MessageSourceRemote marks messages received from remote peers.
	MessageSourceRemote MessageSource = "remote"
)

// Signer produces a signed DMQ message from a payload built for the given
// topic. Implementations in this package include FileSigner, ReloadingSigner,
// and KESSigningProviderSigner.
type Signer interface {
	Sign(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error)
}

// SignerFunc adapts a function to the Signer interface.
type SignerFunc func(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error)

// Sign implements Signer by calling f.
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

// ParseTopologyFile loads a Cardano node topology file from disk for use in
// DiscoveryConfig.Topology.
func ParseTopologyFile(path string) (*dtopology.TopologyConfig, error) {
	return dtopology.NewTopologyConfigFromFile(path)
}
