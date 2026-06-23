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

import "errors"

var (
	// ErrManagerClosed is returned by Manager operations after Shutdown has
	// been called.
	ErrManagerClosed = errors.New("dmq manager is closed")

	// ErrTopicExists is returned by Manager.RegisterTopic when the topic name
	// is already registered.
	ErrTopicExists = errors.New("dmq topic already registered")

	// ErrTopicNotFound is returned by Manager operations that reference a
	// topic that was never registered.
	ErrTopicNotFound = errors.New("dmq topic not found")

	// ErrSignerRequired is returned when an operation needs a Signer (or KES
	// signing provider) and none is configured or active.
	ErrSignerRequired = errors.New("dmq signer is required")

	// ErrDuplicateMessage is returned when a submitted message's ID was
	// already accepted within the topic's duplicate-suppression window.
	ErrDuplicateMessage = errors.New("dmq message already received")

	// ErrQueueFull is returned when a topic queue has reached
	// QueueConfig.MaxMessages.
	ErrQueueFull = errors.New("dmq topic queue full")

	// ErrSubscriptionClosed is returned by Subscription.Close when the
	// subscription was already closed.
	ErrSubscriptionClosed = errors.New("dmq subscription is closed")

	// ErrMessageExpired is returned when a message's ExpiresAt is in the past
	// per the topic's TTL policy.
	ErrMessageExpired = errors.New("dmq message expired")

	// ErrMessageTTLTooFar is returned when a message's ExpiresAt exceeds the
	// topic's maximum allowed TTL.
	ErrMessageTTLTooFar = errors.New("dmq message expiration too far in future")

	// ErrMessageBodyTooLarge is returned when a message body exceeds
	// MaxMessageBodyBytes.
	ErrMessageBodyTooLarge = errors.New("dmq message body too large")

	// ErrMessageExpiryOutOfRange is returned when a computed ExpiresAt value
	// cannot be represented in the DMQ wire format.
	ErrMessageExpiryOutOfRange = errors.New("dmq message expiration out of range")

	// ErrMessageIDMismatch is returned when a submitted message carries an ID
	// that does not match the deterministic ID computed from its payload.
	ErrMessageIDMismatch = errors.New("dmq message ID mismatch")

	// ErrNetworkMagicRequired is returned by Manager.StartNodeToNode when the
	// topic was registered without a NetworkMagic.
	ErrNetworkMagicRequired = errors.New("dmq network magic is required")

	// ErrAuthenticationRequired is returned by Manager.StartNodeToNode when the
	// topic has neither Authentication.Required nor
	// Authentication.AllowUnauthenticated set, so node-to-node networking would
	// otherwise accept and relay remote messages without verification.
	ErrAuthenticationRequired = errors.New("dmq node-to-node requires message authentication; set Authentication.Required or Authentication.AllowUnauthenticated")

	// ErrLedgerPeerSnapshotUnsupported is returned when the configured ledger
	// peer provider cannot produce the requested snapshot kind.
	ErrLedgerPeerSnapshotUnsupported = errors.New("ledger peer snapshot query unsupported")

	// ErrLedgerPeerSnapshotProviderUnset is returned when ledger peer
	// discovery is enabled but no snapshot provider is configured.
	ErrLedgerPeerSnapshotProviderUnset = errors.New("ledger peer snapshot provider is not configured")

	// ErrKESKeyMismatch is returned when a KES signing key does not match the
	// KES verification key embedded in the operational certificate.
	ErrKESKeyMismatch = errors.New("dmq KES key file does not match operational certificate KES vkey")
)
