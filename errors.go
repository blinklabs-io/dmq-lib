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
	ErrManagerClosed                   = errors.New("dmq manager is closed")
	ErrTopicExists                     = errors.New("dmq topic already registered")
	ErrTopicNotFound                   = errors.New("dmq topic not found")
	ErrSignerRequired                  = errors.New("dmq signer is required")
	ErrDuplicateMessage                = errors.New("dmq message already received")
	ErrQueueFull                       = errors.New("dmq topic queue full")
	ErrSubscriptionClosed              = errors.New("dmq subscription is closed")
	ErrMessageExpired                  = errors.New("dmq message expired")
	ErrMessageTTLTooFar                = errors.New("dmq message expiration too far in future")
	ErrMessageBodyTooLarge             = errors.New("dmq message body too large")
	ErrMessageExpiryOutOfRange         = errors.New("dmq message expiration out of range")
	ErrMessageIDMismatch               = errors.New("dmq message ID mismatch")
	ErrNetworkMagicRequired            = errors.New("dmq network magic is required")
	ErrLedgerPeerSnapshotUnsupported   = errors.New("ledger peer snapshot query unsupported")
	ErrLedgerPeerSnapshotProviderUnset = errors.New("ledger peer snapshot provider is not configured")
	ErrKESKeyMismatch                  = errors.New("dmq KES key file does not match operational certificate KES vkey")
)
