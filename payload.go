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
	"fmt"
	"time"
)

const (
	// MaxMessageBodyBytes is the CIP-0137 maximum DMQ message body size.
	MaxMessageBodyBytes = 2000

	// DefaultMessageTTL is the default lifetime for locally published DMQ
	// messages.
	DefaultMessageTTL = 30 * time.Minute

	// MaxMessageTTL is the maximum DMQ message lifetime accepted by the
	// default TTL validator.
	MaxMessageTTL = 30 * time.Minute

	// MaxMessageExpiresAtUnix is the largest ExpiresAt value representable by
	// the DMQ wire format.
	MaxMessageExpiresAtUnix = int64(1<<32 - 1)
)

// ValidateMessageBody checks generic DMQ wire-format body constraints.
func ValidateMessageBody(body []byte) error {
	if len(body) > MaxMessageBodyBytes {
		return fmt.Errorf(
			"%w: %d bytes (max %d)",
			ErrMessageBodyTooLarge,
			len(body),
			MaxMessageBodyBytes,
		)
	}
	return nil
}

// ExpiresAt returns the DMQ wire ExpiresAt value for now + ttl.
func ExpiresAt(now time.Time, ttl time.Duration) (uint32, error) {
	if ttl <= 0 {
		ttl = DefaultMessageTTL
	}
	nowUnix := now.Unix()
	if nowUnix > MaxMessageExpiresAtUnix {
		return 0, fmt.Errorf(
			"%w: now %d plus ttl %s (max %d)",
			ErrMessageExpiryOutOfRange,
			nowUnix,
			ttl,
			MaxMessageExpiresAtUnix,
		)
	}
	if nowUnix < 0 {
		now = time.Unix(0, 0)
	}
	expires := now.Add(ttl).Unix()
	if expires > MaxMessageExpiresAtUnix {
		return 0, fmt.Errorf(
			"%w: now %d plus ttl %s (max %d)",
			ErrMessageExpiryOutOfRange,
			nowUnix,
			ttl,
			MaxMessageExpiresAtUnix,
		)
	}
	return uint32(expires), nil // #nosec G115 -- bounded above by MaxMessageExpiresAtUnix.
}

// NewMessagePayload applies generic DMQ payload policy and builds a payload
// suitable for signing.
func NewMessagePayload(now time.Time, ttl time.Duration, body []byte) (DmqMessagePayload, error) {
	if err := ValidateMessageBody(body); err != nil {
		return DmqMessagePayload{}, err
	}
	expiresAt, err := ExpiresAt(now, ttl)
	if err != nil {
		return DmqMessagePayload{}, err
	}
	return DmqMessagePayload{
		MessageBody: cloneBytes(body),
		ExpiresAt:   expiresAt,
	}, nil
}
