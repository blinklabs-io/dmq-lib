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
	"errors"
	"testing"
	"time"
)

func TestExpiresAtAddsBeforeTruncatingToSeconds(t *testing.T) {
	now := time.Unix(100, int64(900*time.Millisecond))
	ttl := 200 * time.Millisecond

	got, err := ExpiresAt(now, ttl)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	want := uint32(now.Add(ttl).Unix())
	if got != want {
		t.Fatalf("ExpiresAt = %d, want %d", got, want)
	}
}

func TestExpiresAtRejectsOutOfRangeAfterFractionalCarry(t *testing.T) {
	now := time.Unix(MaxMessageExpiresAtUnix, int64(900*time.Millisecond))

	_, err := ExpiresAt(now, 200*time.Millisecond)
	if !errors.Is(err, ErrMessageExpiryOutOfRange) {
		t.Fatalf("ExpiresAt error = %v, want %v", err, ErrMessageExpiryOutOfRange)
	}
}
