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
	"testing"
	"time"
)

func TestTopicNodePublishSubscribe(t *testing.T) {
	ctx := context.Background()
	node, err := NewTopicNode(ctx, TopicNodeConfig{
		Topic: "topic",
		ManagerConfig: ManagerConfig{
			Clock:  testClock{now: time.Now()},
			Signer: testSigner(t),
		},
	})
	if err != nil {
		t.Fatalf("NewTopicNode: %v", err)
	}
	defer func() { _ = node.Close() }()

	sub, err := node.Subscribe()
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() { _ = sub.Close() }()
	published, err := node.Publish(ctx, []byte("hello"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	select {
	case got := <-sub.C:
		if got.Topic != "topic" {
			t.Fatalf("topic = %q, want topic", got.Topic)
		}
		if string(got.Body) != "hello" {
			t.Fatalf("body = %q, want hello", got.Body)
		}
		if string(got.ID) != string(published.ID()) {
			t.Fatalf("id = %x, want %x", got.ID, published.ID())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for message")
	}
}

func TestTopicNodeSubmitSignedRejectsDuplicate(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	signer := testSigner(t)
	node, err := NewTopicNode(ctx, TopicNodeConfig{
		Topic: "topic",
		ManagerConfig: ManagerConfig{
			Clock:  testClock{now: now},
			Signer: signer,
		},
	})
	if err != nil {
		t.Fatalf("NewTopicNode: %v", err)
	}
	defer func() { _ = node.Close() }()

	payload, err := NewMessagePayload(now, time.Minute, []byte("hello"))
	if err != nil {
		t.Fatalf("NewMessagePayload: %v", err)
	}
	msg, err := signer.Sign(ctx, "topic", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := node.SubmitSigned(ctx, msg); err != nil {
		t.Fatalf("first SubmitSigned: %v", err)
	}
	if err := node.SubmitSigned(ctx, msg); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("second SubmitSigned error = %v, want %v", err, ErrDuplicateMessage)
	}
}

func TestTopicNodeNodeToNodeStaticPeerRoundTrip(t *testing.T) {
	ctx := context.Background()
	const topic = "topic"
	signer := testSigner(t)
	nodeB, err := NewTopicNode(ctx, TopicNodeConfig{
		Topic:         topic,
		ManagerConfig: ManagerConfig{Signer: signer},
		TopicConfig: TopicConfig{
			NetworkMagic:   42,
			Authentication: AuthenticationConfig{AllowUnauthenticated: true},
		},
		NodeToNode: NodeToNodeConfig{
			ListenAddress:   "127.0.0.1:0",
			RequestInterval: 10 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("NewTopicNode B: %v", err)
	}
	defer func() { _ = nodeB.Close() }()
	addr := nodeB.ListenAddr()
	if addr == nil {
		t.Fatal("B listen address is nil")
	}
	subB, err := nodeB.Subscribe()
	if err != nil {
		t.Fatalf("Subscribe B: %v", err)
	}
	defer func() { _ = subB.Close() }()

	nodeA, err := NewTopicNode(ctx, TopicNodeConfig{
		Topic:         topic,
		ManagerConfig: ManagerConfig{Signer: signer},
		TopicConfig: TopicConfig{
			NetworkMagic:   42,
			Authentication: AuthenticationConfig{AllowUnauthenticated: true},
		},
		StaticPeers: []Peer{{Address: addr.String()}},
		NodeToNode: NodeToNodeConfig{
			RequestInterval: 10 * time.Millisecond,
			Reconnect: ReconnectConfig{
				InitialBackoff: 10 * time.Millisecond,
				MaxBackoff:     20 * time.Millisecond,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewTopicNode A: %v", err)
	}
	defer func() { _ = nodeA.Close() }()

	serviceA := nodeA.NodeToNodeService()
	if serviceA == nil {
		t.Fatal("A node-to-node service is nil")
	}
	waitForPeerCount(t, serviceA, 1)

	published, err := nodeA.Publish(ctx, []byte("hello ntn"))
	if err != nil {
		t.Fatalf("Publish A: %v", err)
	}
	select {
	case got := <-subB.C:
		if string(got.Body) != "hello ntn" {
			t.Fatalf("body = %q, want hello ntn", got.Body)
		}
		if string(got.ID) != string(published.ID()) {
			t.Fatalf("id = %x, want %x", got.ID, published.ID())
		}
		if got.Source != MessageSourceRemote {
			t.Fatalf("source = %q, want %q", got.Source, MessageSourceRemote)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for node-to-node message")
	}
}

func TestTopicNodeRequiresNetworkMagicWhenNetworkConfigured(t *testing.T) {
	_, err := NewTopicNode(context.Background(), TopicNodeConfig{
		Topic:       "topic",
		StaticPeers: []Peer{{Address: "127.0.0.1:3001"}},
	})
	if !errors.Is(err, ErrNetworkMagicRequired) {
		t.Fatalf("NewTopicNode error = %v, want %v", err, ErrNetworkMagicRequired)
	}
}
