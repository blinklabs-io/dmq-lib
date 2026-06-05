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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/dingo/peergov"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/kes"
	"github.com/blinklabs-io/gouroboros/protocol/localmessagesubmission"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"
)

type testClock struct {
	now time.Time
}

func (c testClock) Now() time.Time {
	return c.now
}

func testSigner(t *testing.T) Signer {
	t.Helper()
	return SignerFunc(func(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error) {
		_ = ctx
		_ = topic
		msg := &DmqMessage{
			Payload:                payload,
			KESSignature:           []byte("sig"),
			OperationalCertificate: OperationalCertificate{KESVerificationKey: []byte("kes")},
			ColdVerificationKey:    []byte("cold"),
		}
		if err := msg.SetComputedMessageID(); err != nil {
			t.Fatal(err)
		}
		return msg, nil
	})
}

func TestManagerPublishSubscribeFanout(t *testing.T) {
	ctx := context.Background()
	m := NewManager(ManagerConfig{
		Clock:  testClock{now: time.Unix(1_700_000_000, 0)},
		Signer: testSigner(t),
	})
	if err := m.RegisterTopic("governance", TopicConfig{}); err != nil {
		t.Fatalf("RegisterTopic: %v", err)
	}
	sub, err := m.Subscribe("governance")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() { _ = sub.Close() }()

	msg, err := m.Publish(ctx, "governance", []byte("hello"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(msg.ID()) == 0 {
		t.Fatal("expected message ID")
	}

	select {
	case got := <-sub.C:
		if got.Topic != "governance" {
			t.Fatalf("topic = %q", got.Topic)
		}
		if string(got.Body) != "hello" {
			t.Fatalf("body = %q", got.Body)
		}
		if string(got.ID) != string(msg.ID()) {
			t.Fatalf("id mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for message")
	}
}

func TestNodeToNodeServiceRoundTrip(t *testing.T) {
	ctx := context.Background()
	const topic = "governance"
	signer := testSigner(t)
	mA := NewManager(ManagerConfig{Signer: signer})
	mB := NewManager(ManagerConfig{Signer: signer})
	for name, manager := range map[string]*Manager{"A": mA, "B": mB} {
		if err := manager.RegisterTopic(topic, TopicConfig{NetworkMagic: 42}); err != nil {
			t.Fatalf("RegisterTopic %s: %v", name, err)
		}
	}
	subB, err := mB.Subscribe(topic)
	if err != nil {
		t.Fatalf("Subscribe B: %v", err)
	}
	defer func() { _ = subB.Close() }()
	peerConnected := make(chan Peer, 1)

	svcB, err := mB.StartNodeToNode(ctx, topic, NodeToNodeConfig{
		ListenAddress:   "127.0.0.1:0",
		RequestInterval: 10 * time.Millisecond,
		Hooks: NodeToNodeHooks{
			OnPeerConnected: func(_ context.Context, _ string, peer Peer) {
				select {
				case peerConnected <- peer:
				default:
				}
			},
		},
	})
	if err != nil {
		t.Fatalf("StartNodeToNode B: %v", err)
	}
	defer func() { _ = svcB.Close() }()
	addr := svcB.ListenAddr()
	if addr == nil {
		t.Fatal("B listen address is nil")
	}

	svcA, err := mA.StartNodeToNode(ctx, topic, NodeToNodeConfig{
		Peers: []Peer{{
			Address: addr.String(),
			Source:  PeerSourceStatic,
		}},
		RequestInterval: 10 * time.Millisecond,
		Reconnect: ReconnectConfig{
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     20 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("StartNodeToNode A: %v", err)
	}
	defer func() { _ = svcA.Close() }()

	waitForPeerCount(t, svcA, 1)
	var serviceAAddr string
	select {
	case peer := <-peerConnected:
		serviceAAddr = peer.Address
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for B peer connection")
	}
	published, err := mA.Publish(ctx, topic, []byte("hello ntn"))
	if err != nil {
		t.Fatalf("Publish A: %v", err)
	}
	publishedID := published.ID()

	select {
	case got := <-subB.C:
		if string(got.Body) != "hello ntn" {
			t.Fatalf("body = %q", got.Body)
		}
		if string(got.ID) != string(publishedID) {
			t.Fatalf("id = %x, want %x", got.ID, publishedID)
		}
		if got.Source != MessageSourceRemote {
			t.Fatalf("source = %q, want %q", got.Source, MessageSourceRemote)
		}
		if got.Peer == nil || got.Peer.Address == "" {
			t.Fatalf("remote peer metadata missing: %+v", got.Peer)
		}
		if got.Peer.Address != serviceAAddr {
			t.Fatalf("peer address = %q, want %q", got.Peer.Address, serviceAAddr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for node-to-node message")
	}
}

func waitForPeerCount(t *testing.T, svc *NodeToNodeService, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	if testDeadline, ok := t.Deadline(); ok {
		deadline = testDeadline
	}
	for time.Now().Before(deadline) {
		if svc.PeerCount() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("peer count = %d, want at least %d", svc.PeerCount(), want)
}

func TestPublishWithPreEpochClock(t *testing.T) {
	m := NewManager(ManagerConfig{
		Clock:  testClock{now: time.Unix(-100, 0)},
		Signer: testSigner(t),
	})
	if err := m.RegisterTopic("topic", TopicConfig{}); err != nil {
		t.Fatal(err)
	}
	msg, err := m.Publish(context.Background(), "topic", []byte("body"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if msg.Payload.ExpiresAt != uint32((30 * time.Minute).Seconds()) {
		t.Fatalf("ExpiresAt = %d", msg.Payload.ExpiresAt)
	}
}

func TestSignerErrorsPropagate(t *testing.T) {
	want := errors.New("boom")
	m := NewManager(ManagerConfig{
		Clock: testClock{now: time.Unix(1_700_000_000, 0)},
		Signer: SignerFunc(func(context.Context, string, DmqMessagePayload) (*DmqMessage, error) {
			return nil, want
		}),
	})
	if err := m.RegisterTopic("topic", TopicConfig{}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Publish(context.Background(), "topic", []byte("body")); !errors.Is(err, want) {
		t.Fatalf("Publish error = %v, want %v", err, want)
	}
}

func TestDuplicateSuppression(t *testing.T) {
	m := NewManager(ManagerConfig{Clock: testClock{now: time.Now()}, Signer: testSigner(t)})
	if err := m.RegisterTopic("topic", TopicConfig{}); err != nil {
		t.Fatal(err)
	}
	msg, err := m.Publish(context.Background(), "topic", []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SubmitSigned(context.Background(), "topic", msg); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("SubmitSigned duplicate error = %v", err)
	}
}

func TestTTLExpiryRejected(t *testing.T) {
	m := NewManager(ManagerConfig{Clock: testClock{now: time.Now()}})
	if err := m.RegisterTopic("topic", TopicConfig{}); err != nil {
		t.Fatal(err)
	}
	msg := &DmqMessage{
		Payload: DmqMessagePayload{
			MessageBody: []byte("expired"),
			ExpiresAt:   uint32(time.Now().Add(-time.Minute).Unix()),
		},
	}
	if err := msg.SetComputedMessageID(); err != nil {
		t.Fatal(err)
	}
	if err := m.SubmitSigned(context.Background(), "topic", msg); !errors.Is(err, ErrMessageExpired) {
		t.Fatalf("SubmitSigned expired error = %v, want %v", err, ErrMessageExpired)
	}
}

func TestQueueBounds(t *testing.T) {
	m := NewManager(ManagerConfig{Clock: testClock{now: time.Now()}, Signer: testSigner(t)})
	if err := m.RegisterTopic("topic", TopicConfig{Queue: QueueConfig{MaxMessages: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Publish(context.Background(), "topic", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Publish(context.Background(), "topic", []byte("two")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("Publish second error = %v", err)
	}
}

func TestPublishRejectsOversizedBody(t *testing.T) {
	m := NewManager(ManagerConfig{Clock: testClock{now: time.Now()}, Signer: testSigner(t)})
	if err := m.RegisterTopic("topic", TopicConfig{}); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, MaxMessageBodyBytes+1)
	if _, err := m.Publish(context.Background(), "topic", body); !errors.Is(err, ErrMessageBodyTooLarge) {
		t.Fatalf("Publish oversized body error = %v, want %v", err, ErrMessageBodyTooLarge)
	}
}

func TestExpiresAtRejectsOutOfRange(t *testing.T) {
	now := time.Unix(MaxMessageExpiresAtUnix, 0)
	_, err := ExpiresAt(now, time.Second)
	if !errors.Is(err, ErrMessageExpiryOutOfRange) {
		t.Fatalf("ExpiresAt error = %v, want %v", err, ErrMessageExpiryOutOfRange)
	}
}

func TestCanceledContextDuringFanoutDoesNotFailAcceptedPublish(t *testing.T) {
	m := NewManager(ManagerConfig{Clock: testClock{now: time.Now()}, Signer: testSigner(t)})
	if err := m.RegisterTopic("topic", TopicConfig{
		Queue: QueueConfig{
			MaxMessages:      32,
			SubscriberBuffer: 1,
		},
	}); err != nil {
		t.Fatal(err)
	}
	sub, err := m.Subscribe("topic")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Close() }()

	if _, err := m.Publish(context.Background(), "topic", []byte("fills-buffer")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := range 10 {
		if _, err := m.Publish(ctx, "topic", []byte{byte(i)}); err != nil {
			t.Fatalf("Publish with canceled context after acceptance: %v", err)
		}
	}
}

func TestShutdownClosesSubscriptions(t *testing.T) {
	m := NewManager(ManagerConfig{Signer: testSigner(t)})
	if err := m.RegisterTopic("topic", TopicConfig{}); err != nil {
		t.Fatal(err)
	}
	sub, err := m.Subscribe("topic")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := <-sub.C; ok {
		t.Fatal("expected closed subscription channel")
	}
	if _, err := m.Publish(context.Background(), "topic", []byte("body")); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("Publish after shutdown = %v", err)
	}
}

func TestLocalMessageSubmissionConfigUsesManagerClock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := NewManager(ManagerConfig{Clock: testClock{now: now}})
	if err := m.RegisterTopic("topic", TopicConfig{}); err != nil {
		t.Fatal(err)
	}
	cfg, err := m.LocalMessageSubmissionConfig("topic")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SubmitMessageFunc == nil {
		t.Fatal("expected submit callback")
	}

	msg := &DmqMessage{
		Payload: DmqMessagePayload{
			MessageBody: []byte("body"),
			ExpiresAt:   uint32(now.Add(time.Minute).Unix()),
		},
	}
	if err := msg.SetComputedMessageID(); err != nil {
		t.Fatal(err)
	}
	if reason := cfg.SubmitMessageFunc(localmessagesubmission.CallbackContext{}, msg); reason != nil {
		t.Fatalf("submit reason = %#v", reason)
	}
	reason := cfg.SubmitMessageFunc(localmessagesubmission.CallbackContext{}, msg)
	if reason == nil {
		t.Fatal("expected duplicate rejection")
	}
	if reason.RejectReasonType() != (AlreadyReceivedReason{}).RejectReasonType() {
		t.Fatalf("duplicate reason = %#v", reason)
	}
}

func TestTopologyParsing(t *testing.T) {
	cfg, err := ReadTopology(strings.NewReader(`{
		"localRoots": [{"accessPoints":[{"address":"relay.local","port":3001}],"advertise":true,"trustable":true,"valency":1,"warmValency":2}],
		"publicRoots": [{"accessPoints":[{"address":"relay.public","port":3002}],"advertise":true,"valency":3,"warmValency":4}],
		"bootstrapPeers": [{"address":"bootstrap","port":3003}],
		"useLedgerAfterSlot": 42
	}`))
	if err != nil {
		t.Fatalf("ReadTopology: %v", err)
	}
	peers := TopologyPeers(cfg)
	if len(peers) != 3 {
		t.Fatalf("peer count = %d", len(peers))
	}
	if peers[0].Source != PeerSourceTopologyLocalRoot || peers[0].Valency != 1 || !peers[0].Trustable {
		t.Fatalf("unexpected local root: %+v", peers[0])
	}
}

func TestNewDiscoveryConfigLoadsTopologyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "topology.json")
	if err := os.WriteFile(
		path,
		[]byte(`{
			"localRoots": [{"accessPoints":[{"address":"relay.local","port":3001}],"advertise":true,"trustable":true,"valency":1}],
			"publicRoots": [],
			"bootstrapPeers": []
		}`),
		0o600,
	); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := NewDiscoveryConfig(path, []Peer{{Address: "static.local:3002"}})
	if err != nil {
		t.Fatalf("NewDiscoveryConfig: %v", err)
	}
	peers := TopologyPeers(cfg.Topology)
	if len(peers) != 1 || peers[0].Address != "relay.local:3001" {
		t.Fatalf("topology peers = %+v", peers)
	}
	if len(cfg.StaticPeers) != 1 || cfg.StaticPeers[0].Address != "static.local:3002" {
		t.Fatalf("static peers = %+v", cfg.StaticPeers)
	}
	if cfg.StaticPeers[0].Source != PeerSourceStatic {
		t.Fatalf("static peer source = %q", cfg.StaticPeers[0].Source)
	}
}

func TestLedgerPeerPoolsIncludeRelayKindsAndBigLedger(t *testing.T) {
	snapshot := LedgerPeerSnapshot{Peers: []LedgerPeer{
		{PoolID: "a", Stake: 80, Relays: []LedgerRelay{{Kind: LedgerRelaySRV, SRVName: "_cardano._tcp.a.example"}}},
		{PoolID: "b", Stake: 10, Relays: []LedgerRelay{{Kind: LedgerRelaySRV, SRVName: "_cardano._tcp.b.example"}}},
		{PoolID: "c", Stake: 5, Relays: []LedgerRelay{{Kind: LedgerRelaySRV, SRVName: "_cardano._tcp.c.example"}}},
		{PoolID: "d", Stake: 5, Relays: []LedgerRelay{{Kind: LedgerRelaySingleHostName, Hostname: "d.example", Port: 3001}}},
		{PoolID: "e", Relays: []LedgerRelay{{Kind: LedgerRelaySingleHostAddress, IPv4: net.ParseIP("192.0.2.1")}}},
	}}
	pools := BuildLedgerPeerPools(snapshot)
	if len(pools.All) != 5 {
		t.Fatalf("all ledger peers = %d", len(pools.All))
	}
	if !hasPeerAddress(pools.All, "d.example:3001") {
		t.Fatalf("missing single-host relay: %+v", pools.All)
	}
	if !hasPeerAddress(pools.All, "192.0.2.1:3001") {
		t.Fatalf("missing IP relay: %+v", pools.All)
	}
	if len(pools.Big) != 2 {
		t.Fatalf("big ledger peers = %d", len(pools.Big))
	}
	if pools.Big[0].PoolID != "a" || pools.Big[1].PoolID != "b" {
		t.Fatalf("unexpected big ledger peers: %+v", pools.Big)
	}
}

func TestBigLedgerPeersCountStakeOncePerPool(t *testing.T) {
	snapshot := LedgerPeerSnapshot{Peers: []LedgerPeer{
		{PoolID: "a", Stake: 80, Relays: []LedgerRelay{
			{Kind: LedgerRelaySRV, SRVName: "_cardano._tcp.a1.example"},
			{Kind: LedgerRelaySRV, SRVName: "_cardano._tcp.a2.example"},
			{Kind: LedgerRelaySRV, SRVName: "_cardano._tcp.a3.example"},
		}},
		{PoolID: "b", Stake: 10, Relays: []LedgerRelay{{Kind: LedgerRelaySRV, SRVName: "_cardano._tcp.b.example"}}},
		{PoolID: "c", Stake: 10, Relays: []LedgerRelay{{Kind: LedgerRelaySRV, SRVName: "_cardano._tcp.c.example"}}},
	}}
	pools := BuildLedgerPeerPools(snapshot)
	if len(pools.Big) != 4 {
		t.Fatalf("big ledger peers = %d, peers = %+v", len(pools.Big), pools.Big)
	}
	if !hasPoolID(pools.Big, "b") {
		t.Fatalf("expected pool b to be included in big ledger peers: %+v", pools.Big)
	}
	if hasPoolID(pools.Big, "c") {
		t.Fatalf("did not expect pool c in big ledger peers: %+v", pools.Big)
	}
}

func TestBigLedgerPeersAvoidsStakeThresholdOverflow(t *testing.T) {
	stake := ^uint64(0) / 2
	snapshot := LedgerPeerSnapshot{Peers: []LedgerPeer{
		{PoolID: "a", Stake: stake, Relays: []LedgerRelay{{Kind: LedgerRelaySRV, SRVName: "_cardano._tcp.a.example"}}},
		{PoolID: "b", Stake: stake, Relays: []LedgerRelay{{Kind: LedgerRelaySRV, SRVName: "_cardano._tcp.b.example"}}},
	}}
	pools := BuildLedgerPeerPools(snapshot)
	if len(pools.Big) != 2 {
		t.Fatalf("big ledger peers = %d, peers = %+v", len(pools.Big), pools.Big)
	}
	if !hasPoolID(pools.Big, "a") || !hasPoolID(pools.Big, "b") {
		t.Fatalf("expected both high-stake pools in big ledger peers: %+v", pools.Big)
	}
}

func TestDingoLedgerPeerProviderAdapterPreservesStakeWhenAvailable(t *testing.T) {
	provider := &mockStakedLedgerPeerProvider{
		slot: 42,
		peers: []LedgerPeer{
			{PoolID: "pool-a", Stake: 100, Relays: []LedgerRelay{{Kind: LedgerRelaySingleHostName, Hostname: "relay.example", Port: 3001}}},
		},
	}
	snapshot, err := (DingoLedgerPeerProviderAdapter{StakedProvider: provider}).LedgerPeerSnapshot(context.Background(), LedgerPeerSnapshotAll)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Slot != 42 || len(snapshot.Peers) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if snapshot.Peers[0].PoolID != "pool-a" || snapshot.Peers[0].Stake != 100 {
		t.Fatalf("peer metadata dropped: %+v", snapshot.Peers[0])
	}
	pools := BuildLedgerPeerPools(snapshot)
	if len(pools.Big) != 1 || pools.Big[0].PoolID != "pool-a" {
		t.Fatalf("big ledger peers = %+v", pools.Big)
	}
}

func TestDingoLedgerPeerProviderAdapterRejectsRelayOnlyByDefault(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")
	provider := &mockDingoLedgerPeerProvider{
		slot:   42,
		relays: []peergov.PoolRelay{{IPv4: &ip, Port: 3001}},
	}
	_, err := (DingoLedgerPeerProviderAdapter{Provider: provider}).LedgerPeerSnapshot(context.Background(), LedgerPeerSnapshotAll)
	if !errors.Is(err, ErrLedgerPeerSnapshotUnsupported) {
		t.Fatalf("error = %v", err)
	}

	snapshot, err := (DingoLedgerPeerProviderAdapter{
		Provider:       provider,
		AllowRelayOnly: true,
	}).LedgerPeerSnapshot(context.Background(), LedgerPeerSnapshotAll)
	if err != nil {
		t.Fatal(err)
	}
	pools := BuildLedgerPeerPools(snapshot)
	if len(pools.All) != 1 || pools.All[0].Address != "192.0.2.1:3001" {
		t.Fatalf("all ledger peers = %+v", pools.All)
	}
	if len(pools.Big) != 0 {
		t.Fatalf("relay-only adapter produced big ledger peers: %+v", pools.Big)
	}
}

func TestRegisterTopicInitializesDefaultAuthenticator(t *testing.T) {
	m := NewManager(ManagerConfig{})
	if err := m.RegisterTopic("topic", TopicConfig{Authentication: AuthenticationConfig{Required: true}}); err != nil {
		t.Fatal(err)
	}
	rt, err := m.topic("topic")
	if err != nil {
		t.Fatal(err)
	}
	if rt.cfg.Authentication.Authenticator == nil {
		t.Fatal("expected default authenticator")
	}
}

func TestDefaultTopicConfigClampsMaxTTLToDefaultTTL(t *testing.T) {
	cfg := defaultTopicConfig(TopicConfig{
		TTL: TTLPolicy{
			DefaultTTL: time.Hour,
			MaxTTL:     time.Minute,
		},
	})
	if cfg.TTL.MaxTTL != time.Hour {
		t.Fatalf("MaxTTL = %v, want %v", cfg.TTL.MaxTTL, time.Hour)
	}
}

func TestLocalStateQueryLedgerPeerSnapshotProvider(t *testing.T) {
	domain := "relay.example"
	port := uint16(3001)
	client := &mockLocalStateQueryLedgerPeerSnapshotClient{
		snapshot: &localstatequery.LedgerPeerSnapshotResult{
			Slot: localstatequery.WithOriginSlot{HasSlot: true, Slot: 42},
			Pools: []localstatequery.PoolLedgerPeers{
				{
					AccumulatedStake: &cbor.Rat{Rat: big.NewRat(9, 10)},
					Detail: localstatequery.PoolLedgerPeersDetail{
						PoolStake: &cbor.Rat{Rat: big.NewRat(9, 10)},
						Relays: []localstatequery.RelayAccessPoint{
							{Kind: localstatequery.RelayKindDomain, Domain: &domain, Port: &port},
						},
					},
				},
			},
		},
	}
	provider := LocalStateQueryLedgerPeerSnapshotProvider{
		Client: client,
	}
	snapshot, err := provider.LedgerPeerSnapshot(context.Background(), LedgerPeerSnapshotAll)
	if err != nil {
		t.Fatal(err)
	}
	if client.kind != localstatequery.LedgerPeerKindAll {
		t.Fatalf("ledger peer kind = %d", client.kind)
	}
	if snapshot.Slot != 42 || len(snapshot.Peers) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if snapshot.Peers[0].Stake == 0 {
		t.Fatalf("expected scaled stake: %+v", snapshot.Peers[0])
	}
	pools := BuildLedgerPeerPools(snapshot)
	if len(pools.All) != 1 || pools.All[0].Address != "relay.example:3001" {
		t.Fatalf("all ledger peers = %+v", pools.All)
	}
	if len(pools.Big) != 1 || pools.Big[0].Source != PeerSourceBigLedger {
		t.Fatalf("big ledger peers = %+v", pools.Big)
	}
}

func TestLocalStateQueryLedgerPeerSnapshotProviderUnsupported(t *testing.T) {
	provider := LocalStateQueryLedgerPeerSnapshotProvider{
		Client: &mockLocalStateQueryLedgerPeerSnapshotClient{
			err: localstatequery.ErrLedgerPeerSnapshotUnsupportedVersion,
		},
	}
	_, err := provider.LedgerPeerSnapshot(context.Background(), LedgerPeerSnapshotAll)
	if !errors.Is(err, ErrLedgerPeerSnapshotUnsupported) {
		t.Fatalf("error = %v", err)
	}
}

func TestLedgerPeerUnsupportedFallback(t *testing.T) {
	m := NewManager(ManagerConfig{})
	provider := LedgerPeerSnapshotProviderFunc(func(context.Context, LedgerPeerSnapshotKind) (LedgerPeerSnapshot, error) {
		return LedgerPeerSnapshot{}, ErrLedgerPeerSnapshotUnsupported
	})
	if err := m.RegisterTopic("topic", TopicConfig{
		Discovery: DiscoveryConfig{
			StaticPeers: []Peer{newPeer("static.example", 3001, Peer{Source: PeerSourceStatic})},
			LedgerPeers: LedgerPeerDiscoveryConfig{
				Enabled:          true,
				AllowUnsupported: true,
				Provider:         provider,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	peers, err := m.TopicPeers(context.Background(), "topic")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].Source != PeerSourceStatic {
		t.Fatalf("peers = %+v", peers)
	}
}

func TestLedgerPeerRefreshPrunesRemovedPeers(t *testing.T) {
	snapshots := []LedgerPeerSnapshot{
		{Peers: []LedgerPeer{{
			PoolID: "a",
			Stake:  100,
			Relays: []LedgerRelay{{Kind: LedgerRelaySingleHostName, Hostname: "ledger-a.example", Port: 3001}},
		}}},
		{Peers: []LedgerPeer{{
			PoolID: "b",
			Stake:  100,
			Relays: []LedgerRelay{{Kind: LedgerRelaySingleHostName, Hostname: "ledger-b.example", Port: 3001}},
		}}},
	}
	call := 0
	provider := LedgerPeerSnapshotProviderFunc(func(context.Context, LedgerPeerSnapshotKind) (LedgerPeerSnapshot, error) {
		if call >= len(snapshots) {
			return snapshots[len(snapshots)-1], nil
		}
		snapshot := snapshots[call]
		call++
		return snapshot, nil
	})
	m := NewManager(ManagerConfig{})
	if err := m.RegisterTopic("topic", TopicConfig{
		Discovery: DiscoveryConfig{
			StaticPeers: []Peer{newPeer("static.example", 3001, Peer{Source: PeerSourceStatic})},
			LedgerPeers: LedgerPeerDiscoveryConfig{
				Enabled:  true,
				Provider: provider,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	peers, err := m.TopicPeers(context.Background(), "topic")
	if err != nil {
		t.Fatal(err)
	}
	if !hasPeerAddress(peers, "ledger-a.example:3001") {
		t.Fatalf("first refresh peers = %+v", peers)
	}

	peers, err = m.TopicPeers(context.Background(), "topic")
	if err != nil {
		t.Fatal(err)
	}
	if hasPeerAddress(peers, "ledger-a.example:3001") {
		t.Fatalf("stale ledger peer was not pruned: %+v", peers)
	}
	if !hasPeerAddress(peers, "ledger-b.example:3001") {
		t.Fatalf("new ledger peer missing after refresh: %+v", peers)
	}
	if !hasPeerAddress(peers, "static.example:3001") {
		t.Fatalf("static peer should be preserved: %+v", peers)
	}
}

func TestLedgerPeersDefaultOff(t *testing.T) {
	called := false
	m := NewManager(ManagerConfig{})
	provider := LedgerPeerSnapshotProviderFunc(func(context.Context, LedgerPeerSnapshotKind) (LedgerPeerSnapshot, error) {
		called = true
		return LedgerPeerSnapshot{}, nil
	})
	if err := m.RegisterTopic("topic", TopicConfig{
		Discovery: DiscoveryConfig{
			StaticPeers: []Peer{newPeer("static.example", 3001, Peer{Source: PeerSourceStatic})},
			LedgerPeers: LedgerPeerDiscoveryConfig{
				Provider: provider,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	peers, err := m.TopicPeers(context.Background(), "topic")
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("ledger provider was called while discovery was disabled")
	}
	if len(peers) != 1 || peers[0].Source != PeerSourceStatic {
		t.Fatalf("peers = %+v", peers)
	}
}

func TestPeerSelectorQuotas(t *testing.T) {
	selector := NewPeerSelector(PeerSelectionConfig{
		TopologyQuota:  1,
		PeerShareQuota: 1,
		LedgerQuota:    2,
		BigLedgerQuota: 1,
	})
	selector.AddPeers([]Peer{
		newPeer("topology-local", 3001, Peer{Source: PeerSourceTopologyLocalRoot}),
		newPeer("topology-a", 3001, Peer{Source: PeerSourceTopologyPublic}),
		newPeer("topology-b", 3001, Peer{Source: PeerSourceTopologyPublic}),
		newPeer("topology-bootstrap", 3001, Peer{Source: PeerSourceTopologyBootstrap}),
		newPeer("static-a", 3001, Peer{Source: PeerSourceStatic}),
		newPeer("shared-a", 3001, Peer{Source: PeerSourcePeerSharing}),
		newPeer("ledger-a", 3001, Peer{Source: PeerSourceLedger}),
		newPeer("ledger-b", 3001, Peer{Source: PeerSourceLedger}),
		newPeer("ledger-c", 3001, Peer{Source: PeerSourceLedger}),
		newPeer("big-a", 3001, Peer{Source: PeerSourceBigLedger}),
		newPeer("big-b", 3001, Peer{Source: PeerSourceBigLedger}),
	})
	selected := selector.Select(0)
	counts := map[PeerSource]int{}
	topologyCount := 0
	for _, peer := range selected {
		counts[peer.Source]++
		if isTopologyQuotaSource(peer.Source) {
			topologyCount++
		}
	}
	if topologyCount != 1 ||
		counts[PeerSourcePeerSharing] != 1 ||
		counts[PeerSourceLedger] != 2 ||
		counts[PeerSourceBigLedger] != 1 {
		t.Fatalf("topologyCount = %d, counts = %+v, selected = %+v", topologyCount, counts, selected)
	}
}

func TestFileSignerSignsAndVerifies(t *testing.T) {
	dir := t.TempDir()
	kesPath, opcertPath := writeSignerFixtures(t, dir, 5)
	signer, err := NewFileSigner(FileSignerConfig{
		KESSigningKeyPath:          kesPath,
		OperationalCertificatePath: opcertPath,
		KESPeriod:                  5,
	})
	if err != nil {
		t.Fatalf("NewFileSigner: %v", err)
	}
	msg, err := signer.Sign(context.Background(), "topic", DmqMessagePayload{
		MessageBody: []byte("body"),
		ExpiresAt:   uint32(time.Now().Add(time.Minute).Unix()),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := signer.Verify(msg)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected signature to verify")
	}
}

func TestPayloadSigningBytesClearsLegacyMessageID(t *testing.T) {
	payload := DmqMessagePayload{
		MessageID:   []byte("legacy"),
		MessageBody: []byte("body"),
		KESPeriod:   5,
		ExpiresAt:   uint32(time.Now().Add(time.Minute).Unix()),
	}
	withLegacyID, err := PayloadSigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.MessageID = nil
	withoutLegacyID, err := PayloadSigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(withLegacyID) != string(withoutLegacyID) {
		t.Fatal("legacy payload message ID changed signing bytes")
	}
}

func TestFileSignerKESPeriodFuncCanAccessSigner(t *testing.T) {
	dir := t.TempDir()
	kesPath, opcertPath := writeSignerFixtures(t, dir, 5)
	var signer *FileSigner
	signer, err := NewFileSigner(FileSignerConfig{
		KESSigningKeyPath:          kesPath,
		OperationalCertificatePath: opcertPath,
		KESPeriodFunc: func(context.Context) (uint64, error) {
			if len(signer.KESVerificationKey()) == 0 {
				return 0, errors.New("empty KES verification key")
			}
			return 5, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFileSigner: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := signer.Sign(context.Background(), "topic", DmqMessagePayload{
			MessageBody: []byte("body"),
			ExpiresAt:   uint32(time.Now().Add(time.Minute).Unix()),
		})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Sign timed out; KESPeriodFunc may be called under signer lock")
	}
}

func TestFileSignerVerifyUsesMessageOperationalCertificatePeriod(t *testing.T) {
	verifierDir := t.TempDir()
	verifierKESPath, verifierOpCertPath := writeSignerFixtures(t, verifierDir, 5)
	verifier, err := NewFileSigner(FileSignerConfig{
		KESSigningKeyPath:          verifierKESPath,
		OperationalCertificatePath: verifierOpCertPath,
		KESPeriod:                  5,
	})
	if err != nil {
		t.Fatalf("NewFileSigner verifier: %v", err)
	}

	signerDir := t.TempDir()
	signerKESPath, signerOpCertPath := writeSignerFixtures(t, signerDir, 10)
	signer, err := NewFileSigner(FileSignerConfig{
		KESSigningKeyPath:          signerKESPath,
		OperationalCertificatePath: signerOpCertPath,
		KESPeriod:                  10,
	})
	if err != nil {
		t.Fatalf("NewFileSigner signer: %v", err)
	}
	msg, err := signer.Sign(context.Background(), "topic", DmqMessagePayload{
		MessageBody: []byte("body"),
		ExpiresAt:   uint32(time.Now().Add(time.Minute).Unix()),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := verifier.Verify(msg)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected signature to verify with message opcert period")
	}
}

func TestDmqMessageCBORRoundTrip(t *testing.T) {
	msg := DmqMessage{
		Payload: DmqMessagePayload{
			MessageBody: []byte("body"),
			KESPeriod:   1,
			ExpiresAt:   uint32(time.Now().Add(time.Minute).Unix()),
		},
		KESSignature: []byte("sig"),
		OperationalCertificate: OperationalCertificate{
			KESVerificationKey: []byte("kes"),
			ColdSignature:      []byte("cold"),
		},
		ColdVerificationKey: []byte("cold-vkey"),
	}
	if err := msg.SetComputedMessageID(); err != nil {
		t.Fatal(err)
	}
	data, err := cbor.Encode(msg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DmqMessage
	if _, err := cbor.Decode(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.Payload.MessageBody) != "body" {
		t.Fatalf("decoded body = %q", decoded.Payload.MessageBody)
	}
	if string(decoded.ID()) != string(msg.ID()) {
		t.Fatal("decoded ID mismatch")
	}
}

type LedgerPeerSnapshotProviderFunc func(context.Context, LedgerPeerSnapshotKind) (LedgerPeerSnapshot, error)

func (f LedgerPeerSnapshotProviderFunc) LedgerPeerSnapshot(ctx context.Context, kind LedgerPeerSnapshotKind) (LedgerPeerSnapshot, error) {
	return f(ctx, kind)
}

type mockLocalStateQueryLedgerPeerSnapshotClient struct {
	kind     localstatequery.LedgerPeerKind
	snapshot *localstatequery.LedgerPeerSnapshotResult
	err      error
}

func (m *mockLocalStateQueryLedgerPeerSnapshotClient) GetLedgerPeerSnapshot(kind localstatequery.LedgerPeerKind) (*localstatequery.LedgerPeerSnapshotResult, error) {
	m.kind = kind
	return m.snapshot, m.err
}

type mockDingoLedgerPeerProvider struct {
	slot   uint64
	relays []peergov.PoolRelay
	err    error
}

func (m *mockDingoLedgerPeerProvider) GetPoolRelays() ([]peergov.PoolRelay, error) {
	return m.relays, m.err
}

func (m *mockDingoLedgerPeerProvider) CurrentSlot() uint64 {
	return m.slot
}

func writeSignerFixtures(t *testing.T, dir string, opcertKESPeriod uint64) (string, string) {
	t.Helper()
	return writeSignerFixturesWithSeed(t, dir, opcertKESPeriod, 0x42)
}

func writeSignerFixturesWithSeed(t *testing.T, dir string, opcertKESPeriod uint64, seedByte byte) (string, string) {
	t.Helper()
	kesPath := filepath.Join(dir, "kes.skey")
	opcertPath := filepath.Join(dir, "opcert.cert")
	vkey := writeKESKeyFixture(t, kesPath, seedByte)
	writeOperationalCertificateFixture(t, opcertPath, vkey, opcertKESPeriod)
	return kesPath, opcertPath
}

func writeKESKeyFixture(t *testing.T, path string, seedByte byte) []byte {
	t.Helper()
	seed := bytesOf(32, seedByte)
	sk, vkey, err := kes.KeyGen(kes.CardanoKesDepth, seed)
	if err != nil {
		t.Fatal(err)
	}
	kesCBOR, err := cbor.Encode(sk.Data)
	if err != nil {
		t.Fatal(err)
	}
	writeKeyFile(t, path, "KesSigningKey_ed25519_kes_2^6", kesCBOR)
	return cloneBytes(vkey)
}

func writeOperationalCertificateFixture(t *testing.T, path string, vkey []byte, opcertKESPeriod uint64) {
	t.Helper()
	coldPub, coldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var body [48]byte
	copy(body[:32], vkey)
	binary.BigEndian.PutUint64(body[32:40], 1)
	binary.BigEndian.PutUint64(body[40:48], opcertKESPeriod)
	sig := ed25519.Sign(coldPriv, body[:])
	opcertCBOR, err := cbor.Encode([]any{
		[]any{vkey, uint64(1), opcertKESPeriod, sig},
		[]byte(coldPub),
	})
	if err != nil {
		t.Fatal(err)
	}
	writeKeyFile(t, path, "NodeOperationalCertificate", opcertCBOR)
}

func writeKeyFile(t *testing.T, path, typ string, cborData []byte) {
	t.Helper()
	body := `{"type":"` + typ + `","description":"","cborHex":"` + hex.EncodeToString(cborData) + `"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bytesOf(n int, b byte) []byte {
	ret := make([]byte, n)
	for i := range ret {
		ret[i] = b
	}
	return ret
}

func hasPeerAddress(peers []Peer, address string) bool {
	for _, peer := range peers {
		if peer.Address == address {
			return true
		}
	}
	return false
}

func hasPoolID(peers []Peer, poolID string) bool {
	for _, peer := range peers {
		if peer.PoolID == poolID {
			return true
		}
	}
	return false
}

type mockStakedLedgerPeerProvider struct {
	slot  uint64
	peers []LedgerPeer
}

func (m *mockStakedLedgerPeerProvider) GetLedgerPeers() ([]LedgerPeer, error) {
	return m.peers, nil
}

func (m *mockStakedLedgerPeerProvider) CurrentSlot() uint64 {
	return m.slot
}
