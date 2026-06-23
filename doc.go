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

// Package dmq provides an embeddable implementation of the CIP-0137
// Distributed Message Queue for Go applications.
//
// The package manages topic-scoped queues, local fanout subscriptions,
// deterministic message ID checks, TTL policy, duplicate suppression, optional
// gOuroboros message authentication, and lifecycle hooks. Use Manager when a
// process needs explicit multi-topic control, or TopicNode when it wants a
// single-topic node that can register the topic, load discovery peers, start
// node-to-node networking, and shut down as one unit.
//
// dmq aliases the gOuroboros DMQ wire types so callers can publish local
// message bodies through a Signer or submit already signed CIP-0137 messages
// directly. It includes Cardano network timing helpers, file-backed,
// reloadable, and external-process KES signing helpers, topology and ledger
// peer discovery, and gOuroboros protocol adapters for local message
// submission, local message notification, and node-to-node message
// submission.
//
// The module path is github.com/blinklabs-io/dmq-lib; the package name is
// dmq:
//
//	import dmq "github.com/blinklabs-io/dmq-lib"
//
// # Core concepts
//
//   - Manager: owns topics. RegisterTopic, then Publish / SubmitSigned /
//     Subscribe / StartNodeToNode per topic. Shutdown releases everything.
//   - TopicNode: one-call wrapper that builds a Manager, registers a single
//     topic, and optionally starts networking. Prefer it for single-topic
//     processes.
//   - Signer: signs locally published bodies into DMQ messages. Required for
//     Publish; not required to SubmitSigned pre-signed messages or to relay.
//   - Subscription: per-subscriber buffered channel of accepted messages.
//   - NodeToNodeService: TCP listener plus reconnecting outbound dials that
//     exchange queued messages with peers via the CIP-0137 message-submission
//     protocol.
//   - Peer discovery: static peers, Cardano topology files, and ledger relay
//     snapshots feed a per-topic PeerSelector.
//
// # Quick start: single-topic node
//
//	signer, err := dmq.NewFileSigner(dmq.FileSignerConfig{
//		KESSigningKeyPath:          "kes.skey",
//		OperationalCertificatePath: "node.opcert",
//		KESPeriodFunc: func(ctx context.Context) (uint64, error) {
//			return dmq.CurrentKESPeriod(764824073, time.Now())
//		},
//	})
//	if err != nil {
//		return err
//	}
//	node, err := dmq.NewTopicNode(ctx, dmq.TopicNodeConfig{
//		Topic:         "mithril-signatures",
//		ManagerConfig: dmq.ManagerConfig{Signer: signer},
//		TopicConfig: dmq.TopicConfig{
//			NetworkMagic:   764824073,
//			Authentication: dmq.AuthenticationConfig{Required: true},
//		},
//		TopologyFile: "topology.json",
//		NodeToNode:    dmq.NodeToNodeConfig{ListenAddress: ":3141"},
//	})
//	if err != nil {
//		return err
//	}
//	defer node.Close()
//
//	sub, err := node.Subscribe()
//	if err != nil {
//		return err
//	}
//	defer sub.Close()
//	go func() {
//		for msg := range sub.C {
//			handle(msg.Body, msg.Source, msg.Peer)
//		}
//	}()
//
//	signed, err := node.Publish(ctx, []byte("message body"))
//
// Networking starts only when TopicNodeConfig provides a listen address,
// peers, or a discovery source; otherwise the node is purely local.
//
// # Multi-topic control with Manager
//
//	mgr := dmq.NewManager(dmq.ManagerConfig{Logger: logger, Signer: signer})
//	defer mgr.Shutdown(ctx)
//	if err := mgr.RegisterTopic("topic-a", dmq.TopicConfig{
//		NetworkMagic:   1,
//		Authentication: dmq.AuthenticationConfig{Required: true},
//	}); err != nil {
//		return err
//	}
//	// StartNodeToNode returns ErrAuthenticationRequired unless the topic sets
//	// Authentication.Required or Authentication.AllowUnauthenticated.
//	svc, err := mgr.StartNodeToNode(ctx, "topic-a", dmq.NodeToNodeConfig{
//		ListenAddress: ":3141",
//		Peers:         []dmq.Peer{{Host: "relay.example.com", Port: 3141}},
//	})
//
// # Choosing a signer
//
//   - FileSigner (NewFileSigner): signs DMQ payloads with a KES signing key
//     and operational certificate from cardano-cli text-envelope files.
//   - ReloadingSigner (NewReloadingFileSigner / NewReloadingSigner): wraps a
//     signer so Reload swaps in fresh credentials after KES rotation without
//     restarting.
//   - KESSigningProvider (NewKESSigner, NewExternalKESSigner, and their
//     reloading variants): lower-level interface that signs arbitrary bytes
//     at a relative KES period. ExternalKESSigner delegates each signature to
//     an operator-supplied helper process so the KES secret key never enters
//     this process. Adapt a provider to Signer with
//     NewKESSigningProviderSigner, or build one-off messages with
//     BuildSignedMessage.
//   - SignerFunc: adapt any function to the Signer interface.
//
// KES periods passed to KESSigningProvider methods are relative to the
// operational certificate's start period; DmqMessagePayload.KESPeriod on the
// wire is absolute. KES keys evolve forward only: signing at a period earlier
// than one already used fails.
//
// # Message validation
//
// Every submission (Publish, SubmitSigned, SubmitRemote, and messages
// arriving over the network) passes through the same pipeline: body size
// check (MaxMessageBodyBytes), deterministic message ID verification
// (ErrMessageIDMismatch), TTL validation (ErrMessageExpired,
// ErrMessageTTLTooFar), optional authenticator verification when
// TopicConfig.Authentication.Required is set, duplicate suppression
// (ErrDuplicateMessage), and queue capacity (ErrQueueFull). Rejections invoke
// Hooks.OnMessageRejected with a RejectReason; failures are sentinel errors
// matchable with errors.Is.
//
// # Security model
//
// Authentication is OFF by default: without it, remote messages are accepted
// after only message-id and TTL checks, with no KES signature, operational
// certificate, or SPO registration verification. Before exposing a node to
// untrusted peers, set TopicConfig.Authentication.Required and configure a
// gOuroboros MessageAuthenticator with a KES verifier and active pool set.
// FileSigner.Verify checks only signature self-consistency and must not be
// used for incoming-message authentication.
//
// # Cardano timing helpers
//
// NetworkParamsForMagic returns Shelley timing parameters for mainnet
// (764824073), preprod (1), and preview (2); NetworkParamsFromShelleyGenesis
// loads them for any other network. From NetworkParams derive
// CurrentKESPeriodFor, CurrentEpochFor, CurrentSlotFor, and KESPeriodStart.
// NewOperationalCredentialStatus reports an operational certificate's
// remaining KES evolutions and expiry for rotation monitoring.
//
// # Peer discovery
//
// DiscoveryConfig combines static peers, a Cardano node topology file
// (ParseTopologyFile, ReadTopology, or NewDiscoveryConfig), and ledger relay
// snapshots. Ledger snapshots come from a LedgerPeerSnapshotProvider:
// LocalStateQueryLedgerPeerSnapshotProvider queries a node over
// local-state-query, and DingoLedgerPeerProviderAdapter adapts dingo peer
// governor sources. BuildLedgerPeerPools splits a snapshot into all-peers and
// big-ledger (highest stake) pools, and PeerSelector applies per-source
// quotas.
//
// # gOuroboros protocol adapters
//
// To embed DMQ mini-protocols in an existing gOuroboros server, wire a topic
// into protocol configs with Manager.LocalMessageSubmissionConfig,
// Manager.LocalMessageNotificationConfig, and Manager.MessageSubmissionConfig.
// Manager.StartNodeToNode handles the node-to-node case end to end.
//
// # Constraints and defaults
//
//   - Message bodies are limited to MaxMessageBodyBytes (2000 bytes).
//   - ExpiresAt is a uint32 Unix timestamp on the wire; build payloads with
//     NewMessagePayload or ExpiresAt rather than by hand.
//   - TTL defaults: DefaultMessageTTL and MaxMessageTTL are both 30 minutes.
//   - Queue defaults: 100 messages, 16-message subscriber buffers, 10-minute
//     duplicate-suppression window.
//   - Subscription channels drop messages when full instead of blocking;
//     size them with QueueConfig.SubscriberBuffer.
//   - Hooks run synchronously on the submitting goroutine; keep them fast.
//   - TopicConfig.NetworkMagic is required for node-to-node networking
//     (ErrNetworkMagicRequired).
//   - Manager and TopicNode methods are safe for concurrent use; after
//     Shutdown they return ErrManagerClosed.
package dmq
