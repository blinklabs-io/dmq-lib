# Architecture

This document is for developers changing `dmq-lib`. It describes the runtime
shape of the package, how messages move through it, and where common extension
points belong.

## Scope

`dmq-lib` is an embeddable Go implementation of CIP-0137 DMQ behavior around
gOuroboros wire types. The package owns local queueing, local fanout,
duplicate/TTL validation, optional message authentication, discovery helpers,
and protocol adapter wiring.

The package does not own process lifecycle, Cardano node lifecycle, persistent
storage, or policy about which DMQ topics an application should use. Those
decisions stay with the caller.

## Source Map

- `doc.go` contains the package-level API description.
- `types.go` defines public configuration, message, hook, signer, and type
  aliases for gOuroboros DMQ wire types.
- `manager.go` owns topic registration, topic lookup, services, and shutdown.
- `topic.go` implements per-topic queueing, subscriptions, dedupe, validation,
  TTL pruning, and hook dispatch.
- `topic_node.go` provides the single-topic convenience wrapper.
- `payload.go` implements body-size, TTL, expiry, and payload construction
  helpers.
- `protocol.go` exposes gOuroboros local and node-to-node protocol configs.
- `network.go` runs the embedded node-to-node listener, outbound dialers,
  handshake, muxer, and message-submission request loop.
- `discovery.go` handles topology parsing, ledger peer conversion, provider
  adapters, and peer selection helpers.
- `cardano.go` derives network timing, slots, epochs, and absolute KES periods.
- `signer.go` and `kes_payload.go` implement DMQ signing helpers, KES provider
  wrappers, operational certificate parsing, and external signer integration.
- `errors.go` centralizes exported sentinel errors.

## Runtime Ownership

```text
TopicNode
  Manager
    topicRuntime per topic
      queue
      seen message IDs
      subscriptions
      PeerSelector
    NodeToNodeService set
      listener
      outbound peer loops
      nodeToNodePeerConnection instances
```

`TopicNode` is a convenience wrapper. It constructs a `Manager`, merges
topology/static-peer shortcut fields into `TopicConfig.Discovery`, registers
one topic, and starts node-to-node networking when network configuration is
present.

`Manager` is the multi-topic owner. It stores topic runtimes by topic name,
tracks active `NodeToNodeService` values, and coordinates shutdown. Topic
runtimes and services are closed during `Shutdown`.

`topicRuntime` is the only owner of a topic queue. All local publishes, signed
submissions, local protocol adapters, and node-to-node remote messages converge
on `topicRuntime.submitSigned`.

## Message Lifecycle

Local publish:

1. `Manager.Publish` or `TopicNode.Publish` finds the `topicRuntime`.
2. `topicRuntime.publish` builds a payload with `NewMessagePayload`.
3. The topic signer, or manager default signer, signs the payload.
4. The signed message is passed to `submitSigned` with `MessageSourceLocal`.
5. `submitSigned` normalizes the deterministic message ID, validates body size
   and TTL, optionally authenticates the message, checks the dedupe cache, and
   appends to the bounded queue.
6. Subscribers receive a cloned `Message` envelope. Accepted hooks run after the
   queue update.

Signed submission:

1. `Manager.SubmitSigned` or `TopicNode.SubmitSigned` receives a complete
   `DmqMessage`.
2. The message is not re-signed.
3. It enters the same `submitSigned` validation, dedupe, queue, subscription,
   and hook path as a locally published message.

Remote node-to-node message:

1. `NodeToNodeService` creates a gOuroboros message-submission config for the
   topic.
2. The request loop asks peers for message IDs at `RequestInterval`.
3. Returned IDs are requested as full messages.
4. Returned messages are submitted with `MessageSourceRemote` and peer metadata.
5. Duplicate or expired messages are rejected by the same topic path used for
   local messages.

## Validation Policy

`submitSigned` is the central validation boundary.

It enforces:

- Maximum message body size with `ValidateMessageBody`.
- Deterministic message ID checks with `ComputeDmqMessageID`.
- TTL checks with gOuroboros `TTLValidator`, unless `TTLPolicy.Disable` is set.
- Optional gOuroboros `MessageAuthenticator` verification when
  `TopicConfig.Authentication.Required` is true.
- Duplicate suppression through the topic `seen` map.
- Queue capacity through `QueueConfig.MaxMessages`.

Defaults are applied during `RegisterTopic`:

- `Queue.MaxMessages`: `100`
- `Queue.SubscriberBuffer`: `16`
- `Queue.DuplicateTTL`: `10m`
- `TTL.DefaultTTL`: `DefaultMessageTTL` (`30m`)
- `TTL.MaxTTL`: `MaxMessageTTL` (`30m`)
- reconnect backoff: `1s` initial, `2m` max
- topology and peer-sharing quotas: `20`
- ledger peer target: `20`
- big-ledger peer target: `5`

Rejected messages are reported through `Hooks.OnMessageRejected` when
configured. Protocol adapters convert internal errors to gOuroboros reject
reasons with `rejectReasonFromError`.

## Queue and Subscription Model

Each topic has an in-memory FIFO queue bounded by `Queue.MaxMessages`. Expired
messages are pruned opportunistically when new messages are submitted or when
message IDs/messages are requested.

Subscriptions are in-process fanout channels. Each subscription has its own
buffer sized by `Queue.SubscriberBuffer`. If a subscriber buffer is full, the
notification is dropped for that subscriber only; the topic queue still retains
the accepted message.

The queue does not persist across process restarts. Applications that require
durability should persist their own accepted-message stream from
`Hooks.OnMessageAccepted` or a subscription.

## Concurrency

`Manager` uses an `RWMutex` to protect the topic map, service set, and closed
state. Individual topic runtimes use their own mutex for queue, dedupe, and
subscriber state. `NodeToNodeService` uses a mutex and wait group to coordinate
listeners, active peer connections, outbound dial loops, and close.

Defensive copies are used for messages, payload bodies, IDs, key material, and
peer metadata before values cross API boundaries. Keep this behavior when adding
new fields that carry mutable slices or pointer-owned data.

Hooks are called synchronously. Avoid calling hooks while holding topic or
service locks when adding new hook points.

## Signing and KES Helpers

The `Signer` interface is intentionally small:

```go
type Signer interface {
    Sign(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error)
}
```

`FileSigner` signs DMQ payloads from local KES key and operational certificate
files. `KESSigner` implements `KESSigningProvider` for arbitrary payload bytes
using network timing to derive the current relative KES period.
`KESSigningProviderSigner` adapts any `KESSigningProvider` into the DMQ
`Signer` interface. `ExternalKESSigner` delegates the actual signature to an
absolute helper executable without invoking a shell.

`ReloadingSigner` and `ReloadingKESSigningProvider` let embedding applications
swap active signing material without restarting. A reload constructs and
validates a complete replacement signer before publishing it; failed reloads
leave the previous signer active. Process signals and file-watch loops stay with
the embedding application rather than this library.

Operational certificate helpers validate KES verification keys, cold keys, cold
signatures, and KES period bounds. `FileSigner.Verify` only checks a
self-contained KES signature over a payload; it is not an identity or SPO
registration proof. Incoming-message authentication belongs on the
`TopicConfig.Authentication.Required` path.

## Discovery and Peer Selection

Discovery is configured per topic through `DiscoveryConfig`.

Static peers are copied directly. Topology files are parsed with Dingo topology
types and converted to package-level `Peer` values. Ledger discovery is opt-in
and requires a `LedgerPeerSnapshotProvider` unless `AllowUnsupported` lets the
topic fall back to non-ledger peers.

`BuildLedgerPeerPools` converts ledger relay snapshots into `Peer` values. It
keeps an all-ledger pool and a big-ledger pool based on stake concentration.
Relays can be SRV, hostname, IPv4, or IPv6 records. Host relays with no port
default to port `3001`.

`PeerSelector` stores peers by `source/address`, returns deterministic sorted
peer lists, and can select with per-source quotas. `Manager.TopicPeers` returns
the current sorted peer list; node-to-node startup dials that list plus peers
provided directly in `NodeToNodeConfig`.

## Protocol Adapters

`protocol.go` exposes gOuroboros config objects instead of wrapping every
protocol call in a new abstraction.

- `LocalMessageSubmissionConfig` accepts locally submitted signed messages into
  the topic.
- `LocalMessageNotificationConfig` accepts remote notification messages into
  the topic.
- `MessageSubmissionConfig` serves the topic queue through gOuroboros
  message-submission callbacks.

`network.go` uses those same message-submission callbacks for embedded
node-to-node DMQ. A peer connection performs a DMQ node-to-node handshake,
starts the gOuroboros muxer in initiator/responder diffusion mode, and runs a
polling request loop for message IDs.

## Lifecycle

`Manager.Shutdown` marks the manager closed, cancels its context, closes all
registered node-to-node services, and closes all topic runtimes. `TopicNode`
delegates shutdown to its manager.

`NodeToNodeService.Close` cancels the service context, unregisters the service
from the manager, closes the listener, closes peer connections, waits for
goroutines, and returns accumulated listener or close errors.

After a manager is closed, topic lookup returns `ErrManagerClosed`; after a
topic runtime is closed, subscriptions are closed and new submissions fail.

## Extension Guidance

Keep new behavior centered on the existing validation boundary. If a feature
accepts a DMQ message from any source, route it through `submitSigned` unless
there is a specific reason to bypass queue, TTL, duplicate, hook, and optional
auth checks.

Prefer adding configuration to `TopicConfig` when behavior is per topic, and to
`ManagerConfig` only when it is a default or shared dependency for many topics.
For single-topic ergonomic shortcuts, add fields to `TopicNodeConfig` and merge
them into `TopicConfig` before registration.

Keep gOuroboros wire types as the source of truth. Public aliases in `types.go`
exist so callers do not need to import gOuroboros for common DMQ message types,
but protocol semantics should continue to follow gOuroboros.

When adding mutable data to public structs or envelopes, update clone helpers
and tests. The package currently assumes callers cannot mutate queued messages
or key material through previously returned slices.

## Testing

The current tests cover:

- publish/subscribe fanout
- duplicate suppression
- TTL and payload expiry helpers
- signed message submission
- node-to-node round trips
- topic-node convenience behavior
- discovery and ledger peer conversion
- KES signing, external signer parsing, and operational credential helpers

Run focused tests with `go test ./...` during development. Before committing,
run `make test` when possible; it runs `go test -v -race ./...` after
`go mod tidy`.
