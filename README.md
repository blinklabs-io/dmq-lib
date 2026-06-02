# dmq-lib

Embeddable Go library for CIP-0137 Distributed Message Queue (DMQ).

`dmq-lib` is a library, not a daemon. It gives Go applications topic-scoped
DMQ queues, local subscriptions, signed message publishing, peer discovery, and
gOuroboros protocol adapters that can be embedded into a Cardano-aware process.

The DMQ wire types come from
`github.com/blinklabs-io/gouroboros/protocol/common`, which keeps this package
aligned with the gOuroboros implementation of CIP-0137. The package also wraps
Dingo topology and peer-governance types, plus Bursa/Cardano key parsing helpers
where those are useful to callers.

## Requirements

- Go 1.26 or newer.
- A caller-provided `Signer` for local publishing.
- `TopicConfig.NetworkMagic` when node-to-node networking is enabled.
- KES signing key and operational certificate material when using the built-in
  SPO KES signing helpers.

## Install

```sh
go get github.com/blinklabs-io/dmq-lib
```

## What It Provides

- Topic-scoped queues with duplicate suppression, TTL validation, bounded body
  size validation, fanout subscriptions, and lifecycle hooks.
- `TopicNode`, a single-topic convenience wrapper for applications that want one
  object for publishing, subscribing, discovery, networking, and shutdown.
- `Manager`, the lower-level multi-topic API for processes that need explicit
  control over topic registration and node-to-node services.
- Publishing through caller-provided signers, plus direct submission of already
  signed CIP-0137 messages.
- File-backed, in-process, and external-process KES signing helpers.
- Static, Dingo/Cardano topology, and optional ledger peer discovery.
- gOuroboros local-message-submission, local-message-notification, and
  message-submission adapters.

## Choosing an API

| Use case | Entry point |
| --- | --- |
| One process owns one DMQ topic | `TopicNode` |
| One process owns multiple topics | `Manager` |
| Caller already has a signed CIP-0137 message | `SubmitSigned` |
| Caller needs embedded node-to-node DMQ | `StartNodeToNode` or `TopicNode` with networking config |
| Caller needs gOuroboros configs only | `LocalMessageSubmissionConfig`, `LocalMessageNotificationConfig`, `MessageSubmissionConfig` |

## TopicNode Quick Start

Use `TopicNode` when the application owns one DMQ topic and wants the library to
register the topic and manage shutdown as one unit.

```go
ctx := context.Background()

node, err := dmq.NewTopicNode(ctx, dmq.TopicNodeConfig{
    Topic: "governance",
    ManagerConfig: dmq.ManagerConfig{
        Signer: signer,
    },
})
if err != nil {
    return err
}
defer func() { _ = node.Close() }()

sub, err := node.Subscribe()
if err != nil {
    return err
}
defer func() { _ = sub.Close() }()

msg, err := node.Publish(ctx, []byte("hello"))
if err != nil {
    return err
}
_ = msg.ID()

for received := range sub.C {
    _ = received.Body
}
```

`TopicNode` starts node-to-node networking automatically when discovery peers or
`NodeToNode` settings are present. Networked topics must set
`TopicConfig.NetworkMagic`.

```go
node, err := dmq.NewTopicNode(ctx, dmq.TopicNodeConfig{
    Topic: "governance",
    ManagerConfig: dmq.ManagerConfig{
        Signer: signer,
    },
    TopicConfig: dmq.TopicConfig{
        NetworkMagic: 764824073,
    },
    TopologyFile: "topology.json",
    StaticPeers: []dmq.Peer{
        {Address: "relay.example:3001"},
    },
    NodeToNode: dmq.NodeToNodeConfig{
        ListenAddress: "127.0.0.1:3001",
    },
})
if err != nil {
    return err
}
defer func() { _ = node.Close() }()
```

## Manager API

Use `Manager` directly when one process manages multiple topics or when the
application wants explicit control over topic registration, queue policy, and
node-to-node services.

```go
m := dmq.NewManager(dmq.ManagerConfig{
    Signer: signer,
})

err := m.RegisterTopic("governance", dmq.TopicConfig{
    Queue: dmq.QueueConfig{
        MaxMessages: 1000,
    },
})
if err != nil {
    return err
}

sub, err := m.Subscribe("governance")
if err != nil {
    return err
}
defer func() { _ = sub.Close() }()

msg, err := m.Publish(ctx, "governance", []byte("hello"))
if err != nil {
    return err
}
_ = msg
```

`Publish` builds a DMQ payload, applies body-size and TTL policy, signs the
payload with the topic signer or manager signer, then submits the signed message
through the same validation and queue path used by remote messages.

`SubmitSigned` accepts a complete CIP-0137 message and routes it through queue,
duplicate, TTL, hook, and optional authentication checks without signing it
again.

```go
err := m.SubmitSigned(ctx, "governance", signedMessage)
```

## Signing

Applications can inject their own signer:

```go
type Signer interface {
    Sign(ctx context.Context, topic string, payload dmq.DmqMessagePayload) (*dmq.DmqMessage, error)
}
```

For SPO KES signing, derive network timing and wrap a KES provider as a DMQ
signer:

```go
params, err := dmq.NetworkParamsFromShelleyGenesis("shelley-genesis.json")
if err != nil {
    return err
}

provider, err := dmq.NewKESSigner("kes.skey", "opcert.cert", params)
if err != nil {
    return err
}

signer := dmq.NewKESSigningProviderSigner(provider)
```

`NewExternalKESSigner` is available when KES custody lives in a separate helper
process. `NewOperationalCredentialStatus` reports the current KES period,
remaining evolutions, and expiration time for operational credentials.

## Discovery

Static peers and Dingo/Cardano-style topology files are supported without
callers importing Dingo topology types:

```go
discovery, err := dmq.NewDiscoveryConfig("topology.json", []dmq.Peer{
    {Address: "relay.example:3001", Source: dmq.PeerSourceStatic},
})
if err != nil {
    return err
}

err = m.RegisterTopic("governance", dmq.TopicConfig{
    Discovery: discovery,
})
if err != nil {
    return err
}
```

Ledger peer discovery is opt-in through
`LedgerPeerDiscoveryConfig.Provider`. `BuildLedgerPeerPools` normalizes SRV,
hostname, IPv4, and IPv6 relay records and creates all-ledger plus big-ledger
pools. gOuroboros LocalStateQuery clients can be adapted with
`LocalStateQueryLedgerPeerSnapshotProvider`; Dingo `peergov.LedgerPeerProvider`
can be adapted with `DingoLedgerPeerProviderAdapter`.

## Node-to-Node DMQ

For embedded node-to-node DMQ, register a topic with a network magic and start a
service:

```go
err := m.RegisterTopic("governance", dmq.TopicConfig{
    NetworkMagic: 764824073,
})
if err != nil {
    return err
}

svc, err := m.StartNodeToNode(ctx, "governance", dmq.NodeToNodeConfig{
    ListenAddress: "127.0.0.1:3001",
    Peers: []dmq.Peer{
        {Address: "relay.example:3001"},
    },
})
if err != nil {
    return err
}
defer func() { _ = svc.Close() }()
```

The service dials configured peers, accepts inbound peers when `ListenAddress`
is set, and exchanges message IDs and messages through the gOuroboros
message-submission protocol.

## Development

Useful commands:

```sh
go test ./...
make test
make format
go mod tidy
```

`make test` runs `go test -v -race ./...` after `go mod tidy`.

For implementation details, ownership rules, and change guidance, see
[ARCHITECTURE.md](ARCHITECTURE.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
