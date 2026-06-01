# dmq-lib

Embeddable Go library for CIP-0137 Distributed Message Queue (DMQ).

`dmq-lib` uses `github.com/blinklabs-io/gouroboros@v0.179.0` as the
DMQ wire/protocol source of truth. It also wraps Dingo topology and
peer-governance types, plus Bursa/Cardano key parsing helpers where they are
useful to callers.

## Install

```sh
go get github.com/blinklabs-io/dmq-lib
```

## What It Provides

- Topic-scoped DMQ queues with duplicate suppression, TTL validation, fanout
  subscriptions, and hooks.
- `TopicNode`, a single-topic convenience wrapper that can register a topic,
  load discovery peers, and start node-to-node networking.
- `Manager`, the lower-level multi-topic API.
- Publishing through caller-provided signers, plus direct submission of already
  signed CIP-0137 messages.
- File-backed, in-process, and external-process KES signing helpers.
- Static, Dingo/Cardano topology, and optional ledger peer discovery.
- gOuroboros local-message-submission, local-message-notification, and
  message-submission adapters.

## TopicNode Quick Start

Use `TopicNode` when the application owns one DMQ topic and wants one object
for publishing, subscribing, discovery, networking, and shutdown.

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

`TopicNode` starts node-to-node networking automatically when network discovery
or `NodeToNode` settings are present. Networked topics must set
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

Use `Manager` directly when one process needs to manage multiple topics or
when the application wants explicit control over topic registration and
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

`Publish` builds a DMQ payload, applies `MaxMessageBodyBytes`,
`DefaultMessageTTL`, and the topic's TTL policy, then signs the payload with
the topic signer or manager signer. `SubmitSigned` accepts a complete CIP-0137
message and routes it through the same queue, duplicate, TTL, hook, and optional
authentication path.

## Signed Messages

Applications can inject their own signer:

```go
type Signer interface {
    Sign(ctx context.Context, topic string, payload dmq.DmqMessagePayload) (*dmq.DmqMessage, error)
}
```

Callers that already have a CIP-0137 signed message can bypass signing:

```go
err := m.SubmitSigned(ctx, "governance", signedMessage)
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

`NewExternalKESSigner` can be used when KES custody lives in a separate helper
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
can be adapted with `DingoLedgerPeerProviderAdapter` as an explicit relay-only
source unless a staked provider is supplied.

## gOuroboros Adapters

For embedded node-to-node DMQ, start a service on a registered topic:

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

The service dials configured topic peers, accepts inbound peers when a listen
address is set, and exchanges messages through the topic queue. `StartNodeToNode`
requires the topic to be registered with `TopicConfig.NetworkMagic`; otherwise
it returns `ErrNetworkMagicRequired`.

`Manager` can also produce gOuroboros protocol configs for an existing topic:

```go
localSubmitCfg, err := m.LocalMessageSubmissionConfig("governance")
localNotifyCfg, err := m.LocalMessageNotificationConfig("governance")
messageSubmitCfg, err := m.MessageSubmissionConfig("governance")
```

The adapters disable gOuroboros' internal TTL/auth prevalidation and route
validation through the manager so topic policy, hooks, duplicate suppression,
and the manager clock stay authoritative.
