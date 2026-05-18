# dmq-lib

Embeddable Go library for CIP-0137 Distributed Message Queue (DMQ).

This package uses `github.com/blinklabs-io/gouroboros@v0.171.0` as the DMQ wire/message source of truth, with Dingo topology/peer-governance types and Bursa key parsing where useful.

## Status

This is the first embeddable library cut. It provides direct Go APIs for topic registration, publish/subscribe, signed message submission, duplicate suppression, TTL validation, topology peers, ledger-peer snapshot adapters, and file-backed SPO signing.

Local CIP-0137 socket listeners are intentionally not part of this API. Callers that need gOuroboros protocol wiring can use the config adapter methods on `Manager`.

## Basic Use

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
defer sub.Close()

msg, err := m.Publish(ctx, "governance", []byte("hello"))
if err != nil {
    return err
}
_ = msg

for received := range sub.C {
    _ = received.Body
}
```

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

For file-backed SPO signing, use `NewFileSigner` with cardano-cli-compatible KES signing key and operational certificate files.

## Discovery

Static peers and Dingo topology files are supported directly:

```go
topology, err := dmq.ParseTopologyFile("topology.json")
if err != nil {
    return err
}

err = m.RegisterTopic("governance", dmq.TopicConfig{
    Discovery: dmq.DiscoveryConfig{
        Topology: topology,
        StaticPeers: []dmq.Peer{
            {Host: "relay.example", Port: 3001, Source: dmq.PeerSourceStatic},
        },
    },
})
if err != nil {
    return err
}
```

Ledger peer discovery is opt-in through `LedgerPeerDiscoveryConfig.Provider`. `BuildLedgerPeerPools` normalizes SRV, hostname, and IP relay records and creates all-ledger plus big-ledger pools. gOuroboros LocalStateQuery clients can be adapted with `LocalStateQueryLedgerPeerSnapshotProvider`; Dingo `peergov.LedgerPeerProvider` can be adapted with `DingoLedgerPeerProviderAdapter` only as an explicit relay-only source unless a staked provider is supplied.

## gOuroboros Adapters

`Manager` can produce gOuroboros protocol configs for an existing topic:

```go
localSubmitCfg, err := m.LocalMessageSubmissionConfig("governance")
localNotifyCfg, err := m.LocalMessageNotificationConfig("governance")
messageSubmitCfg, err := m.MessageSubmissionConfig("governance")
```

The adapters disable gOuroboros' internal TTL/auth prevalidation and route validation through the manager so topic policy, hooks, duplicate suppression, and the manager clock stay authoritative.
