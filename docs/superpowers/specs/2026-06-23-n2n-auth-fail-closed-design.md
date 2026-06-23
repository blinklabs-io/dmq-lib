# Fail-Closed Node-to-Node Authentication — Design

Date: 2026-06-23
Status: Approved
Branch: `worktree-n2n-auth-fail-closed`

## Problem

`Manager.StartNodeToNode` accepts and relays messages from remote peers after
only deterministic message-id and TTL checks unless `Authentication.Required`
is set on the topic. Since commit ba9e871 (#18) the library *warns* when N2N
starts without authentication, but it still proceeds. An operator can therefore
expose a node to untrusted peers, unauthenticated, by simply not setting a
field. The safe path is not the default path.

## Goal

Make unauthenticated node-to-node networking a deliberate, explicit choice:
fail closed when authentication is neither required nor explicitly waived.

Non-goal: changing what the default KES verifier checks. It verifies the KES
signature and operational certificate but not active-SPO-pool membership (that
needs caller-supplied ledger state). That limitation is unchanged here and
remains documented.

## Decision

Fail-closed with an explicit opt-out (chosen over auto-enabling auth or keeping
the warn-only behavior).

- `Authentication.Required == true` → run authenticated. The KES verifier is
  already auto-provisioned in `newTopicRuntime` when no
  authenticator is supplied; unchanged.
- `Authentication.Required == false && Authentication.AllowUnauthenticated == true`
  → run unauthenticated, logging the existing warning.
- `Authentication.Required == false && Authentication.AllowUnauthenticated == false`
  → return `ErrAuthenticationRequired`; the service does not start.

## Public API changes

- `AuthenticationConfig.AllowUnauthenticated bool` (types.go) — new field, placed
  next to `Required` so all auth knobs live in one struct. Documented as: opt in
  to running node-to-node networking without message verification. Ignored when
  `Required` is true.
- `ErrAuthenticationRequired` (errors.go) — new sentinel:
  `"dmq node-to-node requires message authentication; set Authentication.Required or Authentication.AllowUnauthenticated"`.

## Behavior change (the gate)

In `Manager.StartNodeToNode` (network.go), replace the warn-only block:

```go
if !rt.cfg.Authentication.Required {
    if !rt.cfg.Authentication.AllowUnauthenticated {
        return nil, ErrAuthenticationRequired
    }
    rt.logger.Warn(/* existing unauthenticated warning */)
}
```

The gate is the only behavior change. `submitSigned` and the local-publish path
are untouched. The gate fires identically whether a listener is
configured — relaying an unauthenticated peer's messages is the risk in both
the inbound and outbound-only cases.

## Edge cases

- `Required && AllowUnauthenticated` both true → `Required` wins (auth runs);
  the opt-out is ignored. Documented, not an error.
- `TopicNode` inherits the flag for free through
  `TopicConfig.Authentication`; no `TopicNodeConfig` change is needed.

## Backward compatibility

Breaking change for callers that relied on warn-and-proceed. Acceptable at
v0.x. Callers must now set either `Authentication.Required` or
`Authentication.AllowUnauthenticated`.

## Testing

TDD. New and updated tests in `manager_test.go`:

1. New: `TestStartNodeToNodeFailsWhenUnauthenticatedNotAllowed` — register a
   topic with neither flag set; assert `StartNodeToNode` returns
   `ErrAuthenticationRequired` and starts no service.
2. Update: `TestStartNodeToNodeWarnsWhenAuthenticationNotRequired` —
   register with `AllowUnauthenticated: true`; assert it still warns and starts.
3. Keep: `TestStartNodeToNodeNoWarnWhenAuthenticationRequired` —
   `Required: true`; unaffected.
4. Update: the N2N round-trip test (`TestNodeToNodeServiceRoundTrip`) — add
   `AllowUnauthenticated: true` to both topics so the round trip still runs.
5. Check `topic_node_test.go` for any no-auth N2N start and fix likewise.

## Docs

- README "Node-to-Node DMQ": show the auth/opt-out choice; note the breaking
  change.
- `doc.go` examples: same.

## Implementation order

1. Add `ErrAuthenticationRequired` (errors.go).
2. Add `AuthenticationConfig.AllowUnauthenticated` field + doc (types.go).
3. Write/adjust failing tests (1–5 above).
4. Implement the gate (network.go).
5. Update README + doc.go.
6. Verify: `go test ./...`, `go vet ./...`, `golangci-lint`, `gofmt`.
