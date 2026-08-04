# Civic Resilience Wreath — Go reference implementation

A vetted **wreath** of member organizations (municipalities,
non-profits), each dedicating a small slice of compute to serving the
others' **signed, static "lights-on" page** when a member's own site
goes dark. Pooled, reciprocal failover — mutual aid for uptime.
(Spiritual ancestor: the web-ring.)

- **Why / decisions:** [DESIGN.md](DESIGN.md)
- **Build brief / milestones:** [KICKOFF.md](KICKOFF.md)
- **Wire-format decision log (future RFC raw material):** [WIRE-NOTES.md](WIRE-NOTES.md)

## Components

| Path | What it is |
|---|---|
| `cmd/wreath-agent` | Peer agent daemon: replicate, verify, serve, probe |
| `cmd/wreath-publish` | Publisher CLI: keygen, build, sign, verify, push |
| `cmd/wreath-sim` | Simulated multi-member wreath: demo + protocol test bed |
| `internal/demo` | `wreath-sim demo`: long-running wreath + web dashboard |
| `internal/wire` | **The future RFC**: wire types, RFC 8785 canonicalization, Ed25519 sign/verify |

Trust model in one line: members publish **Ed25519-signed** bundles;
peers replicate and re-serve them but **cannot forge** them — the worst
a bad peer can do is withhold or serve stale, and the health matrix
catches both.

## Quickstart

```sh
go test ./...            # everything, incl. the 7 failure scenarios
go run ./cmd/wreath-sim list
go run ./cmd/wreath-sim run -scenario=origin-down
go run ./cmd/wreath-sim run -scenario=all
go run ./cmd/wreath-sim demo   # live dashboard at http://127.0.0.1:8100
```

`wreath-sim demo` runs the same real agents long-lived at human pace, with
a web dashboard: per-member iframes loaded through a client-walk proxy
(the stand-in for the browser's HTTPS/SVCB-record walk, RFC 9460), the
gossiped health matrix, manual kill/revive/publish controls, and a chaos
mode that swings members dark and back automatically. DNS is the one
simulated component; everything else is the reference implementation.

A scenario run reads like an incident log:

```
=== origin-down — origin dies; client walk lands on a peer; everyone keeps serving
   0.085s  converged: alpha at v1 on [alpha bravo charlie]
   0.100s  killing alpha's origin AND alpha's agent (co-tenant dies with the host)
   0.103s  client walk for alpha/ -> served by agent:bravo
PASS
```

## Status

MVP milestones M1–M5 (see KICKOFF.md) are implemented and tested.
Explicitly out of scope so far: real DNS-provider integration, the
incident banner / out-of-band signer, shed/offload mode, appliance
build, sharding, dashboards. The RFC will be distilled from
`internal/wire` + `WIRE-NOTES.md` once a second implementation is
underway.
