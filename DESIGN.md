# Civic Resilience Ring — Design & Decision Record

*Status: living design doc. This is the reference context for the Go reference
implementation. It captures decisions made so far; it is not itself the RFC —
the RFC will be **distilled from the working Go implementation** (see §8).*

**One-liner:** A vetted web-ring in which member organizations dedicate a small
slice of compute/storage to serving each other's **signed, static "lights-on"
page** when a member's own site goes dark. Aimed first at municipalities and
non-profits whose fallback content carries no sensitive information. Pooled,
reciprocal failover — mutual aid for uptime.

---

## 0. Positioning (read first)

**This is not primarily a disaster tool.** The dramatic regional-disaster
scenario is the *weakest* fit (see §2); leading a pitch with it is a framing
bug. The honest framing: *"your site goes down for boring reasons more often
than you'd like, and right now all anyone sees is a browser error."* Bad
deploys, expired TLS certs, and upstream cloud/CDN outages are the common cases,
and in all of them the citizen's internet is fine.

The value is **tail-risk insurance + institutional credibility**, not traffic
volume. Payoff = the occasional outage that coincides with genuinely
safety-or-logistics-critical info (boil-water notice, shelter/polling changes,
closures) plus the "we're a functioning government that didn't just vanish"
signal. The saving grace is that the **cost is tiny**, so it's cheap insurance
against a class of events that hits every org eventually.

Strategic note: as an add-on to a data-sovereignty / NextCloud-migration
consultancy, the ring is **migration de-risking** — it directly answers the #1
objection to self-hosting ("Microsoft has a 99.9% SLA and an ops army; if we
self-host and it goes down, it's on us"). An *open* resilience layer is also
coherent with the anti-lock-in sovereignty thesis in a way a proprietary one
would not be.

---

## 1. Scope: the "lights-on" tier

Every failover scheme must solve a **data plane** (does someone else hold a copy
of what to serve?) and a **control plane** (when your box is dark, how does a
visitor's browser reach a peer instead of your corpse?). Scoping to a static
status page collapses both hard problems: no live state, no secrets.

- **Tier A — lights-on fallback (the target).** Signed static page: "we're
  experiencing an outage — status, contact, emergency info." No state, no
  secrets, inherently public. Data plane = replicate a small signed bundle.
- **Tier B — read-only cached content.** Harder (freshness, larger bundles),
  still no secrets. Later.
- **Tier C — full stateful failover.** Live DBs, sessions, secrets. Out of
  scope — where most "distributed hosting" ideas die.

Key property: because the fallback content is *inherently public*, "no sensitive
info need be shared" falls out for free rather than being engineered.

---

## 2. When it's useful (scenario taxonomy)

Organizing principle: **decorrelation.** The ring is valuable to the degree that
whatever killed the site did *not* also kill the citizen's ability to reach it.

| Why the site went dark | Site down? | Citizens reachable? | Fit | Mechanism |
|---|---|---|---|---|
| Botched deploy / expired cert / DNS fat-finger | yes | fully | **Strong** | failover |
| Upstream cloud / CDN / shared-host outage | yes | fully | **Strong** | failover |
| Cyberattack → site pulled for forensics | yes | fully | **Strong** | failover |
| Server-closet-local power / ISP loss (not whole city) | yes | residents fine | **Strong** | failover |
| Hardware / disk-full / OS crash | yes | fully | **Strong** | failover |
| Traffic surge / disaster-driven demand | degraded | yes & trying | **Good, but** | **shed/offload (different!)** |
| Area-wide power outage | yes | wired ✗ / cellular ✓ | **Partial** | failover; access via mobile |
| Catastrophic / prolonged (cell towers down too) | yes | no | **Out of scope** | → IPAWS / radio |

The top five rows — the *common* outages — are fully decorrelated and by count
dominate. **Cellular is the channel that survives** a regional power event (tower
battery/generator backup + phone batteries), so "reachable citizens" ≈ "anyone
with a charged phone and a working tower," not "generator + Starlink households."
This is *why* the bundle must be tiny, static, and JS-light: so it arrives over a
congested cellular link. Where usefulness ends (cell towers depleted, prolonged):
that regime belongs to WEA/IPAWS + NOAA radio; the ring should not pretend to
serve "civilization is down."

---

## 3. Two operating modes

Failover and surge are **not the same mechanism.**

- **Failover mode** — origin *unreachable* (crash, cyberattack, cloud outage,
  cert expiry, local power). Control plane swings to the signed static bundle on
  peers. Binary, clean. **This is the MVP.**
- **Shed / offload mode** — origin *alive but overwhelmed*. A binary swing is
  wrong here (it flaps: origin recovers as load drops → traffic returns →
  re-overloads). Want graceful shedding — the mesh absorbs read-heavy static
  traffic (scales trivially, CDN-style) to shield a small dynamic core. **Later.**

---

## 4. Trust model: sign, don't share secrets

"Share a key with peers" has a hidden failure mode: if the key lets a peer
*serve as you*, a compromised member can impersonate you. Flip it:

- Each member publishes a **signed static bundle**. Peers replicate but
  **cannot forge** it. Worst a bad peer can do is serve *stale* content or
  withhold it — never fabricate.
- The shared key is **membership/authentication** into the ring, *not* "act as
  me."
- Use a **delegated, revocable incident-signing subkey** so field staff can post
  updates without the root key (blast-radius containment).

Analogy: BGP peers don't trust intentions — they use route filtering / RPKI so a
peer can't announce what it shouldn't. Signing is that guardrail for content.

---

## 5. Control plane: DNS / routing

Two failover models. **Model A (client-driven, the MX model):** DNS hands the
client *all* candidate endpoints; the client falls back on its own; no external
brain. **Model B (server-driven):** DNS hands out one answer; a distributed brain
health-checks and changes it. The "external load balancer is itself a SPOF"
worry is a correct critique of *naive* Model B; the fix is to not run the brain
yourself.

How much MX-style ranking DNS actually has:

- **Multiple A records** — real client-side fallback (browsers try another IP,
  Happy Eyeballs) but slow (~8–30s) and *no priority* (resolvers reorder).
- **SRV** — full priority+weight, but browsers ignore it for the web.
- **HTTPS/SVCB records (RFC 9460)** — the real "MX for the web": priority field +
  alternate endpoints; Chrome/Firefox/Safari read them now. Caveat: service-
  binding semantics, not liveness.

Multi-cloud without a single-point LB: **health-checked managed DNS** (brain lives
in the provider's anycast network, not a VM in one cloud; residual SPOF = your DNS
provider → mitigate with secondary DNS across two providers), or **IP anycast /
BGP** (no brain, needs your own ASN — overkill for a county).

**Elegant loop for lights-on:** an `HTTPS`/multi-A record set pointing at origin
*and* two peers serving the signed bundle. If the origin dies, the browser walks
the list to a peer — client-driven, no external brain. The 8–30s delay and
statelessness that make naive multi-A bad for real apps are *free* when the
fallback is just "we're up, here's the info."

**DNS onboarding & cert custody (see also §8):** a one-time **delegation** of a
subdomain — full `NS` delegation of e.g. `status.countyX.gov`, or the lighter
`CNAME` delegation of just `_acme-challenge.status.countyX.gov` (acme-dns
pattern) — lets the ring automate failover records *and* obtain TLS certs via
DNS-01 **without the member ever sharing a private key**. Closest thing to
turn-key DNS; still one manual one-time step (honest asterisk).

---

## 6. Data plane: distribution architecture

**Three components:**

1. **Registry** — the thin "IX of the ring." A small **signed manifest** everyone
   syncs: member list, public keys, bundle endpoints, replication assignments,
   DNS fallback targets. MVP form: a signed JSON file (e.g., in a git repo). It is
   the source of truth for "who backs up whom."
2. **Peer agent** — the daemon on each member's donated slice. **The meat.** Four
   jobs: **replicate** (hold current copies of assigned bundles), **verify**
   (check every bundle against the member's pubkey + monotonic version before
   storing), **serve** (answer on failover), **probe** (liveness; gossip health).
3. **Publisher client** — build, sign, push. Its offline/mobile variant is the
   (deferred) incident-signing tool; it is *not* a separate artifact, just this
   client with an offline mode.

**Distribution = pull-based poll + optional push-notify.** Each agent periodically
polls the registry and each member's canonical bundle endpoint (e.g.
`https://countyX.gov/.well-known/ring/bundle` + detached signature); if the
version incremented and the signature verifies, fetch and cache. Pull is
firewall-friendly (agents reach *out*) and self-healing (an agent that was down
catches up on next poll). The publisher may additionally ping "new version,
re-poll now" for speed; correctness never depends on that notification arriving.

**Peer-to-peer backfill (important):** agents must be able to pull a bundle *from
each other*, not only from the origin — because when a member's origin is down, a
peer that missed the last update must heal from *another peer*, not the dead
origin. Signing makes relay safe (anyone can relay; nobody can forge).

**Topology:** **full-mesh first** (every member holds every other member's bundle;
bundles are kilobytes, so this scales to hundreds of members). Move to `k`-of-`N`
diversity-selected sharding *only* when storage forces it.

**Versioning / anti-rollback:** monotonic version (sequence or timestamp) inside
the signed bundle; an agent never serves an older version over a newer one it has
seen. A staleness tolerance defines "fresh" for liveness (§9).

**Bundle format:** a signed **manifest** (file list + content hashes + monotonic
version + timestamp + metadata) plus the files, delivered content-addressed.
Don't invent a container — a signed tar + manifest is fine. This shape is what
enables safe p2p relay.

---

## 7. Stack & deployment unit

**Peer agent: Go.** Deciding constraints: it runs on *other orgs'* heterogeneous
infra, operated by non-experts, and must be *trusted*. → single static
cross-compiled binary, memory-safe, tiny dependency surface (stdlib `net/http`,
`crypto/ed25519`, `crypto/tls`), goroutines fit the I/O-bound work, boring and
long-lived with a big hiring pool, easy to audit. It's the lingua franca of infra
daemons (Caddy, Traefik, etcd, Prometheus). Embed **certmagic** (Caddy's ACME
library) for automatic Let's Encrypt.

- *Rust* is the honest alternative if you weight max trustworthiness /
  reproducible builds / smallest footprint over dev velocity. Workload isn't
  perf-critical, so Go's simplicity wins for now. Not a hill to die on.
- *Avoid interpreted runtimes (Python/Node) for the agent* — they push dependency
  management onto other orgs' machines, the exact pain we're sparing them. (Fine
  for tooling/dashboards.)

**The real fork is the deployment unit, and the language follows it:**

- **Co-tenant slice** (daemon/container on the org's existing server) → Go wins.
  Caveat: an agent co-located with the origin *dies with the origin* — a
  decorrelation weakness.
- **Dedicated node** (a cheap Pi-class appliance or dedicated VM that *is* the
  agent) → independent failure domain (better resilience) and, if built on
  **Nerves** (embedded Elixir: minimal firmware, A/B partitions + auto-rollback),
  a best-in-class remote-fleet story. Elixir's footprint is no longer an
  objection (Nerves / AtomVM / Burrito). Note: the *separate-failure-domain* win
  is runtime-neutral (Go-on-a-Pi gets it too); what Nerves uniquely adds is
  device-fleet management.

**Decision:** prototype **co-tenant in Go** to prove the protocol; **design the
interfaces so the deployment unit is a swap, not a rewrite** (isolate "how am I
deployed / how do I serve" from core protocol logic). An appliance build (Nerves
or Go-on-Pi) is a later track.

*Where Elixir/Phoenix does earn a place now:* the **coordination plane** —
registry service + operator console + a LiveView **mesh-health dashboard** (the
green/red "who-holds-which-version-and-is-it-fresh" matrix) — which lives on infra
*you* control and dodges the deploy-on-random-infra tax. Optional; Go can do it
too. Note distributed-Erlang clustering is *not* used for the agent mesh: the
mesh is mutually-distrusting orgs across the open internet behind NATs, which is
exactly where distributed Erlang is weakest; the loosely-coupled HTTPS-poll design
routes around needing it.

---

## 8. Conformance-first strategy (via reference implementation)

A conformance spec is what makes a *federation* possible: an org won't run a
vendor's binary on trust, but *will* run a conformant implementation it audited,
built, or bought. Openness here is a requirement of the sovereignty value prop,
not a concession.

**Sequence (decided): code → run → distill.** Build the Go reference
implementation, run it live or simulated to iron out where the protocol is
actually wrong, then **distill the RFC from the working code.** A spec written in
the abstract tends to describe the protocol you *imagined*. The bar for "the spec
is real" is the IETF one: **two independent implementations that interoperate** —
so the later Nerves/second implementation is simultaneously the premium SKU *and*
the conformance test.

**Draw the conformance boundary at the wire; leave internals free.** Standardize
only what two implementations must agree on to interoperate:

- **Registry & bundle formats** — schemas + the signed-manifest structure.
- **Crypto suite** — Ed25519; key/signature encodings; *exactly* what bytes the
  signature covers; delegation/rotation semantics. Highest-stakes section.
- **Distribution protocol** — well-known pull endpoints, poll & freshness
  semantics, p2p relay/backfill, optional push-notify.
- **Health/liveness protocol** — probe/gossip formats; the *numeric* definition
  of "fresh" (staleness tolerance).
- **Serving/failover contract** — content types; the TLS cert-custody naming
  rules (§5).

**Canonicalization footgun (call out hard):** two implementations in two languages
will serialize JSON differently before signing (key order, whitespace, number
formatting) and signatures won't verify cross-implementation → silent federation
break. **Pin a canonical form** (RFC 8785 JSON Canonicalization Scheme) *or* sign
content hashes rather than serialized JSON. Even the single-implementation MVP
should do this now, so the spec is extractable and the second implementation
"just works."

A real conformance **test suite** (not just prose) is what lets a county buy a Pi
and self-certify. Keep wire-format types in a dedicated package and keep notes on
formats as the code evolves, so RFC + test-suite extraction is cheap.

---

## 9. Testing: two planes

- **Data-plane liveness** (continuous, invisible): each agent periodically fetches
  out-of-band (by peer hostname/IP, bypassing normal DNS) each bundle it holds and
  checks **`reachable ∧ valid-signature ∧ version ≥ last-published`** (within a
  staleness tolerance). A stale-but-signed bundle is "up" and useless — the
  freshness check is the one people forget. Gossiped results = the mesh-health
  signal (and the demo dashboard).
- **Control-plane correctness** (would DNS actually swing?): a **permanent
  always-on fallback hostname** (`fallback.countyX.gov`) that resolves straight to
  the peer-served bundle at all times — the honest fire-drill endpoint, same code
  path as a real failover, and the best single demo artifact. Plus announced
  **game-days** (swing the real site in a maintenance window) and a throwaway
  `drill.countyX.gov` with a dummy origin you can kill on a schedule.

*Testing ∪ comms are the same machinery:* post a `[DRILL]` incident record to the
always-on endpoint and watch it propagate — exercising authoring, signing,
replication, and rendering without touching the real site.

---

## 10. Incident banner (deferred — gravy, not meat)

Requirement: a plaintext banner with incident-specific info (nature, ETA,
concerns). **Reject the "JS fetches latest social post" scheme** — it inverts both
reliability (delivers the most critical payload over the least reliable path at
the worst moment) and trust (unsigned, mutable, client-injected text in an
official emergency banner). Reframe: the banner is a **small, separately-signed,
frequently-republished data object**, ideally under the delegated incident subkey.

**The hard part is authoring, not delivery** — during an outage the origin can't
publish, so you need an **out-of-band publish path** (sign + push straight to the
mesh from a laptop/phone). This is deferred; the pre-baked generic page carries
most of the value without it.

Alternatives, ranked: (1) **bake the record into the re-published signed bundle**
(reuse the freshness pipeline; best MVP-adjacent default); (2) separate tiny
signed record fetched same-origin from the peer (progressive enhancement); (3)
signed **DNS TXT** pointer (rides anycast; redundant secondary); (4) social media
as a **static link, never scraped content**; (5) hosted status pages only as a
place staff *type* an update a signer picks up. Schema note: use
`updated_at` + `next_update_by`, **not** a hard ETA countdown (a slipped "restored
by 2pm" is worse than silence).

---

## 11. Governance (from the Tier-1 peering lessons)

Internet peering solved "cooperate with rivals you don't trust" with **objective,
measurable membership criteria + enforced symmetry + credible, revocable
dependence** — and broke where symmetry broke (CDNs/hyperscalers shattered the
traffic-ratio assumption → paid peering).

Transferable rules for the ring:

- **Vet on demonstrated capability** to keep others' lights on (uptime, capacity,
  operational maturity), not goodwill. Objective, hard-to-game criteria.
- **Geographic / infrastructural diversity is a hard requirement** — one rule,
  two payoffs: prevents gaming *and* prevents correlated failure (same grid / ISP
  / cloud region = the ring saves nothing).
- **Symmetric-contribution rule** or someone becomes a net drain. **Design an
  accounting hook from day one** — if some members are heavy *consumers* of
  fallback capacity and others heavy *providers*, pure reciprocity strains just
  like it did for the internet.
- **Enforcement = graceful degradation, not a binary "de-peering" nuke** (which
  hurts innocent users). A bad member's privileges decay smoothly.
- **A thin neutral coordination layer** (the registry, the "IX of the ring") beats
  O(n²) bilateral arrangements. Handshake-level informality + easy exit may beat
  heavy contracts.
- **Credible neutrality of the spec steward:** if one entity both authors the spec
  *and* sells the turnkey box, buyers may fear spec capture → prefer an open,
  RFC-style process. Don't build governance machinery for the MVP; just don't
  design the spec and the vendor to be inseparable.

---

## 12. Prior art & "steal, don't invent"

- **IPFS Cluster** — peers pin/replicate content-addressed data with a replication
  factor; closest data-plane primitive; gives p2p backfill for free at the cost of
  IPFS's conceptual weight. Start with plain signed-HTTPS-pull + relay; keep IPFS
  as the scale-up option.
- **TUF (The Update Framework)** — designed for securely distributing signed
  artifacts over *untrusted mirrors* with delegation, key rotation, and rollback
  protection. This is our distribution problem; its "timestamp role" *is* our
  freshness mechanism. Steal the threat model even if not the full impl.
- **certmagic / ACME (DNS-01)** — automatic TLS; don't hand-roll cert renewal.
- **RFC 8785 (JSON Canonicalization Scheme)** — for deterministic cross-impl
  signing (§8).
- **RFC 9460 (SVCB/HTTPS records)** — the control-plane ranking primitive (§5).
- Emergency-comms channels of record (out of scope, know the boundary): WEA /
  IPAWS, NOAA weather radio.

Whitespace: nobody has packaged "pooled reciprocal failover for low-sensitivity
civic sites" (signed static fallback + health-checked/HTTPS-record failover + a
vetted, diversity-selected ring) turnkey enough for a two-person county IT shop.

---

## 13. Out of scope for the MVP

Dynamic incident banner & out-of-band phone signer (§10); shed/offload mode (§3);
Tier B/C content (§1); Nerves appliance build (§7, design for swap only); live
managed-DNS integration (simulate the control-plane swing — see KICKOFF);
`k`-of-`N` sharding (§6, full-mesh first); multi-provider secondary DNS;
accounting/quota enforcement (§11, leave a hook).

---

## 14. Open questions

- Exact "fresh" staleness tolerance and poll interval defaults.
- Registry governance & key-rotation ceremony (who signs the registry; threshold?).
- Shed/offload mechanics without flapping.
- Graceful-degradation (privilege-decay) design for misbehaving members.
- Whether the coordination plane is Go or Elixir/Phoenix.
- Product naming (both the consultancy and this product are currently unnamed).
