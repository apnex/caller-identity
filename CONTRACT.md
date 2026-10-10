---
id: unminted
category: component
title: caller-identity - the principal each request comes from, from its caller's evidence and the host's rules
status: draft
hydrate-when: A service must know which principal each request comes from, to record a writer or rule on a request, and you are about to map connections to callers by hand
sovereignty: internal
supersedes: []
related: [C0, A3]
---

# caller-identity

The contract of record for caller-identity: what a consumer can depend on, admitted to zorg's component set by the director's rulings `D35` and `D37` in zorg's `docs/DECISIONS.md`; its vision awaits the director's ratification, and until then this contract is a draft.\
It also carries the fields of a mission-kit registry entry, and that entry is generated from this file when the component is filed, never written as a second copy.\
The registry id is unminted on purpose; one is minted only when the entry is admitted to the registry.

---

## Duty

Establish the principal each request comes from, from the evidence its caller presented and the host's rules.

---

## Contract

What a consumer can depend on, one capability per row.\
A capability is named for what it offers, not for who offers it, so two components that provide the same capability share its name, and the overlap is visible.\
**Provides** means this component implements the capability; **carries from X** means it passes X's capability through its own interface.\
**Requires** names the capabilities of other components a row depends on, as `component:capability`, so a census can follow an application's demand down through the components it reaches.\
The trait column names any trait a system takes on by using the capability.

| Capability | Relation | Requires | What a consumer can depend on | Trait |
|---|---|---|---|---|
| `session-principal` | provides | `agp:peer-identity-evidence`, `agp:read-only-observation` | For each session the host admits, the principal its evidence supports under the host's rules is recorded with how it was established - asserted or proved - and kept until a stated time after the session closes; a session whose evidence supports none has none. | none |
| `request-evidence` | provides | `agp:delivery-context` | Each request is answered, as it arrives, with one tagged record of who is calling: its origin, the principal recorded for the session it arrived on, and whether that principal was proved; a request whose origin is not that session's peer, or whose session has no principal, has no principal from its session, and an asserted principal is never presented as proved; a principal a request's own evidence establishes is `verified-principal`'s. | none |
| `verified-principal` | provides | none | A credential a caller presents - a token, or the headers of a proxy the host trusts - is checked by verifiers the host supplies, and a credential they accept gives a proved principal with its issuer and expiry; one they refuse gives none. | none |

The component holds the principals of open and recently closed sessions in memory, so none of its capabilities brings a trait.\
It coordinates no actors and contains no model.\
In zorg's Delta 1, `session-principal` and `request-evidence` are built, under AGP's trusted-development security, where every principal is asserted; `verified-principal` is left out of Delta 1, and drawv2's sign-in through a trusted proxy, its connection codes and zorg's web canvas need it.\
Issuing credentials - drawv2's connection codes among them, and the admission keys of zorg's `D38` - is credential-issuer's (zorg's `D39`), never caller-identity's, as the vision excludes; caller-identity verifies them, through a verifier its host supplies.

---

## Identity design

**Maturity: provisional**, designed under zorg's Delta 1, amendment 2, and zorg's rulings `D26`, `D31`, `D35` and `D37`.\
Each declaration names the exit criterion of zorg's `docs/DELTAS/DELTA-1.md` that proves it and the test that exercises it.\
AGP's evidence, admission port and delivery context are those of AGP at `4ae96f1`.

**CI1 - A host's rule.**\
A host gives caller-identity a rule that turns a session's evidence into a principal or into none.\
The component offers one rule, the asserted node rule, for AGP's trusted-development security: it reads only the peer's node name, as AGP's identity-admission request gives it in `remoteNodeId`, ignoring the transport's own evidence; the principal is that name up to its first dot, when there is a dot and that part matches `^[a-z0-9][a-z0-9-]{0,62}$`, and is none otherwise - the naming operation-proxy gives the node of each identity's proxy (`PX1`) - and every principal it gives is asserted, never proved.\
So applied over AGP's production in-process carrier, whose transport evidence reports a verified same-process peer, the rule still gives an asserted principal; the evidence trusted-development WebSocket security actually reports, with no authentication and no protection, is observed by zorg's `E5`, in `packages/zorg-hub/test/evidence.test.js` over AGP's WebSocket transport, as zorg's `EM13` says.\
Tested by: `E18`, in `test/contract/session-principal.test.js`, for a name with a dot, one without, one whose first part breaks the pattern, and one with several dots.

**CI2 - Admitting a session, and forgetting it.**\
The component offers an implementation of AGP's identity-admission port, which admits every peer unless the host gives it an admission ruling of its own, and records for each session it admits, keyed by the peer's node and the host node's own session identifier for it, the principal the host's rule gives and whether it was proved; a record for a key already held replaces the earlier one.\
It forgets records by sweeping, not by events, which AGP may drop.\
Time is read from a clock port the host gives it, in milliseconds that a change to the wall clock does not move, by default `performance.now()`; the host starts the sweeping when it starts its node, and stops it when it stops the node.\
Every 30 seconds by that clock it reads AGP's connection snapshot (`operations.connections()`), in which a session is present when an admitted connection has the record's peer as `remoteNodeId` and its session identifier as `sessionId`, or when a pending connection - one AGP has not yet committed, whose entry carries only the host's own session identifier - has it as `localSessionId`, because AGP asks the admission port before it commits the session.\
Each record keeps the time its session was last found present, starting at the moment it was admitted; the first sweep after that time that finds the session absent notes when absence was first seen; a later sweep that finds it present clears that; and the first sweep at which at least 60 seconds have passed since absence was first seen forgets the record.\
A session closes after it was last found present and no later than absence was first seen, so its record is found by every request arriving less than 60 seconds after it closed, and is forgotten by the first sweep at least 60 seconds after absence was first seen, which falls within 90 seconds of its close.\
Two things keep a record longer, and nothing keeps it shorter: sweeps that run late, by as much as they are late; and another connection, pending with the same session identifier, which AGP's opening time-out ends - a pending entry names no peer, so a record cannot tell its own pending session from another's, and is kept rather than lost.\
A record admitted for a session refused, or closed, before it was established is forgotten the same way, from the moment it was admitted.\
A key admitted again replaces its record, with the time of its new admission and no absence noted.\
Tested by: `E18`, in `test/contract/session-principal.test.js`, against AGP's production in-process carrier with an injected clock port and sweeps: an admitted session's record; a session closed 1 millisecond after a sweep, whose record is found 59 seconds after the close, and is gone after the sweep 90 seconds after the last sweep that found it; a session closed at the instant of a sweep; a session admitted while pending at a sweep and established and closed between that sweep and the next, whose record is still found 59 seconds after its close; a sweep run 10 seconds late; another peer's pending connection with the same session identifier, which keeps the record until it ends; a session refused after admission before it was established; a reconnection under a new session with a record of its own; one session number used by two nodes, each with its own record; and a key admitted again, whose new record replaces the old and its noted absence.

**CI3 - The evidence of a request.**\
Given a request's delivery context - its origin node, and its ingress node and session when it arrived over a session - the component answers with one record, exactly `{"kind": "agp-session", "node": <the origin node>, "principal": <a principal or null>, "proved": <true or false>}`.\
`node` is always the origin node; the ingress node and session only find the record.\
`principal` is the recorded one, and `proved` its recorded certainty, when the origin node is the ingress node and a record exists for that ingress node and session; otherwise `principal` is `null` and `proved` is `false`.\
A host asks as it receives the request, before anything else is done with it.\
Tested by: `E18`, in `test/contract/request-evidence.test.js`, with the injected clock port and sweeps of `CI2`, asserting the whole record for a well-formed node, a node whose name gives no principal, an origin that is not the ingress node, a delivery with no ingress, a request 59 seconds after its session closed, one just before the sweep that forgets its record and one just after, a request of a session established and closed between two sweeps, 59 seconds after its close, a delivery context naming, as its ingress, a session refused after admission before it was established, while that session's record is kept and after it is forgotten, a reconnection, and one session number on two nodes.

**CI4 - Certainty is never inferred.**\
A record's `proved` is `true` only for a principal the transport's own proof established - AGP's evidence of a verified peer - or a verifier the host supplied established (`verified-principal`, outside Delta 1); no rule, default or later step turns an asserted principal into a proved one, and a record's `kind` says what produced it, so a later kind of evidence is a new variant of the record rather than a change to this one.\
Tested by: `E18`, in `test/contract/request-evidence.test.js`, which checks that every record produced under trusted-development security has `proved` `false`.

**CI5 - What zorg composes.**\
The hub of zorg gives caller-identity the asserted node rule, supplies its admission port to the hub's AGP node, and gives operation-call's host half its answer for each request as that request's evidence; zorg's own use of the record - the writer it names and the policy it applies - is zorg's `EM13`.\
Tested by: `E5`, in zorg's `packages/zorg-hub/test/evidence.test.js` and `test/e2e/refusals-and-writers.test.js`.

---

## Reference

Not yet built.\
This repository, `apnex/caller-identity`, private until its first working code: `VISION.md` and, once built, the implementation.

---

## Fit criteria

### Does my project want this at all

- A service has remote callers, and records who wrote something or rules on what a caller may do.
- Evidence of who is calling arrives with a connection or with a request, and the operations that need it see only requests.
- Some callers are only asserted and some are proved, and the difference must not be lost.

### Does it meet my requirement

- Every part of the host reads one principal for one request.
- An asserted principal is never presented as proved.
- The host chooses its rules and its verifiers; no provider is built in.

**It is the wrong tool when**

| You need | Reach elsewhere, because caller-identity is |
|---|---|
| a decision about what a caller may do | not an authority; that is the application's policy |
| a protected channel or a proof of a key | not a transport; the transport observes and reports |
| accounts, sign-in pages or passwords | not an identity provider |
| a store of users or their profiles | not a store of users |

---

## Adjustment policy

Internal and sovereign, so a fit gap has somewhere to go.

1. Record a measured gap where both sides can see it.
2. Resolve it by adjusting caller-identity, so every consumer gets the change, or by fracturing it when the gap reveals a second duty.
3. Never fork.

Evidence reaches it through the transport's own reports and verifiers the host supplies, so a new transport profile or a new kind of credential is a verifier rather than a change to caller-identity.

---

## Edges

**Composes:** nothing registered.

**Consumes, through a declared contract:**

- `agp`: `peer-identity-evidence`, `delivery-context`, `read-only-observation`

**Composed-by:** nothing yet.\
Its first consumer, once built, is zorg's hub, which supplies AGP's admission check through it and gives operation-call's host half the evidence of each request.

The registry's edge vocabulary has no edge for one component using another's contract without containing it; see the note in operation-call's entry.
