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
| `session-principal` | provides | `agp:peer-identity-evidence` | For each session the host admits, the principal its evidence supports under the host's rules is recorded with how it was established - asserted or proved - and kept until a stated time after the session closes; a session whose evidence supports none has none. | none |
| `request-evidence` | provides | `agp:delivery-context` | Each request is answered, as it arrives, with one tagged record of who is calling: its origin, the principal recorded for the session it arrived on, and whether that principal was proved; a request whose origin is not that session's peer, or whose session has no principal, has no principal, and an asserted principal is never presented as proved. | none |
| `verified-principal` | provides | none | A credential a caller presents - a token, or the headers of a proxy the host trusts - is checked by verifiers the host supplies, and a credential they accept gives a proved principal with its issuer and expiry; one they refuse gives none. | none |
| `machine-credential` | provides | none | Credentials for callers that are programs are issued and revoked under the host's policy, each bound to the principal it names, shown once and stored only as a check value. | T1 |

The component holds the principals of open and recently closed sessions in memory, so `session-principal` and `request-evidence` bring no trait; `machine-credential` keeps its records durably, so a system using it is stateful (`T1`).\
It coordinates no actors and contains no model.\
In zorg's Delta 1, `session-principal` and `request-evidence` are built, under AGP's trusted-development security, where every principal is asserted; `verified-principal` and `machine-credential` are rows left out of Delta 1, which drawv2's sign-in through a trusted proxy and its connection codes, and zorg's web canvas, need.

---

## Identity design

**Maturity: provisional**, designed under zorg's Delta 1, amendment 2, and zorg's rulings `D26`, `D31`, `D35` and `D37`.\
Each declaration names the exit criterion of zorg's `docs/DELTAS/DELTA-1.md` that proves it and the test that exercises it.\
AGP's evidence, admission port and delivery context are those of AGP at `4ae96f1`.

**CI1 - A host's rule.**\
A host gives caller-identity a rule that turns a session's evidence into a principal or into none.\
For AGP's trusted-development security, where the evidence is the name the peer's node asserts, caller-identity offers one rule, the asserted node rule: the principal is the node's name up to its first dot, when there is a dot and that part matches `^[a-z0-9][a-z0-9-]{0,62}$`, and is none otherwise - the naming operation-proxy gives the node of each identity's proxy (`PX1`); every principal it gives is asserted, never proved.\
Tested by: `E18`, in `test/contract/session-principal.test.js`, for a name with a dot, one without, one whose first part breaks the pattern, and one with several dots.

**CI2 - Admitting a session.**\
The component offers an implementation of AGP's identity-admission port, which admits every peer unless the host gives it an admission ruling of its own, and records for each session it admits, keyed by the peer's node and the host node's own session identifier for it, the principal the host's rule gives and whether it was proved.\
It learns that a session has closed from AGP's operational events, and forgets that session's record 60 seconds later, so a request dispatched just before the close still finds it.\
Tested by: `E18`, in `test/contract/session-principal.test.js`, against AGP's production in-process carrier: an admitted session's record, a record still found 59 seconds after its session closed and gone at 61, a reconnection under a new session with a record of its own, and one session number used by two nodes, each with its own record.

**CI3 - The evidence of a request.**\
Given a request's delivery context - its origin node, and its ingress node and session when it arrived over a session - the component answers with one record, exactly `{"kind": "agp-session", "node": <the origin node>, "principal": <a principal or null>, "proved": <true or false>}`.\
`node` is always the origin node; the ingress node and session only find the record.\
`principal` is the recorded one, and `proved` its recorded certainty, when the origin node is the ingress node and a record exists for that ingress node and session; otherwise `principal` is `null` and `proved` is `false`.\
A host asks as it receives the request, before anything else is done with it.\
Tested by: `E18`, in `test/contract/request-evidence.test.js`, asserting the whole record for a well-formed node, a node whose name gives no principal, an origin that is not the ingress node, a delivery with no ingress, a request after its session's record was forgotten, and a reconnection.

**CI4 - Certainty is never inferred.**\
A record's `proved` is `true` only for a principal a verifier established (`verified-principal`, outside Delta 1); no rule, default or later step turns an asserted principal into a proved one, and a record's `kind` says what produced it, so a later kind of evidence is a new variant of the record rather than a change to this one.\
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
- Evidence of who is calling arrives with a connection, and the operations that need it see only requests.
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

- `agp`: `peer-identity-evidence`, `delivery-context`

**Composed-by:** nothing yet.\
Its first consumer, once built, is zorg's hub, which supplies AGP's admission check through it and gives operation-call's host half the evidence of each request.

The registry's edge vocabulary has no edge for one component using another's contract without containing it; see the note in operation-call's entry.
