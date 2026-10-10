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
