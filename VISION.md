# caller-identity - Vision

**Status: drafted 2026-10-10 under zorg's `D35` and `D37`; not ratified.**\
This document states why caller-identity exists and what it will never be.\
It carries no current state, no roadmap, and no schedule.

Holding this document authorises nothing.\
It does not ratify a decision, admit a component to any registry, or approve a contract change.\
Until the director ratifies it, it is a proposal, and nothing may cite it as enduring.\
A change of direction is recorded as a decision first and absorbed here afterwards.

---

## North star

> Let every operation know which principal is calling it, from the evidence its caller presented and the rules its host chose, and never claim more certainty about that principal than the evidence gives.

Four terms in that sentence carry weight, so this document defines them rather than leaving them to the reader.

**Principal** means the identity a host attributes a request to: an agent, a person, or a service.\
It is the name a writer is recorded under and a policy rules on, not the address or the connection the request arrived by.

**Evidence** means what a caller presents or a transport observes about who is calling: a name the caller asserts, a key it proved it holds, a token a verifier accepted, or the headers of a proxy the host trusts.

**The rules its host chose** means the application decides which evidence it accepts and how accepted evidence becomes a principal, and supplies the verifiers that check it.

**More certainty than the evidence gives** means every principal is marked with how it was established - asserted or proved - and a principal that was only asserted is never presented as proved, by inference or by default.

---

## Why it exists

Every service with remote callers must answer the same question before it can record a writer or rule on a request: who is this?\
The transport knows something about the connection, the application knows what it trusts, and the operation that needs the answer sees neither.

Each application builds the bridge itself.\
It keeps its own table from connections to callers, verifies tokens in its own way, and passes the result to its handlers by whatever means is to hand.\
Each one loses something: a name that was only asserted is treated as proved, a request is attributed to the wrong connection after a reconnection, or one part of the host reads a different caller from another.

caller-identity builds that bridge once, so every operation of a host reads one principal for one request, as certain as its evidence and no more.

---

## What it is

An embeddable library used by the host side of a service.\
When a session is admitted, it records the principal that session's evidence supports, under the host's rules; when a request arrives, it answers the request's operation with one record of who is calling - the principal, the evidence it came from, and whether it was proved.

The application supplies its rules and its verifiers; the transport supplies its evidence.

---

## What it is not

**Not an authority.**\
It says who is calling, never what that caller may do.\
Ruling on a request is the application's policy, which reads the principal caller-identity gives it.

**Not a transport or a security layer.**\
It protects no channel and proves nothing itself; the transport observes, a verifier checks, and caller-identity records what they found.

**Not an identity provider.**\
It creates no accounts, runs no sign-in, and holds no passwords; it accepts the evidence of providers the application trusts.

**Not a store of users.**\
It holds the principals of sessions open now, and of sessions closed only a short while, and nothing that must survive a restart.

**Not a guesser.**\
Where the evidence does not establish a principal, a request has none, and the record says so.

**Not agentic.**\
It identifies callers of agentic systems and contains no cognition, model, or orchestration.

---

## What success means

Four dimensions.\
They are not weighted, and they do not collapse.

**Honesty.**\
No record claims more certainty than its evidence.\
The measure is that no asserted principal is ever presented as proved, and no request is attributed to a session it did not arrive on.

**Agreement.**\
Every part of a host reads the same principal for one request.\
The measure is that the writer a store records, the caller a policy rules on, and the principal a log names never differ for one request.

**Leanness.**\
A host adds little code to identify its callers.\
The measure is the code an application writes beyond its rules and its verifiers, stated and small.

**Reuse.**\
A second, unrelated application adopts it without a variant, a fork, or a privileged path.

A programme strong on three of these and weak on one has one unmet dimension, and which one it is says more than any average of the four.

---

## Authority

Held by the director.\
Drafted by anyone; ratified only by the director.

This statement is amended, never quietly rewritten.\
A ruling that changes direction is recorded as a decision and absorbed here, so the reasoning survives the change.

Where this narrative and a verified record disagree about state, the record governs.
