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

The contract of record for caller-identity: what a consumer can depend on, admitted to zorg's component set by the director's rulings `D35` and `D37` in zorg's `docs/DECISIONS.md`; its vision is ratified (zorg's `D43`), and this contract is a draft until its capabilities are built and verified.\
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
| `session-principal` | provides | `agp:peer-identity-evidence`, `agp:read-only-observation`, `shape-check:plain-json-value` | For each session the host admits, the principal its evidence supports under the host's rules is recorded with how it was established - asserted or proved - and kept until a stated time after the session closes; a session whose evidence supports none has none. | none |
| `request-evidence` | provides | `agp:delivery-context` | Each request is answered, as it arrives, with one tagged record of who is calling: its origin, the principal recorded for the session it arrived on, and whether that principal was proved; a request whose origin is not that session's peer, or whose session has no principal, has no principal from its session, and an asserted principal is never presented as proved; a principal a request's own evidence establishes is `verified-principal`'s. | none |
| `verified-principal` | provides | `shape-check:plain-json-value` | A credential a caller presents - a token, or the headers of a proxy the host trusts - is checked by verifiers the host supplies, and a credential they accept gives a proved principal with its issuer and expiry; one they refuse gives none. | none |

The component holds the principals of open and recently closed sessions in memory, so none of its capabilities brings a trait.\
It coordinates no actors and contains no model.\
In zorg's Delta 1, `session-principal` and `request-evidence` are built, under AGP's trusted-development security, where every principal is asserted; `verified-principal` is left out of Delta 1, and drawv2's sign-in through a trusted proxy, its connection codes and zorg's web canvas need it.\
Issuing credentials - drawv2's connection codes among them, and the admission keys of zorg's `D38` - is credential-issuer's (zorg's `D39`), never caller-identity's, as the vision excludes; caller-identity verifies them, through a verifier its host supplies.

---

## Identity design

**Maturity: provisional**, designed under zorg's Delta 1, amendment 2, and zorg's rulings `D26`, `D31`, `D35` and `D37`.\
Each declaration names the exit criterion of zorg's `docs/DELTAS/DELTA-1.md` that proves it and the test that exercises it.\
AGP's evidence, admission port and delivery context are those of AGP at `baa2c1a` (zorg's `D42`).

**CI1 - A host's rule.**\
A host gives caller-identity a rule that turns a session's evidence into a principal or into none: a port whose `apply`, given AGP's identity-admission request, returns at once `{principal, proved}` or `null`, read as plain data through `shape-check`'s `readPlainJson` and `observePromises` (zorg's `D54`, `D55`) - `null`, or a plain object holding only `principal`, a string, and `proved`, a boolean, as own enumerable data properties, running no getter, no inherited field, no non-enumerable property, no symbol and no `then`; a rule that throws, or returns anything else, a promise or a non-native thenable included, refuses the session, nothing is recorded, and any native `Promise` met within the reader's bound on what it returned or threw is given a do-nothing handler so no rejection escapes to the host's runtime.\
The component offers one rule, the asserted node rule, for AGP's trusted-development security: it reads only the peer's node name, as AGP's identity-admission request gives it in `remoteNodeId`, ignoring the transport's own evidence; the principal is that name up to its first dot, when there is a dot and that part matches `^[a-z0-9][a-z0-9-]{0,62}$`, and is none otherwise - the naming operation-proxy gives the node of each identity's proxy (`PX1`) - and every principal it gives is asserted, never proved.\
So applied over AGP's production in-process carrier, whose transport evidence reports a verified same-process peer, the rule still gives an asserted principal; the evidence trusted-development WebSocket security actually reports, with no authentication and no protection, is observed by zorg's `E5`, in `packages/zorg-hub/test/evidence.test.js` over AGP's WebSocket transport, as zorg's `EM13` says.\
Tested by: `E18`, in `test/contract/session-principal.test.js`, for a name with a dot, one without, one whose first part breaks the pattern, and one with several dots; and, against AGP's production in-process carrier, a rule that throws, one that returns a malformed result and one that returns a promise, each session observed refused by AGP and nothing recorded, and a promise that rejects at once and one that rejects later, each refused with no rejection escaping and the host serving on.

**CI2 - Admitting a session, and forgetting it.**\
The component offers an implementation of AGP's identity-admission port, which admits every peer unless the host gives it an admission ruling of its own, answers every admission within an admission deadline the host gives - by default 10 seconds, AGP's default opening time-out, and the host gives the same value as its node's - taking a ruling that has not answered by then - judged by when its answer comes on the clock port, not by which callback runs first, so an answer at or after the deadline is the denial too - as a denial with AGP's code `POLICY`, so AGP is never left awaiting it - the component's own protection, kept whether or not AGP corrects its own obligation to release a connection whose admission expired, which AGP has accepted as its defect `B53` - and records for each session it admits, keyed by the peer's node and the host node's own session identifier for it, the principal established for that session (in legacy or `"unauthenticated"` mode, the principal the host's rule gives and whether it was proved under `CI4`; in `"authenticated"` mode, the principal and `proved: true` established by `redeemedVerifier`, `CI6`, bypassing `rule.apply` and `CI4`'s transport-proof restriction); a record for a key already held replaces the earlier one.\
What the host's admission ruling returns, after any declared native `Promise` completion (a non-native thenable is not awaited), and what `operations.connections()` returns at a sweep are read as plain data through `shape-check`'s `readPlainJson` and `observePromises` (zorg's `D54`, `D55`): an admission ruling's answer is `{decision: "allow"}` or `{decision: "deny", reasonCode}` with `reasonCode` one of AGP's `IdentityDenialCode` values (`"POLICY"`, `"EXPECTED_NODE_MISMATCH"`, `"SECURITY_EVIDENCE"` or `"CAPACITY"`) as own enumerable data properties only, anything else or a throw or rejection refusing the admission (or denied with `POLICY` at or after the deadline) with any native promises met observed; and a connection snapshot is `{items}`, a plain array of plain objects whose `identityState` is `"admitted"` (with string `remoteNodeId` and `sessionId`) or `"pending"` (with string `localSessionId`), anything else or a throw being a snapshot that cannot be read, reported to the diagnostic port with any native promises met observed and changing no record.\
It forgets records by sweeping, not by events, which AGP may drop.\
Time is read from a clock port the host gives it, offering `now`, in milliseconds that a change to the wall clock does not move, and `schedule`, which runs a callback after a delay and can be cancelled; by default `performance.now()` and the runtime's timers.\
The host starts the sweeping when it starts its node, giving it the node's operations, and stops it when it stops the node; starting it while it runs is an error, stopping it twice is not, and records stay readable after it stops.\
Every 30 seconds by that clock - the first 30 seconds after it starts, and each one 30 seconds after the last actually ran - it reads AGP's connection snapshot (`operations.connections()`), in which a session is present when an admitted connection has the record's peer as `remoteNodeId` and its session identifier as `sessionId`, or when a pending connection - one AGP has not yet committed, whose entry carries only the host's own session identifier - has it as `localSessionId`, because AGP asks the admission port before it commits the session.\
Each record keeps the time its session was last found present, starting at the moment it was admitted; the first sweep after that time that finds the session absent notes when absence was first seen; and the first sweep at which at least 60 seconds have passed since then forgets the record.\
Once absence is noted, no later sweep clears it: a session AGP has dropped from its snapshot has closed and never returns, so an entry that matches the record afterwards - another peer's pending connection with the same session identifier, or a new session of the same peer that reuses it - is not its session; a new session is admitted afresh and replaces the record (below).\
A session closes after it was last found present and no later than absence was first seen, so its record is found by every request arriving less than 60 seconds after it closed, and is forgotten by the first sweep at least 60 seconds after absence was first seen, which falls within 90 seconds of its close.\
Three things keep a record longer, and nothing keeps it shorter: sweeps that run late, by as much as they are late; sweeps whose snapshot cannot be read, which change no record, for as long as the snapshot cannot be read, each failure reported to a diagnostic port the host may give; and another connection, pending with the same session identifier, which ends at AGP's opening time-out if it never sends its opening, or within the admission deadline if it awaits this port's answer - a pending entry names no peer, so a record cannot tell its own pending session from another's, and is kept rather than lost.\
So the bound of 60 to 90 seconds after a close holds while sweeps run on time and snapshots can be read; a late sweep lengthens it by as long as it is late; a snapshot that cannot be read lengthens it by every sweep at which it fails - at least one sweep interval however brief the failure, since absence is noted, and a record forgotten, only at a sweep that reads the snapshot - and another connection pending with the same session identifier lengthens it only when it is pending at the sweeps right after the close, before absence is noted, by its own duration rounded up to the next sweep.\
A record admitted for a session refused, or closed, before it was established is forgotten the same way, from the moment it was admitted.\
A session whose evidence gives no principal is recorded too, with `principal` `null`, and a host reads any session's record by its peer node and session identifier.\
A key admitted again replaces its record, with the time of its new admission and no absence noted.\
Under zorg's `D59` to `D63` and `D71` (`upstream/agp-admission-use-lifecycle-fit-reply.md`, `upstream/agp-credentialed-peer-interface-reply.md`), once AGP's `direct-peer-send`, `admission-use-lifecycle` and `agp.admission-acquisition/v2` surfaces land alongside `verified-principal`, the host configures `caller-identity` in an explicit mode - `"authenticated"` or `"unauthenticated"` (`trusted-development`, whereas omitting `mode` or passing `undefined` preserves the legacy Delta 1 `{decision: "allow"}` result without `authorizationAssociation`, `CI6`) - and every verifier or rule declares its canonical `issuer` authority namespace (1 to 256 Unicode scalar values with no control character or lone surrogate, never an unqualified `"agp-transport"` literal): in `"authenticated"` mode on the local-redeemer acquisition branch (where proof/redemption and custody precede controller protocol processing, protocol `OPEN` is processed so `IdentityAdmissionPort.evaluate` receives `request.remoteNodeId`, and application delivery remains admission-gated), `caller-identity`'s admission port declares `supportsRedeemedAdmission: true`, receives `options.redeemedAdmission` (`{redemptionId, lifecycle}`) on `evaluate(request, options)`, resolves the trusted record in `credential-issuer`'s `admission-key-verifier` by both `redemptionId` and exact object identity of `lifecycle` (`record.lifecycle === options.redeemedAdmission.lifecycle`, never deriving identity or principal from the native 127-byte ASCII PSK selector), verifies that `request.remoteNodeId === record.node`, denies any missing, mismatched, failed or unproved credential (`decision` `"deny"` with `"SECURITY_EVIDENCE"`, `"EXPECTED_NODE_MISMATCH"` or `"POLICY"`), never downgrading to `"unauthenticated"`, and supplies AGP's `IdentityAdmissionResult` the immutable `authorizationAssociation` `{mode: "authenticated", issuer, principal, instanceBinding}` (with `issuer`, `principal` and `instanceBinding` each 1 to 256 Unicode scalar values with no control character or lone surrogate); in explicit `"unauthenticated"` mode on the ordinary transport branch, an admitted session supplies `{mode: "unauthenticated"}`, which AGP attaches to the session and to `EndpointDeliveryContext.directPeer` when a request arrives directly from its origin node so reply isolation never consults `CI2`'s swept session table at reply time.\
Tested by: `E18`, in `test/contract/session-principal.test.js`, against AGP's production in-process carrier with an injected clock port and sweeps: an admitted session's record; a session closed 1 millisecond after a sweep, whose record is found 59 seconds after the close, and is gone after the sweep 90 seconds after the last sweep that found it; a session closed at the instant of a sweep; a session admitted while pending at a sweep and established and closed between that sweep and the next, whose record is still found 59 seconds after its close; a sweep run 10 seconds late; another peer's pending connection with the same session identifier, which keeps the record until it ends; a session refused after admission before it was established; a reconnection under a new session with a record of its own; one session number used by two nodes, each with its own record; a key admitted again, whose new record replaces the old - its principal and its certainty both changed - and its noted absence; a host ruling that answers allow, and one that rejects, after the deadline, each denied whether its answer or the deadline's timer runs first, an answer just before the deadline taken, and an asynchronous ruling on the default clock that answers late; a host ruling that never answers, denied at the admission deadline, after which another peer's record sharing that session identifier is forgotten as any absent session's is; another peer pending with a closed session's identifier only after that session's absence was noted, which changes nothing; and one pending at the sweep right after the close, which delays the noting of absence to the next sweep; a snapshot that throws, reported to the diagnostic port and keeping every record, then read again, the record forgotten by the first readable sweep 60 seconds after absence was first seen; a failure of 2 milliseconds at the first sweep after a close, delaying the noting of absence by one sweep interval; a failure at the sweep where a record falls due, which forgets it at the next readable sweep; and the sweeping stopped twice, the second stop changing nothing.

**CI3 - The evidence of a request.**\
Given a request's delivery context - its origin node, and its ingress node and session when it arrived over a session - the component answers with one record, exactly `{"kind": "agp-session", "node": <the origin node>, "principal": <a principal or null>, "proved": <true or false>}`.\
`node` is always the origin node; the ingress node and session only find the record.\
`principal` is the recorded one, and `proved` its recorded certainty, when the origin node is the ingress node and a record exists for that ingress node and session; otherwise `principal` is `null` and `proved` is `false`.\
A host asks as it receives the request, before anything else is done with it.\
Tested by: `E18`, in `test/contract/request-evidence.test.js`, with the injected clock port and sweeps of `CI2`, asserting the whole record for a well-formed node, a node whose name gives no principal, an origin that is not the ingress node, a delivery with no ingress, a request 59 seconds after its session closed, one just before the sweep that forgets its record and one just after, a request of a session established and closed between two sweeps, 59 seconds after its close, a delivery context naming, as its ingress, a session refused after admission before it was established, while that session's record is kept and after it is forgotten, a reconnection, and one session number on two nodes.

**CI4 - Certainty is never inferred.**\
A record's `proved` is `true` only for a principal the transport's own proof established - AGP's evidence of a verified peer - or a verifier the host supplied established (`verified-principal`, `CI6`, outside Delta 1); in legacy or `"unauthenticated"` session admission, the component records `proved` `true` only when the rule claims it for exactly the principal AGP's evidence verified - `authentication.kind` `verified` and the rule's principal equal to `authentication.principal` - and records any other principal asserted, a principal a rule derives from the verified one included, whereas in `"authenticated"` session admission (`CI6`) `proved` `true` and the session's `principal` come from `redeemedVerifier`, and in request-level verification (`CI6`) `proved` `true` and the evidence's `principal` and `issuer` come from the host's `CredentialVerifier`s; no rule, default or later step turns an asserted principal into a proved one, and a record's `kind` says what produced it (`agp-session` or `verified-principal`), so a later kind of evidence is a new variant of the record rather than a change to `agp-session`.\
Tested by: `E18`, in `test/contract/request-evidence.test.js`, which checks that every record produced under trusted-development security has `proved` `false`, and, against AGP's production in-process carrier, whose evidence verifies a transport principal, that a rule claiming proof for that principal itself is recorded proved, one claiming proof for another name over the same evidence is recorded asserted, a rule whose result's `principal` or `proved` is a getter refused as non-plain data without calling the getter and recording nothing (zorg's `D54`), and one claiming proof over a session whose evidence reports no authentication - the carrier's accepted channels relabelled to report what trusted-development WebSocket security reports, since the in-process carrier always reports a verified peer - is recorded asserted.

**CI5 - What zorg composes.**\
The hub of zorg gives caller-identity the asserted node rule, supplies its admission port to the hub's AGP node, and gives operation-call's host half its answer for each request as that request's evidence; zorg's own use of the record - the writer it names and the policy it applies - is zorg's `EM13`.\
Tested by: `E5`, in zorg's `packages/zorg-hub/test/evidence.test.js` and `test/e2e/refusals-and-writers.test.js`.

**CI6 - Verified principals and redeemed-admission mode (`D37` to `D39`, `D54`, `D55`, `D60` to `D63`, `D71`, `D73`).**\
A bounded identifier (`issuer`, `principal`, `instanceBinding`, `redemptionId`, `session`) is a string of 1 to 256 Unicode scalar values (`Array.from(value).length` from `1` to `256`) containing no control character (`U+0000..U+001F` or `U+007F..U+009F`) and no lone surrogate, and an `issuer` namespace must never equal `"agp-transport"`.\
For `verified-principal`, a `CredentialVerifier` is a plain object (`Object.getPrototypeOf(verifier) === Object.prototype || Object.getPrototypeOf(verifier) === null`, with own enumerable data properties `issuer`, a valid bounded identifier string not equal to `"agp-transport"`, and `verify`, a function, and no symbols or other own properties) validated at construction (`createCallerIdentity` or `verifyCredential(verifiers, credential, options?)`, throwing `TypeError` on a non-array `verifiers` or any nonconforming verifier entry, class instance, getter or invalid `issuer`).\
When `verifyCredential(verifiers, credential, { clock })` or `callerIdentity.verify(credential)` runs, it reads `clock.now()` before and after invoking every configured verifier's `verify(credential)`, awaiting only a native `Promise` (`raw instanceof Promise`, attached via guarded `Promise.prototype.then`) and treating any non-native thenable, throw or rejection as a verifier refusal after observing any reachable native promises within `shape-check`'s reader bound (`D54`, `D55`); each settled non-`null` return value is read as plain data through `readPlainJson` and `observePromises` as `{ principal, expiresAt?, session? }` with own enumerable data properties only (`principal` a valid 1 to 256 scalar-value string, optional `expiresAt` a finite number of milliseconds on `clock` with `clock.now() < expiresAt` at verification completion, and optional `session` a valid 1 to 256 scalar-value string identifying the sign-in session for `D39` revocation checks; any other shape, `expiresAt <= now`, getter, symbol or extra field is treated as a refusal).\
If zero verifiers accept, `verify` resolves `null`; if two or more verifiers accept and any two disagree on `(issuer, principal)`, conflicting evidence establishes no principal (`VISION.md`) and `verify` resolves `null`; if one or more verifiers accept the same `(issuer, principal)`, `verify` resolves a brand-tagged, deeply frozen `VerifiedCredential` `{ kind: "verified-credential", principal, issuer, proved: true, expiresAt, session }` (where `expiresAt` is the minimum finite `expiresAt` among the accepting verifiers, or `null` when none gave `expiresAt`, and `session` is the agreed `session` string when at least one accepting verifier supplied `session` and all accepting verifiers that supplied `session` gave the same value, or `null` when none supplied `session` or when two accepting verifiers supplied different `session` strings).\
`callerIdentity.evidence(delivery, verified?)` checks `delivery.source.originNodeId` first (`CI3`); when `verified` is omitted or `undefined`, it returns `CI3`'s `agp-session` record unchanged; when `verified` is passed, it requires `verified` to carry the private provenance brand of a `VerifiedCredential` minted either by this exact `CallerIdentity` instance (`callerIdentity.verify`) or by standalone `verifyCredential` with the exact same `ClockPort` object (`=== clock`, where both `createCallerIdentity` and `verifyCredential` use the one shared `defaultClock` singleton when `clock` is omitted so a default-clock standalone `verifyCredential` result is accepted by a default-clock `CallerIdentity` instance, while a `VerifiedCredential` minted by another `CallerIdentity` instance is always rejected even if both share `clock`, as is a standalone result from a different `ClockPort`) and checks `verified.expiresAt === null || clock.now() < verified.expiresAt`, returning `Object.freeze({ kind: "verified-principal", node: delivery.source.originNodeId, principal: verified.principal, issuer: verified.issuer, proved: true, expiresAt: verified.expiresAt })` when valid, and throwing `TypeError` (never falling back to `agp-session`) if `verified` is unbranded, forged, from another `CallerIdentity` instance, from a different `ClockPort`, or if `clock.now() >= verified.expiresAt`.\
For session admission (`CI2`, `D60` to `D63`, `D71`), `CallerIdentityOptions` accepts optional `mode?: "unauthenticated" | "authenticated"` and optional `verifiers?: readonly CredentialVerifier[]`: when `mode` is omitted or `undefined`, `admission.evaluate(request)` preserves the legacy Delta 1 `{ decision: "allow" }` result without `authorizationAssociation`; when `mode` is explicitly `"unauthenticated"`, `admission.evaluate(request)` returns `Object.freeze({ decision: "allow", authorizationAssociation: Object.freeze({ mode: "unauthenticated" }) })` on allow; when `mode === "authenticated"`, `createCallerIdentity` requires `redeemedVerifier: RedeemedAdmissionVerifier` (`{ verifyRedeemed(input: { readonly redemptionId: string; readonly lifecycle: object; readonly remoteNodeId: string }): unknown }`, with `rule` optional in `CallerIdentityOptions` since `"authenticated"` admission records the principal from `redeemedVerifier` and never calls `rule.apply`), sets `admission.supportsRedeemedAdmission = true`, and in `admission.evaluate(request, options)` runs within the single `admissionDeadlineMs` budget on `clock`: first evaluating any explicit host `admission` ruling port within the deadline, then reading `options` and `options.redeemedAdmission` via own enumerable data descriptors only (denying with `reasonCode: "SECURITY_EVIDENCE"` if missing, non-plain, or lacking a valid 1 to 256 scalar-value `redemptionId` and non-null object `lifecycle`), calling `redeemedVerifier.verifyRedeemed({ redemptionId, lifecycle, remoteNodeId: request.remoteNodeId })` (awaiting a native `Promise` if returned, within the remaining deadline) and reading its result through `readPlainJson` and `observePromises` as `{ ok: true, issuer, principal, instanceBinding }` (each a valid 1 to 256 scalar-value string with `issuer !== "agp-transport"`) or `{ ok: false, reasonCode?: "SECURITY_EVIDENCE" | "EXPECTED_NODE_MISMATCH" | "POLICY" | "CAPACITY" }` (defaulting `reasonCode` to `"SECURITY_EVIDENCE"`, any throw, rejection or malformed return denying with `"SECURITY_EVIDENCE"`, and deadline expiry denying with `"POLICY"` with nothing recorded), and on a valid `{ ok: true, issuer, principal, instanceBinding }` before the deadline recording the session in `SessionRecords` with `principal` and `proved: true` (ignoring `request.peerEvidence` and `rule.apply`) and returning `Object.freeze({ decision: "allow", authorizationAssociation: Object.freeze({ mode: "authenticated", issuer, principal, instanceBinding }) })`.\
Tested by: `D10-E1` (covering `CI2`, `CI3`, `CI4` and `CI6`), in `test/contract/verified-principal.test.js`, including plain-object vs class-instance verifier validation, single and multiple agreeing verifiers (minimum `expiresAt`, and `session` aggregation across none supplied -> `null`, one supplied -> retained, identical supplied -> retained, conflicting supplied -> `null`, and refused verifiers ignored), conflicting `(issuer, principal)` verifiers returning `null`, instance-bound vs standalone same-clock (including default-clock to default-clock handoff) vs different-instance/different-clock provenance and expiry-at-use in `evidence(delivery, verified)`, omitted/undefined `mode` (`{ decision: "allow" }`) vs explicit `"unauthenticated"` mode (`authorizationAssociation: { mode: "unauthenticated" }`) vs `"authenticated"` mode (with conflicting transport/rule/redeemed principals proving `SessionRecords` and subsequent `CI3` `evidence(delivery)` record the redeemed principal with `proved: true` and `rule.apply` uncalled, no new or replaced session record on `verifyRedeemed` refusal or deadline expiry, `Object.isFrozen` and mutation-resistance checks on `VerifiedCredential`, `verified-principal` evidence and `authorizationAssociation`, host `admission` ruling, descriptor-safe `options.redeemedAdmission`, `verifyRedeemed`, and `D54`/`D55` plain-data protection).

---

## Reference

This repository, `apnex/caller-identity`, private until its first working code is certified.\
The package `@apnex/caller-identity` exports `createCallerIdentity`, which gives a host its identity-admission port, the sweeps it starts and stops with its node, each session's record, credential verification and each request's evidence, `assertedNodeRule`, and `verifyCredential`, as `export-map.json` records.\
It depends on `@apnex/shape-check` through a `file:` link, takes AGP's types from `@agp/core` as a peer dependency through a `file:` link to AGP's checkout, imports nothing from AGP at run time, and imports no module particular to one runtime.

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
- `shape-check`: `plain-json-value`

**Composed-by:** nothing yet.\
Its first consumer, once built, is zorg's hub, which supplies AGP's admission check through it and gives operation-call's host half the evidence of each request.

The registry's edge vocabulary has no edge for one component using another's contract without containing it; see the note in operation-call's entry.
