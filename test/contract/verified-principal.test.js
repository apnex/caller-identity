// verified-principal - CONTRACT.md's row, through CI2, CI3, CI4 and CI6, for zorg's D10-E1.
//
// Tests plain-object CredentialVerifier construction validation, bounded 1..256 Unicode scalar-value identifier
// validation, single and multiple agreeing verifiers (minimum expiresAt and session aggregation), conflicting
// (issuer, principal) verifiers returning null, provenance brand and expiry-at-use enforcement in
// evidence(delivery, verified) (including default-clock to default-clock handoff and cross-instance rejection),
// and session admission modes (omitted/undefined, "unauthenticated", and "authenticated" with redeemedVerifier,
// descriptor-safe options.redeemedAdmission, host admission ruling, deadline enforcement, and D54/D55 plain-data
// and promise observation).
import assert from "node:assert/strict";
import { test } from "node:test";
import { assertedNodeRule, createCallerIdentity, verifyCredential } from "@apnex/caller-identity";
import { ManualClock } from "../support/manual-clock.js";

const START = 1_000_000;

/** Runs `body` while observing process-level unhandled rejections; returns any that escaped. */
async function observingUnhandledRejections(body) {
	const escaped = [];
	const observe = (reason) => {
		escaped.push(reason);
	};
	process.on("unhandledRejection", observe);
	try {
		await body();
		await new Promise((resolve) => setTimeout(resolve, 40));
	} finally {
		process.off("unhandledRejection", observe);
	}
	return escaped;
}

const delivery = (originNodeId = "alice.1", ingressNodeId = "alice.1", ingressSessionId = "000001") => ({
	source: { endpoint: "svc", originNodeId },
	...(ingressNodeId === undefined ? {} : { ingressNodeId }),
	...(ingressSessionId === undefined ? {} : { ingressSessionId }),
});

const admissionRequest = (remoteNodeId = "alice.1", localSessionId = "000001", peerEvidence = {
	locality: "network",
	protection: "none",
	authentication: { kind: "none" },
}) => ({
	localNodeId: "hub",
	remoteNodeId,
	localSessionId,
	remoteSessionId: "000099",
	direction: "inbound",
	peerEvidence,
});

// 1. Verifier construction & bounded identifier validation (CI6)

test("CI6, D10-E1: createCallerIdentity and verifyCredential validate plain-object CredentialVerifiers and canonical issuer namespaces at construction", async () => {
	const clock = new ManualClock(START);
	class VerifierClass {
		constructor() {
			this.issuer = "zorg-hub";
			this.verify = () => null;
		}
	}
	const sym = Symbol("extra");
	const nonPlain = Object.create({ issuer: "zorg-hub", verify: () => null });
	const getterIssuer = {
		get issuer() {
			return "zorg-hub";
		},
		verify: () => null,
	};
	const getterVerify = {
		issuer: "zorg-hub",
		get verify() {
			return () => null;
		},
	};
	const nonEnumIssuer = {};
	Object.defineProperty(nonEnumIssuer, "issuer", { value: "zorg-hub", enumerable: false });
	Object.defineProperty(nonEnumIssuer, "verify", { value: () => null, enumerable: true });

	const invalidVerifierLists = [
		"not-an-array",
		null,
		{},
		[null],
		["verifier"],
		[[]],
		[new VerifierClass()],
		[nonPlain],
		[getterIssuer],
		[getterVerify],
		[nonEnumIssuer],
		[{ issuer: "zorg-hub", verify: () => null, extra: 1 }],
		[{ issuer: "zorg-hub", verify: () => null, [sym]: 1 }],
		[{ issuer: "zorg-hub", verify: "not-a-fn" }],
		[{ issuer: "", verify: () => null }],
		[{ issuer: "agp-transport", verify: () => null }],
		[{ issuer: "a".repeat(257), verify: () => null }],
		[{ issuer: "bad\u0000issuer", verify: () => null }],
		[{ issuer: "bad\u001fissuer", verify: () => null }],
		[{ issuer: "bad\u007fissuer", verify: () => null }],
		[{ issuer: "bad\u009fissuer", verify: () => null }],
		[{ issuer: "bad\ud800issuer", verify: () => null }],
		[{ issuer: "bad\udfffissuer", verify: () => null }],
	];

	for (const bad of invalidVerifierLists) {
		assert.throws(
			() => createCallerIdentity({ rule: assertedNodeRule, clock, verifiers: bad }),
			TypeError,
		);
		await assert.rejects(
			() => verifyCredential(bad, "tok", { clock }),
			TypeError,
		);
	}

	// Null-prototype plain object and 256-scalar-value emoji issuer are valid.
	const nullProtoVerifier = Object.assign(Object.create(null), {
		issuer: "🙂".repeat(256),
		verify: () => ({ principal: "alice" }),
	});
	const ci = createCallerIdentity({ rule: assertedNodeRule, clock, verifiers: [nullProtoVerifier] });
	const res = await ci.verify("tok");
	assert.equal(res.issuer, "🙂".repeat(256));
	assert.equal(res.principal, "alice");
});

// 2. Credential verification: single verifier, clock reads, D54/D55 plain data, bounded strings, expiry

test("CI6, D10-E1: verifyCredential and callerIdentity.verify read clock.now() before and after each verifier, accept sync and native-Promise results, and return a deeply frozen VerifiedCredential", async () => {
	const reads = [];
	let current = START;
	const trackingClock = {
		now() {
			reads.push(current);
			return current;
		},
		schedule(delayMs, cb) {
			const h = setTimeout(cb, delayMs);
			return { cancel: () => clearTimeout(h) };
		},
	};
	const syncVerifier = {
		issuer: "issuer-a",
		verify(cred) {
			current += 5;
			return cred === "valid" ? { principal: "alice", expiresAt: START + 100, session: "sess-1" } : null;
		},
	};
	const asyncVerifier = {
		issuer: "issuer-a",
		async verify(cred) {
			current += 10;
			return cred === "valid" ? { principal: "alice", expiresAt: START + 80, session: "sess-1" } : null;
		},
	};

	const ci = createCallerIdentity({
		rule: assertedNodeRule,
		clock: trackingClock,
		verifiers: [syncVerifier, asyncVerifier],
	});
	const verified = await ci.verify("valid");
	assert.deepEqual(reads, [START, START + 5, START + 5, START + 15], "clock.now() read before and after each verifier");
	assert.deepEqual(verified, {
		kind: "verified-credential",
		principal: "alice",
		issuer: "issuer-a",
		proved: true,
		expiresAt: START + 80,
		session: "sess-1",
	});
	assert.ok(Object.isFrozen(verified));
	assert.throws(() => {
		verified.principal = "mallory";
	}, TypeError);
	assert.throws(() => {
		verified.extra = 1;
	}, TypeError);
});

test("CI6, D54, D55, D10-E1: verifier refusals — null, throw, rejection, non-native thenable, getter, symbol, prototype, extra field, invalid principal/session, or expiresAt <= now — are refused without calling getters or leaking rejections", async () => {
	const clock = new ManualClock(START);
	let getterCalls = 0;
	const sym = Symbol("s");
	const badOutputs = [
		null,
		undefined,
		"alice",
		123,
		[],
		() => {
			throw new Error("sync verifier throw");
		},
		() => Promise.reject(new Error("async verifier rejection")),
		// Non-native thenable is not awaited and is rejected by readPlainJson
		{ then(resolve) { resolve({ principal: "alice" }); } },
		// Getter on principal/expiresAt/session must never be invoked
		{
			get principal() {
				getterCalls += 1;
				return "alice";
			},
		},
		{
			principal: "alice",
			get expiresAt() {
				getterCalls += 1;
				return START + 1_000;
			},
		},
		{
			principal: "alice",
			get session() {
				getterCalls += 1;
				return "s1";
			},
		},
		Object.create({ principal: "alice" }),
		{ principal: "alice", [sym]: 1 },
		{ principal: "alice", extra: true },
		{ principal: "" },
		{ principal: "a".repeat(257) },
		{ principal: "bad\u0000principal" },
		{ principal: "bad\u007fprincipal" },
		{ principal: "bad\u0080principal" },
		{ principal: "bad\ud800principal" },
		{ principal: "bad\udfffprincipal" },
		{ principal: "alice", session: "" },
		{ principal: "alice", session: "s".repeat(257) },
		{ principal: "alice", session: "bad\u0007session" },
		{ principal: "alice", session: "bad\ud800session" },
		{ principal: "alice", session: 42 },
		{ principal: "alice", expiresAt: START }, // expiresAt === now -> expired at completion
		{ principal: "alice", expiresAt: START - 1 },
		{ principal: "alice", expiresAt: Number.NaN },
		{ principal: "alice", expiresAt: Number.POSITIVE_INFINITY },
		{ principal: "alice", expiresAt: "2000000" },
		// Nested native rejected Promise inside return value or thrown error is observed (D55)
		{ principal: "alice", nested: Promise.reject(new Error("nested rejection")) },
		() => {
			const err = new Error("throw with promise");
			err.inner = Promise.reject(new Error("inner rejection"));
			throw err;
		},
	];

	const escaped = await observingUnhandledRejections(async () => {
		for (const out of badOutputs) {
			const verifier = {
				issuer: "zorg-hub",
				verify: typeof out === "function" ? out : () => out,
			};
			const res = await verifyCredential([verifier], "cred", { clock });
			assert.equal(res, null);
		}
	});
	assert.equal(getterCalls, 0, "no getter on a verifier result was called");
	assert.deepEqual(escaped, [], "no unhandled rejection escaped");
});

// 3. Multiple verifiers: agreement, minimum expiresAt, session aggregation, and conflict refusal

test("CI6, D10-E1: multiple verifiers — agreeing verifiers take the minimum finite expiresAt and aggregate session; any disagreement on (issuer, principal) resolves null", async () => {
	const clock = new ManualClock(START);

	// Zero verifiers configured -> null
	assert.equal(await verifyCredential([], "cred", { clock }), null);
	const emptyCi = createCallerIdentity({ rule: assertedNodeRule, clock });
	assert.equal(await emptyCi.verify("cred"), null);

	// 1) None supply session, none supply expiresAt -> both null
	{
		const v1 = { issuer: "iss", verify: () => ({ principal: "alice" }) };
		const v2 = { issuer: "iss", verify: async () => ({ principal: "alice" }) };
		const res = await verifyCredential([v1, v2], "cred", { clock });
		assert.deepEqual(res, {
			kind: "verified-credential",
			principal: "alice",
			issuer: "iss",
			proved: true,
			expiresAt: null,
			session: null,
		});
	}

	// 2) One supplies session and expiresAt, another supplies neither, a third refuses -> session and expiresAt retained
	{
		const v1 = { issuer: "iss", verify: () => ({ principal: "alice" }) };
		const v2 = { issuer: "iss", verify: () => ({ principal: "alice", expiresAt: START + 500, session: "sess-42" }) };
		const v3 = { issuer: "other-issuer", verify: () => null };
		const res = await verifyCredential([v1, v2, v3], "cred", { clock });
		assert.deepEqual(res, {
			kind: "verified-credential",
			principal: "alice",
			issuer: "iss",
			proved: true,
			expiresAt: START + 500,
			session: "sess-42",
		});
	}

	// 3) Multiple supply identical session and different expiresAt -> session retained, minimum expiresAt chosen
	{
		const v1 = { issuer: "iss", verify: () => ({ principal: "alice", expiresAt: START + 900, session: "sess-same" }) };
		const v2 = { issuer: "iss", verify: () => ({ principal: "alice", expiresAt: START + 300, session: "sess-same" }) };
		const res = await verifyCredential([v1, v2], "cred", { clock });
		assert.equal(res.expiresAt, START + 300);
		assert.equal(res.session, "sess-same");
	}

	// 4) Multiple accepting verifiers agree on (issuer, principal) but supply different session strings -> session is null
	{
		const v1 = { issuer: "iss", verify: () => ({ principal: "alice", session: "sess-a" }) };
		const v2 = { issuer: "iss", verify: () => ({ principal: "alice", session: "sess-b" }) };
		const v3 = { issuer: "iss", verify: () => ({ principal: "alice", session: "sess-a" }) };
		const res = await verifyCredential([v1, v2, v3], "cred", { clock });
		assert.equal(res.principal, "alice");
		assert.equal(res.session, null);
	}

	// 5) Two accepting verifiers disagree on principal -> null
	{
		const v1 = { issuer: "iss", verify: () => ({ principal: "alice" }) };
		const v2 = { issuer: "iss", verify: () => ({ principal: "bob" }) };
		assert.equal(await verifyCredential([v1, v2], "cred", { clock }), null);
	}

	// 6) Two accepting verifiers agree on principal but have different issuer -> null
	{
		const v1 = { issuer: "iss-1", verify: () => ({ principal: "alice" }) };
		const v2 = { issuer: "iss-2", verify: () => ({ principal: "alice" }) };
		assert.equal(await verifyCredential([v1, v2], "cred", { clock }), null);
	}

	// 7) Overall-completion expiry across multiple verifiers: if an earlier verifier accepts with expiresAt: 105
	// and a subsequent verifier advances the clock to 104 (valid) vs 105 or 106 (expired at overall completion -> null),
	// either inside verify() or inside a Proxy trap during readPlainJson (for both valid and refused shapes),
	// both verifyCredential and callerIdentity.verify enforce expiry at overall completion.
	for (const [endTime, shouldPass] of [[104, true], [105, false], [106, false]]) {
		for (const useInstance of [false, true]) {
			for (const mode of ["callback", "proxy-valid", "proxy-refused"]) {
				const c = new ManualClock(100);
				const verifiers = [
					{ issuer: "iss", verify: () => ({ principal: "alice", expiresAt: 105 }) },
					{
						issuer: "iss",
						verify: () => {
							if (mode === "callback") {
								c.setTime(endTime);
								return null;
							}
							const target = mode === "proxy-valid" ? { principal: "alice" } : { extra: true };
							return new Proxy(target, {
								ownKeys(t) {
									c.setTime(endTime);
									return Reflect.ownKeys(t);
								},
							});
						},
					},
				];
				const out = useInstance
					? await createCallerIdentity({ rule: assertedNodeRule, clock: c, verifiers }).verify("cred")
					: await verifyCredential(verifiers, "cred", { clock: c });
				if (shouldPass) {
					assert.deepEqual(out, {
						kind: "verified-credential",
						principal: "alice",
						issuer: "iss",
						proved: true,
						expiresAt: 105,
						session: null,
					});
				} else {
					assert.equal(out, null, `expired at overall completion (${endTime}, ${mode}) must resolve null`);
				}
			}
		}
	}
});

// 4. callerIdentity.evidence(delivery, verified?) provenance, clock matching, and expiry-at-use (CI3, CI4, CI6)

test("CI3, CI4, CI6, D10-E1: evidence(delivery, verified) enforces provenance brand (same CallerIdentity instance or standalone verifyCredential on the same ClockPort, including defaultClock) and clock.now() < expiresAt", async () => {
	const clock1 = new ManualClock(START);
	const clock2 = new ManualClock(START);
	const verifier = {
		issuer: "zorg-hub",
		verify: (c) => (c === "no-exp"
			? { principal: "alice" }
			: c === "exp"
				? { principal: "alice", expiresAt: START + 1_000, session: "s1" }
				: null),
	};

	const ci1 = createCallerIdentity({ rule: assertedNodeRule, clock: clock1, verifiers: [verifier] });
	const ci2 = createCallerIdentity({ rule: assertedNodeRule, clock: clock1, verifiers: [verifier] });
	const ciOtherClock = createCallerIdentity({ rule: assertedNodeRule, clock: clock2, verifiers: [verifier] });

	// Record an asserted session for alice.1 so we can verify that invalid `verified` throws TypeError and never falls back to agp-session.
	await ci1.admission.evaluate(admissionRequest("alice.1", "000001"));
	assert.deepEqual(ci1.evidence(delivery("alice.1", "alice.1", "000001")), {
		kind: "agp-session",
		node: "alice.1",
		principal: "alice",
		proved: false,
	});
	assert.deepEqual(ci1.evidence(delivery("alice.1", "alice.1", "000001"), undefined), {
		kind: "agp-session",
		node: "alice.1",
		principal: "alice",
		proved: false,
	});

	// 1) Minted by ci1.verify -> accepted by ci1, rejected by ci2 (even though ci1 and ci2 share clock1)
	const fromCi1 = await ci1.verify("exp");
	const ev1 = ci1.evidence(delivery("origin-node.9", "relay.1", "000001"), fromCi1);
	assert.deepEqual(ev1, {
		kind: "verified-principal",
		node: "origin-node.9",
		principal: "alice",
		issuer: "zorg-hub",
		proved: true,
		expiresAt: START + 1_000,
	});
	assert.ok(Object.isFrozen(ev1));
	assert.throws(() => {
		ev1.principal = "bob";
	}, TypeError);
	assert.throws(() => ci2.evidence(delivery(), fromCi1), TypeError, "credential from another CallerIdentity instance is rejected");
	assert.throws(() => ciOtherClock.evidence(delivery(), fromCi1), TypeError);

	// 2) Minted by standalone verifyCredential on clock1 -> accepted by both ci1 and ci2 (same clock1), rejected by ciOtherClock (clock2)
	const fromStandaloneClock1 = await verifyCredential([verifier], "no-exp", { clock: clock1 });
	const evStandalone = ci1.evidence(delivery("node.a"), fromStandaloneClock1);
	assert.deepEqual(evStandalone, {
		kind: "verified-principal",
		node: "node.a",
		principal: "alice",
		issuer: "zorg-hub",
		proved: true,
		expiresAt: null,
	});
	assert.deepEqual(ci2.evidence(delivery("node.b"), fromStandaloneClock1), {
		kind: "verified-principal",
		node: "node.b",
		principal: "alice",
		issuer: "zorg-hub",
		proved: true,
		expiresAt: null,
	});
	assert.throws(() => ciOtherClock.evidence(delivery("node.b"), fromStandaloneClock1), TypeError, "different ClockPort rejected");

	// 3) Default-clock to default-clock handoff: standalone verifyCredential without clock is accepted by default-clock CallerIdentity; cross-instance still rejected
	const defaultCi1 = createCallerIdentity({ rule: assertedNodeRule, verifiers: [verifier] });
	const defaultCi2 = createCallerIdentity({ rule: assertedNodeRule, verifiers: [verifier] });
	const fromDefaultStandalone = await verifyCredential([verifier], "no-exp");
	assert.deepEqual(defaultCi1.evidence(delivery("node.def"), fromDefaultStandalone), {
		kind: "verified-principal",
		node: "node.def",
		principal: "alice",
		issuer: "zorg-hub",
		proved: true,
		expiresAt: null,
	});
	const fromDefaultCi1 = await defaultCi1.verify("no-exp");
	assert.throws(() => defaultCi2.evidence(delivery("node.def"), fromDefaultCi1), TypeError, "different default-clock instance still rejected");

	// 4) Forged / unbranded / spread-cloned object throws TypeError
	for (const forged of [
		null,
		"verified",
		123,
		{ kind: "verified-credential", principal: "alice", issuer: "zorg-hub", proved: true, expiresAt: null, session: null },
		{ ...fromCi1 },
		Object.create(fromCi1),
	]) {
		assert.throws(() => ci1.evidence(delivery(), forged), TypeError);
	}

	// 5) Missing delivery.source.originNodeId throws TypeError even when verified is valid
	assert.throws(() => ci1.evidence({}, fromCi1), TypeError);
	assert.throws(() => ci1.evidence({ source: {} }, fromCi1), TypeError);

	// 6) Expiry at use: valid at START + 999, throws TypeError at START + 1_000 and START + 1_001
	clock1.advanceTo(START + 999);
	assert.equal(ci1.evidence(delivery(), fromCi1).principal, "alice");
	clock1.advanceTo(START + 1_000);
	assert.throws(() => ci1.evidence(delivery(), fromCi1), TypeError, "expired at exact expiresAt throws TypeError");
	clock1.advanceTo(START + 1_001);
	assert.throws(() => ci1.evidence(delivery(), fromCi1), TypeError, "expired after expiresAt throws TypeError");
	// Credential with expiresAt: null remains valid after clock advances
	assert.equal(ci1.evidence(delivery(), fromStandaloneClock1).principal, "alice");
});

// 5. Session admission modes: omitted/undefined vs "unauthenticated" vs "authenticated" (CI2, CI3, CI4, CI6)

test("CI2, CI6, D10-E1: session admission modes — omitted/undefined mode returns legacy { decision: \"allow\" }, explicit \"unauthenticated\" mode returns frozen authorizationAssociation: { mode: \"unauthenticated\" }", async () => {
	const clock = new ManualClock(START);

	// Invalid mode rejected at construction
	assert.throws(() => createCallerIdentity({ rule: assertedNodeRule, clock, mode: "invalid" }), TypeError);
	assert.throws(() => createCallerIdentity({ mode: "unauthenticated", clock }), TypeError, "rule required in unauthenticated mode");
	assert.throws(() => createCallerIdentity({ clock }), TypeError, "rule required when mode is omitted");
	assert.throws(() => createCallerIdentity({ mode: "authenticated", clock }), TypeError, "redeemedVerifier required in authenticated mode");

	const legacyOmitted = createCallerIdentity({ rule: assertedNodeRule, clock });
	const legacyUndefined = createCallerIdentity({ rule: assertedNodeRule, mode: undefined, clock });
	const unauth = createCallerIdentity({ rule: assertedNodeRule, mode: "unauthenticated", clock });

	assert.equal("supportsRedeemedAdmission" in legacyOmitted.admission, false);
	assert.equal("supportsRedeemedAdmission" in unauth.admission, false);

	const resOmitted = await legacyOmitted.admission.evaluate(admissionRequest("alice.1", "000001"));
	assert.deepEqual(resOmitted, { decision: "allow" });
	assert.equal("authorizationAssociation" in resOmitted, false);
	assert.ok(Object.isFrozen(resOmitted));

	const resUndefined = await legacyUndefined.admission.evaluate(admissionRequest("alice.1", "000001"));
	assert.deepEqual(resUndefined, { decision: "allow" });
	assert.equal("authorizationAssociation" in resUndefined, false);

	const resUnauth = await unauth.admission.evaluate(admissionRequest("alice.1", "000001"));
	assert.deepEqual(resUnauth, {
		decision: "allow",
		authorizationAssociation: { mode: "unauthenticated" },
	});
	assert.ok(Object.isFrozen(resUnauth));
	assert.ok(Object.isFrozen(resUnauth.authorizationAssociation));
	assert.deepEqual(unauth.sessionPrincipal("alice.1", "000001"), {
		node: "alice.1",
		session: "000001",
		principal: "alice",
		proved: false,
	});
});

test("CI2, CI3, CI4, CI6, D10-E1: \"authenticated\" mode sets supportsRedeemedAdmission: true, bypasses rule.apply and transport peerEvidence, records the redeemed principal with proved: true, and returns frozen authorizationAssociation", async () => {
	const clock = new ManualClock(START);
	const lifecycle = Object.freeze({ token: "lc-1" });
	let ruleCalled = 0;
	const conflictingRule = {
		apply() {
			ruleCalled += 1;
			return { principal: "rule-principal", proved: false };
		},
	};
	const seenInputs = [];
	const redeemedVerifier = {
		verifyRedeemed(input) {
			seenInputs.push(input);
			if (input.redemptionId === "red-1" && input.lifecycle === lifecycle && input.remoteNodeId === "peer-node.1") {
				return {
					ok: true,
					issuer: "zorg-hub",
					principal: "redeemed-alice",
					instanceBinding: "peer-node.1",
				};
			}
			return { ok: false, reasonCode: "EXPECTED_NODE_MISMATCH" };
		},
	};

	const ci = createCallerIdentity({
		mode: "authenticated",
		rule: conflictingRule,
		redeemedVerifier,
		clock,
	});
	assert.equal(ci.admission.supportsRedeemedAdmission, true);
	assert.ok(Object.isFrozen(ci.admission));

	// Transport evidence claims a different verified principal ("transport-bob"), rule claims "rule-principal",
	// redeemedVerifier establishes "redeemed-alice".
	const req = admissionRequest("peer-node.1", "sess-auth-1", {
		locality: "process-local",
		protection: "confidentiality-and-integrity",
		authentication: { kind: "verified", principal: "transport-bob", method: "loopback" },
	});
	const result = await ci.admission.evaluate(req, {
		redeemedAdmission: { redemptionId: "red-1", lifecycle },
	});

	assert.equal(ruleCalled, 0, "rule.apply is never called in authenticated mode");
	assert.equal(seenInputs.length, 1);
	assert.equal(seenInputs[0].redemptionId, "red-1");
	assert.equal(seenInputs[0].lifecycle, lifecycle, "exact object identity of lifecycle is preserved");
	assert.equal(seenInputs[0].remoteNodeId, "peer-node.1");

	assert.deepEqual(result, {
		decision: "allow",
		authorizationAssociation: {
			mode: "authenticated",
			issuer: "zorg-hub",
			principal: "redeemed-alice",
			instanceBinding: "peer-node.1",
		},
	});
	assert.ok(Object.isFrozen(result));
	assert.ok(Object.isFrozen(result.authorizationAssociation));
	assert.throws(() => {
		result.authorizationAssociation.principal = "mallory";
	}, TypeError);

	// SessionRecords and subsequent CI3 evidence(delivery) reflect the redeemed principal and proved: true.
	assert.deepEqual(ci.sessionPrincipal("peer-node.1", "sess-auth-1"), {
		node: "peer-node.1",
		session: "sess-auth-1",
		principal: "redeemed-alice",
		proved: true,
	});
	assert.deepEqual(ci.evidence(delivery("peer-node.1", "peer-node.1", "sess-auth-1")), {
		kind: "agp-session",
		node: "peer-node.1",
		principal: "redeemed-alice",
		proved: true,
	});

	// Refusal from redeemedVerifier does not overwrite an existing session record or create a new one.
	const denyResult = await ci.admission.evaluate(req, {
		redeemedAdmission: { redemptionId: "wrong-id", lifecycle },
	});
	assert.deepEqual(denyResult, { decision: "deny", reasonCode: "EXPECTED_NODE_MISMATCH" });
	assert.ok(Object.isFrozen(denyResult));
	assert.deepEqual(ci.sessionPrincipal("peer-node.1", "sess-auth-1"), {
		node: "peer-node.1",
		session: "sess-auth-1",
		principal: "redeemed-alice",
		proved: true,
	});
	const denyNew = await ci.admission.evaluate(admissionRequest("peer-node.2", "sess-auth-2"), {
		redeemedAdmission: { redemptionId: "wrong-id", lifecycle },
	});
	assert.deepEqual(denyNew, { decision: "deny", reasonCode: "EXPECTED_NODE_MISMATCH" });
	assert.equal(ci.sessionPrincipal("peer-node.2", "sess-auth-2"), null);
});

test("CI2, CI6, D54, D55, D10-E1: \"authenticated\" mode descriptor-safe options.redeemedAdmission reading, verifyRedeemed plain-data validation, host admission ruling composition, and shared admissionDeadlineMs", async () => {
	const clock = new ManualClock(START);
	const lifecycle = { id: 1 };
	let getterCalls = 0;
	const sym = Symbol("sym");

	// 1) Malformed options or options.redeemedAdmission denies with SECURITY_EVIDENCE without calling getters or verifyRedeemed
	let verifierCalls = 0;
	const ci = createCallerIdentity({
		mode: "authenticated",
		clock,
		redeemedVerifier: {
			verifyRedeemed() {
				verifierCalls += 1;
				return { ok: true, issuer: "zorg-hub", principal: "alice", instanceBinding: "alice.1" };
			},
		},
	});

	const badOptionsList = [
		undefined,
		null,
		"bad",
		[],
		{},
		{ redeemedAdmission: null },
		{ redeemedAdmission: "bad" },
		{ redeemedAdmission: [] },
		{
			get redeemedAdmission() {
				getterCalls += 1;
				return { redemptionId: "r1", lifecycle };
			},
		},
		{
			redeemedAdmission: {
				get redemptionId() {
					getterCalls += 1;
					return "r1";
				},
				lifecycle,
			},
		},
		{
			redeemedAdmission: {
				redemptionId: "r1",
				get lifecycle() {
					getterCalls += 1;
					return lifecycle;
				},
			},
		},
		Object.create({ redeemedAdmission: { redemptionId: "r1", lifecycle } }),
		{ redeemedAdmission: Object.create({ redemptionId: "r1", lifecycle }) },
		{ [sym]: 1, redeemedAdmission: { redemptionId: "r1", lifecycle } },
		{ redeemedAdmission: { [sym]: 1, redemptionId: "r1", lifecycle } },
		{ redeemedAdmission: { redemptionId: "r1", lifecycle, extra: 1 } },
		{ redeemedAdmission: { redemptionId: "", lifecycle } },
		{ redeemedAdmission: { redemptionId: "r".repeat(257), lifecycle } },
		{ redeemedAdmission: { redemptionId: "bad\u0000id", lifecycle } },
		{ redeemedAdmission: { redemptionId: "bad\ud800id", lifecycle } },
		{ redeemedAdmission: { redemptionId: "r1", lifecycle: null } },
		{ redeemedAdmission: { redemptionId: "r1", lifecycle: "not-an-object" } },
	];

	const revokedOuter = Proxy.revocable({ redeemedAdmission: { redemptionId: "r1", lifecycle } }, {});
	revokedOuter.revoke();
	const revokedInner = Proxy.revocable({ redemptionId: "r1", lifecycle }, {});
	revokedInner.revoke();

	const proxyOptionsList = [
		revokedOuter.proxy,
		{ redeemedAdmission: revokedInner.proxy },
		new Proxy(
			{ redeemedAdmission: { redemptionId: "r1", lifecycle } },
			{
				getPrototypeOf() {
					const err = new Error("CI2 malformed options");
					err.nested = Promise.reject(new Error("D55 option proxy nested rejection"));
					throw err;
				},
			},
		),
		{
			redeemedAdmission: new Proxy(
				{ redemptionId: "r1", lifecycle },
				{
					getOwnPropertyDescriptor() {
						throw { nested: Promise.reject(new Error("D55 redeemedAdmission proxy nested rejection")) };
					},
				},
			),
		},
	];

	const proxyEscaped = await observingUnhandledRejections(async () => {
		for (const badOpt of [...badOptionsList, ...proxyOptionsList]) {
			const res = await ci.admission.evaluate(admissionRequest("alice.1", "000001"), badOpt);
			assert.deepEqual(res, { decision: "deny", reasonCode: "SECURITY_EVIDENCE" });
			assert.ok(Object.isFrozen(res));
			assert.equal(ci.sessionPrincipal("alice.1", "000001"), null);
		}
	});
	assert.deepEqual(proxyEscaped, [], "no unhandled rejection escaped from throwing proxy options");
	assert.equal(getterCalls, 0, "no getter on options or redeemedAdmission was called");
	assert.equal(verifierCalls, 0, "verifyRedeemed was not called when options were invalid");

	// 2) verifyRedeemed throws, rejects, returns non-plain data, invalid identifiers, or { ok: false }
	const verifierOutputs = [
		[{ ok: false }, "SECURITY_EVIDENCE"],
		[{ ok: false, reasonCode: "CAPACITY" }, "CAPACITY"],
		[{ ok: false, reasonCode: "POLICY" }, "POLICY"],
		[{ ok: false, reasonCode: "EXPECTED_NODE_MISMATCH" }, "EXPECTED_NODE_MISMATCH"],
		[{ ok: false, reasonCode: "SECURITY_EVIDENCE" }, "SECURITY_EVIDENCE"],
		[{ ok: false, reasonCode: "UNKNOWN_CODE" }, "SECURITY_EVIDENCE"],
		[{ ok: false, reasonCode: "POLICY", extra: 1 }, "SECURITY_EVIDENCE"],
		[null, "SECURITY_EVIDENCE"],
		["allow", "SECURITY_EVIDENCE"],
		[{ ok: true, issuer: "agp-transport", principal: "alice", instanceBinding: "alice.1" }, "SECURITY_EVIDENCE"],
		[{ ok: true, issuer: "zorg-hub", principal: "", instanceBinding: "alice.1" }, "SECURITY_EVIDENCE"],
		[{ ok: true, issuer: "zorg-hub", principal: "alice", instanceBinding: "bad\u0000node" }, "SECURITY_EVIDENCE"],
		[{ ok: true, issuer: "zorg-hub", principal: "alice", instanceBinding: "alice.1", extra: 1 }, "SECURITY_EVIDENCE"],
		[
			{
				ok: true,
				get issuer() {
					getterCalls += 1;
					return "zorg-hub";
				},
				principal: "alice",
				instanceBinding: "alice.1",
			},
			"SECURITY_EVIDENCE",
		],
		[() => { throw new Error("verifyRedeemed sync failure"); }, "SECURITY_EVIDENCE"],
		[() => Promise.reject(new Error("verifyRedeemed async failure")), "SECURITY_EVIDENCE"],
	];

	const escaped = await observingUnhandledRejections(async () => {
		for (const [out, expectedCode] of verifierOutputs) {
			const instance = createCallerIdentity({
				mode: "authenticated",
				clock,
				redeemedVerifier: {
					verifyRedeemed: typeof out === "function" ? out : () => out,
				},
			});
			const res = await instance.admission.evaluate(admissionRequest("alice.1", "000001"), {
				redeemedAdmission: { redemptionId: "r1", lifecycle },
			});
			assert.deepEqual(res, { decision: "deny", reasonCode: expectedCode });
			assert.equal(instance.sessionPrincipal("alice.1", "000001"), null);
		}
	});
	assert.equal(getterCalls, 0);
	assert.deepEqual(escaped, []);

	// 3) Host admission ruling runs before redeemedVerifier and shares the single admissionDeadlineMs budget
	const deadlineClock = new ManualClock(START);
	let rulingGate;
	let redeemedGate;
	const gated = createCallerIdentity({
		mode: "authenticated",
		clock: deadlineClock,
		admissionDeadlineMs: 1_000,
		admission: {
			evaluate: () => new Promise((resolve) => { rulingGate = resolve; }),
		},
		redeemedVerifier: {
			verifyRedeemed: () => new Promise((resolve) => { redeemedGate = resolve; }),
		},
	});

	// 3a) Host admission denies -> redeemedVerifier is never called
	const pDeny = gated.admission.evaluate(admissionRequest("alice.1", "000001"), {
		redeemedAdmission: { redemptionId: "r1", lifecycle },
	});
	rulingGate({ decision: "deny", reasonCode: "CAPACITY" });
	assert.deepEqual(await pDeny, { decision: "deny", reasonCode: "CAPACITY" });
	assert.equal(redeemedGate, undefined);

	// 3b) Host admission takes 600ms, redeemedVerifier takes 400ms (total 1000ms === deadline) -> denied with POLICY and nothing recorded
	const pTimeout = gated.admission.evaluate(admissionRequest("alice.1", "000002"), {
		redeemedAdmission: { redemptionId: "r1", lifecycle },
	});
	deadlineClock.advanceBy(600);
	rulingGate({ decision: "allow" });
	await new Promise((resolve) => setImmediate(resolve));
	assert.equal(typeof redeemedGate, "function");
	deadlineClock.advanceBy(400);
	redeemedGate({ ok: true, issuer: "zorg-hub", principal: "alice", instanceBinding: "alice.1" });
	assert.deepEqual(await pTimeout, { decision: "deny", reasonCode: "POLICY" });
	assert.equal(gated.sessionPrincipal("alice.1", "000002"), null);

	// 3c) Host admission takes 600ms, redeemedVerifier takes 399ms (total 999ms < 1000ms) -> allowed and recorded
	const pTimely = gated.admission.evaluate(admissionRequest("alice.1", "000003"), {
		redeemedAdmission: { redemptionId: "r1", lifecycle },
	});
	deadlineClock.advanceBy(600);
	rulingGate({ decision: "allow" });
	await new Promise((resolve) => setImmediate(resolve));
	deadlineClock.advanceBy(399);
	redeemedGate({ ok: true, issuer: "zorg-hub", principal: "alice", instanceBinding: "alice.1" });
	const allowed = await pTimely;
	assert.deepEqual(allowed, {
		decision: "allow",
		authorizationAssociation: {
			mode: "authenticated",
			issuer: "zorg-hub",
			principal: "alice",
			instanceBinding: "alice.1",
		},
	});
	assert.deepEqual(gated.sessionPrincipal("alice.1", "000003"), {
		node: "alice.1",
		session: "000003",
		principal: "alice",
		proved: true,
	});
});
