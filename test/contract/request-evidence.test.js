// request-evidence - CONTRACT.md's row, through CI3 and CI4, for zorg's E18.
//
// A host using caller-identity over AGP's production in-process carrier, with the asserted node rule and the
// injected clock port and sweeps of CI2, asks for each request's evidence as it receives the request, and
// gets exactly {"kind": "agp-session", "node", "principal", "proved"}: the origin node always, and the
// principal recorded for the session it arrived on only when the origin is that session's peer. Every record
// produced under trusted-development security - the asserted node rule - has proved false, though this
// carrier's own evidence reports a verified peer; a rule claiming proof is recorded proved only for exactly the
// transport principal that evidence verified.
import assert from "node:assert/strict";
import { test } from "node:test";
import { assertedNodeRule, createCallerIdentity } from "@apnex/caller-identity";
import { ManualClock } from "../support/manual-clock.js";
import { closePeer, eventually, newFabric, request, startHost, startPeer, stopAll } from "../support/loopback-host.js";

const START = 1_000_000;
const SWEEP = 30_000;
const sweep = (k) => START + k * SWEEP;

/** Every evidence record this file's hosts produce, for CI4's check over all of them. */
const produced = [];
/** Every transport evidence AGP gave the hosts' admission ports. */
const carrierEvidence = [];

/** Asserts the whole record: exactly its four fields, in order, frozen. */
function assertRecord(actual, node, principal) {
	assert.deepEqual(Object.keys(actual), ["kind", "node", "principal", "proved"]);
	assert.deepEqual(actual, { kind: "agp-session", node, principal, proved: false });
	assert.equal(JSON.stringify(actual), JSON.stringify({ kind: "agp-session", node, principal, proved: false }));
	assert.ok(Object.isFrozen(actual));
}

async function setUp(t, { before, ...options } = {}) {
	const clock = new ManualClock(START);
	const fabric = newFabric();
	const parts = [];
	t.after(async () => {
		produced.push(...parts.flatMap((p) => p.requests ?? []).map((r) => r.evidence));
		await stopAll(...parts);
	});
	if (before !== undefined) parts.push(...await before(fabric));
	const ruling = { async evaluate(r) { carrierEvidence.push(r.peerEvidence); return { decision: "allow" }; } };
	const host = await startHost(fabric, { clock, ruling, ...options });
	parts.push(host);
	const peer = async (name, peerOptions) => {
		const node = await startPeer(fabric, name, peerOptions);
		parts.push(node);
		return node;
	};
	/** Asks for a delivery's evidence again, later, as a request naming that context would. */
	const ask = (delivery) => {
		const evidence = host.identity.evidence(delivery);
		produced.push(evidence);
		return evidence;
	};
	return { clock, fabric, host, peer, ask };
}

test("CI3, E18: a request from a well-formed node over its own session has that node and its asserted principal", async (t) => {
	const { host, peer } = await setUp(t);
	const alice = await peer("alice.5c2e9f0a1b3d4e6f");
	const { delivery, evidence } = await request(host, alice);
	assert.equal(delivery.source.originNodeId, "alice.5c2e9f0a1b3d4e6f");
	assert.equal(delivery.ingressNodeId, "alice.5c2e9f0a1b3d4e6f");
	assert.equal(delivery.ingressSessionId, await host.sessionWith("alice.5c2e9f0a1b3d4e6f"));
	assertRecord(evidence, "alice.5c2e9f0a1b3d4e6f", "alice");
});

test("CI3, E18: a request from a node whose name gives no principal has that node and a null principal", async (t) => {
	const { host, peer } = await setUp(t);
	assertRecord((await request(host, await peer("nodot"))).evidence, "nodot", null);
	assertRecord((await request(host, await peer("al_ice.5c2e9f0a1b3d4e6f"))).evidence, "al_ice.5c2e9f0a1b3d4e6f", null);
});

test("CI3, E18: a request whose origin is not the ingress node has the origin node and no principal, though the ingress session has one", async (t) => {
	const { host, peer } = await setUp(t);
	const relay = await peer("relay.77", { listen: "relay", transit: true });
	const carol = await peer("carol.1", { address: "relay", expect: "relay.77" });
	const { delivery, evidence } = await request(host, carol, {}, relay);
	assert.equal(delivery.source.originNodeId, "carol.1");
	assert.equal(delivery.ingressNodeId, "relay.77");
	assert.equal(host.identity.sessionPrincipal("relay.77", delivery.ingressSessionId).principal, "relay", "the ingress session has a principal");
	assertRecord(evidence, "carol.1", null);
	assertRecord((await request(host, relay)).evidence, "relay.77", "relay");
});

test("CI3, E18: a delivery with no ingress has the origin node and no principal", async (t) => {
	const { host, ask } = await setUp(t);
	const { delivery, evidence } = await host.localRequest({});
	assert.equal(delivery.ingressNodeId, undefined);
	assert.equal(delivery.ingressSessionId, undefined);
	assertRecord(evidence, "hub", null);
	// A context naming a recorded session's peer as origin, but no ingress, still has no principal.
	await host.identity.admission.evaluate({ localNodeId: "hub", remoteNodeId: "zed.1", localSessionId: "00ffff", remoteSessionId: "000001", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } });
	assertRecord(ask({ source: { endpoint: "e", originNodeId: "zed.1" } }), "zed.1", null);
	assertRecord(ask({ source: { endpoint: "e", originNodeId: "zed.1" }, ingressNodeId: "zed.1" }), "zed.1", null);
	assertRecord(ask({ source: { endpoint: "e", originNodeId: "zed.1" }, ingressNodeId: "zed.1", ingressSessionId: "00ffff" }), "zed.1", "zed");
});

test("CI3, E18: a request 59 seconds after its session closed has its principal; one just before the sweep that forgets the record has it, and one just after has none", async (t) => {
	const { clock, host, peer, ask } = await setUp(t);
	const alice = await peer("alice.1");
	const { delivery, evidence } = await request(host, alice);
	assertRecord(evidence, "alice.1", "alice");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, delivery.ingressSessionId);
	clock.advanceTo(sweep(1) + 1 + 59_000);
	assertRecord(ask(delivery), "alice.1", "alice");
	clock.advanceTo(sweep(4) - 1);
	assertRecord(ask(delivery), "alice.1", "alice");
	clock.advanceTo(sweep(4));
	assertRecord(ask(delivery), "alice.1", null);
});

test("CI3, E18: a request of a session established and closed between two sweeps has its principal 59 seconds after its close", async (t) => {
	let release;
	const gate = (r) => r.remoteNodeId === "dan.1" ? new Promise((resolve) => { release = resolve; }) : undefined;
	const { clock, host, peer, ask } = await setUp(t, { gate });
	clock.advanceTo(sweep(1) - 5_000);
	const dan = await peer("dan.1");
	await eventually(() => release, "caller-identity to admit dan before AGP commits the session");
	assert.equal(host.connections()[0].identityState, "pending");
	clock.advanceTo(sweep(1));
	release();
	const { delivery, evidence } = await request(host, dan);
	assertRecord(evidence, "dan.1", "dan");
	clock.advanceTo(sweep(1) + 1_000);
	await closePeer(host, dan, delivery.ingressSessionId);
	clock.advanceTo(sweep(1) + 1_000 + 59_000);
	assertRecord(ask(delivery), "dan.1", "dan");
	clock.advanceTo(sweep(4));
	assertRecord(ask(delivery), "dan.1", null);
});

test("CI3, E18: a delivery context naming as its ingress a session refused after admission, before it was established, has its principal while the record is kept and none after it is forgotten", async (t) => {
	const before = async (fabric) => [await startPeer(fabric, "erin.1", { listen: "erin", address: "nowhere" })];
	const { clock, host, ask } = await setUp(t, { before, sessionIds: ["0e0e0e"], dial: [{ address: "erin", expect: "dave.1" }] });
	await eventually(() => host.identity.sessionPrincipal("erin.1", "0e0e0e"), "caller-identity to admit erin.1");
	await eventually(() => host.connections().length === 0, "AGP to refuse the session");
	const delivery = { source: { endpoint: "from-erin-1", originNodeId: "erin.1" }, ingressNodeId: "erin.1", ingressSessionId: "0e0e0e" };
	assertRecord(ask(delivery), "erin.1", "erin");
	clock.advanceTo(sweep(3) - 1);
	assertRecord(ask(delivery), "erin.1", "erin");
	clock.advanceTo(sweep(3));
	assertRecord(ask(delivery), "erin.1", null);
});

test("CI3, E18: a reconnection's requests find the new session's record, and the old session's context finds nothing once its record is forgotten", async (t) => {
	const { clock, host, peer, ask } = await setUp(t, { sessionIds: ["000101", "000102"] });
	const first = await peer("alice.1");
	const old = await request(host, first);
	assert.equal(old.delivery.ingressSessionId, "000101");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, first, "000101");
	const second = await peer("alice.1");
	const fresh = await request(host, second);
	assert.equal(fresh.delivery.ingressSessionId, "000102");
	assertRecord(fresh.evidence, "alice.1", "alice");
	assertRecord(ask(old.delivery), "alice.1", "alice");
	clock.advanceTo(sweep(4));
	assertRecord(ask(old.delivery), "alice.1", null);
	assertRecord(ask(fresh.delivery), "alice.1", "alice");
});

test("CI3, E18: one session number on two nodes: each node's requests find its own record", async (t) => {
	const { clock, host, peer, ask } = await setUp(t, { sessionIds: ["00abcd", "00abcd"] });
	const alice = await peer("alice.1");
	const bob = await peer("bob.1");
	const fromAlice = await request(host, alice);
	const fromBob = await request(host, bob);
	assert.equal(fromAlice.delivery.ingressSessionId, "00abcd");
	assert.equal(fromBob.delivery.ingressSessionId, "00abcd");
	assertRecord(fromAlice.evidence, "alice.1", "alice");
	assertRecord(fromBob.evidence, "bob.1", "bob");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, "00abcd");
	clock.advanceTo(sweep(4));
	assertRecord(ask(fromAlice.delivery), "alice.1", null);
	assertRecord(ask(fromBob.delivery), "bob.1", "bob");
});

// CI4 over the carrier, with rules that claim proof. These records are not trusted-development security's,
// so they stay out of `produced`.

/** Asserts the whole record with the certainty given. */
function assertCertainty(actual, node, principal, proved) {
	assert.deepEqual(Object.keys(actual), ["kind", "node", "principal", "proved"]);
	assert.deepEqual(actual, { kind: "agp-session", node, principal, proved });
	assert.ok(Object.isFrozen(actual));
}

/** A host whose rule claims proof, and the transport evidence AGP gave its admission port, by peer node. */
async function claimingHost(t, rule, options = {}) {
	const fabric = newFabric();
	const evidenceOf = new Map();
	const ruling = { async evaluate(r) { evidenceOf.set(r.remoteNodeId, r.peerEvidence); return { decision: "allow" }; } };
	const host = await startHost(fabric, { clock: new ManualClock(START), rule, ruling, ...options });
	const parts = [host];
	t.after(() => stopAll(...parts));
	const peer = async (name) => {
		const node = await startPeer(fabric, name);
		parts.push(node);
		return node;
	};
	return { host, peer, evidenceOf };
}

test("CI4, E18: over the in-process carrier, a rule claiming proof for exactly the transport principal AGP's evidence verified is recorded proved; claiming it for another name, a derived one included, is recorded asserted", async (t) => {
	const claims = {
		"same.1": (verified) => verified,
		"alice.1": () => "alice",
		"derived.1": (verified) => `${verified}-derived`,
		"upper.1": (verified) => verified.toUpperCase(),
	};
	const rule = { apply: (r) => ({ principal: claims[r.remoteNodeId](r.peerEvidence.authentication.principal), proved: true }) };
	const { host, peer, evidenceOf } = await claimingHost(t, rule);
	for (const [name, claim] of Object.entries(claims)) {
		const node = await peer(name);
		const { delivery, evidence } = await request(host, node);
		const authentication = evidenceOf.get(name).authentication;
		assert.equal(authentication.kind, "verified", "the carrier's evidence verifies a transport principal");
		assert.match(authentication.principal, /^t-\d+$/);
		const principal = claim(authentication.principal);
		const proved = name === "same.1";
		assertCertainty(evidence, name, principal, proved);
		assert.deepEqual(host.identity.sessionPrincipal(name, delivery.ingressSessionId), { node: name, session: delivery.ingressSessionId, principal, proved });
	}
});

/** The principal and certainty of an evidence record, as a session record gives them. */
const pick = ({ principal, proved }) => ({ principal, proved });

test("CI1, CI4, E18, D2-E3, D54: a rule whose result's principal or proved is a getter is refused as non-plain data without calling the getter, and nothing is recorded", async (t) => {
	// Under D54, a getter on a rule's result is never called and refuses the session outright.
	const reads = new Map();
	const getter = (name, first, later) => ({
		get principal() { const n = (reads.get(name) ?? 0) + 1; reads.set(name, n); return n === 1 ? first : later; },
		proved: true,
	});
	const results = {
		"late.1": (verified) => getter("late.1", "alice", verified),
		"early.1": (verified) => getter("early.1", verified, "alice"),
		// Ordinary controls: a plain result claiming proof for the verified principal, and for another name.
		"same.1": (verified) => ({ principal: verified, proved: true }),
		"other.1": () => ({ principal: "other", proved: true }),
	};
	const rule = { apply: (r) => results[r.remoteNodeId](r.peerEvidence.authentication.principal) };
	const { host, peer, evidenceOf } = await claimingHost(t, rule);
	for (const name of ["late.1", "early.1"]) {
		await peer(name);
		await eventually(() => !host.connections().some((c) => c.remoteNodeId === name), `${name} refused`);
	}
	assert.equal(reads.get("late.1"), undefined, "the getter is never called");
	assert.equal(reads.get("early.1"), undefined, "the getter is never called");
	const recorded = {};
	for (const name of ["same.1", "other.1"]) {
		const { delivery, evidence } = await request(host, await peer(name));
		const authentication = evidenceOf.get(name).authentication;
		assert.equal(authentication.kind, "verified");
		assert.match(authentication.principal, /^t-\d+$/);
		assert.deepEqual(host.identity.sessionPrincipal(name, delivery.ingressSessionId), { node: name, session: delivery.ingressSessionId, ...pick(evidence) });
		if (evidence.proved) assert.equal(evidence.principal, authentication.principal, `${name}: proved only for the verified principal`);
		recorded[name] = { verified: authentication.principal, evidence };
	}
	assertCertainty(recorded["same.1"].evidence, "same.1", recorded["same.1"].verified, true);
	assertCertainty(recorded["other.1"].evidence, "other.1", "other", false);
});

test("CI1, D2-E3, D54: a rule's result whose principal or proved is a getter, or is non-plain data, refuses the session with zero getter invocations, and nothing is recorded", async () => {
	const admission = { localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: "000001", remoteSessionId: "000002", direction: "inbound", peerEvidence: { locality: "process-local", protection: "none", authentication: { kind: "verified", principal: "alice" } } };
	let calls = 0;
	const failing = [
		{ get principal() { calls++; throw new Error("principal unreadable"); }, proved: true },
		{ principal: "alice", get proved() { calls++; throw new Error("proved unreadable"); } },
		Object.create({ principal: "alice", proved: true }),
		{ principal: "alice", proved: true, extra: 1 },
	];
	for (const result of failing) {
		const identity = createCallerIdentity({ rule: { apply: () => result }, clock: new ManualClock(START) });
		await assert.rejects(identity.admission.evaluate(admission), /plain data/);
		assert.equal(identity.sessionPrincipal("alice.1", "000001"), null);
	}
	assert.equal(calls, 0, "no getter on a rule's result was called");
});

test("CI4, E18: over a session whose evidence reports no authentication, a rule claiming proof is recorded asserted", async (t) => {
	const none = Object.freeze({ locality: "network", protection: "none", authentication: Object.freeze({ kind: "none" }) });
	const rule = { apply: (r) => ({ principal: r.remoteNodeId.split(".")[0], proved: true }) };
	const { host, peer, evidenceOf } = await claimingHost(t, rule, { peerEvidence: none });
	const { delivery, evidence } = await request(host, await peer("alice.1"));
	assert.deepEqual(evidenceOf.get("alice.1"), none, "AGP gave the admission port evidence with no authentication");
	assertCertainty(evidence, "alice.1", "alice", false);
	assert.equal(host.identity.sessionPrincipal("alice.1", delivery.ingressSessionId).proved, false);
});

test("CI4: a rule cannot make a principal proved over evidence that proved nothing; the kind names what produced the record", async () => {
	const clock = new ManualClock(START);
	const claiming = { apply: (r) => ({ principal: r.remoteNodeId.split(".")[0], proved: true }) };
	const identity = createCallerIdentity({ rule: claiming, clock });
	const trustedDevelopment = { locality: "network", protection: "none", authentication: { kind: "none" } };
	await identity.admission.evaluate({ localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: "000001", remoteSessionId: "000002", direction: "inbound", peerEvidence: trustedDevelopment });
	const evidence = identity.evidence({ source: { endpoint: "e", originNodeId: "alice.1" }, ingressNodeId: "alice.1", ingressSessionId: "000001" });
	produced.push(evidence);
	assertRecord(evidence, "alice.1", "alice");
	assert.equal(identity.sessionPrincipal("alice.1", "000001").proved, false);
	// The asserted node rule never claims proof, whatever the carrier says.
	const asserted = createCallerIdentity({ rule: assertedNodeRule, clock });
	const verified = { locality: "process-local", protection: "confidentiality-and-integrity", authentication: { kind: "verified", principal: "alice.1", method: "process-capability" } };
	await asserted.admission.evaluate({ localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: "000001", remoteSessionId: "000002", direction: "inbound", peerEvidence: verified });
	const overVerified = asserted.evidence({ source: { endpoint: "e", originNodeId: "alice.1" }, ingressNodeId: "alice.1", ingressSessionId: "000001" });
	produced.push(overVerified);
	assertRecord(overVerified, "alice.1", "alice");
});

test("CI4, E18: every record produced under trusted-development security, over the carrier's verified evidence, has proved false", () => {
	assert.ok(produced.length >= 30, `the file produced ${produced.length} records`);
	const carrier = carrierEvidence.filter((e) => e.locality === "process-local");
	assert.ok(carrier.length >= 10 && carrier.every((e) => e.authentication.kind === "verified"), "the carrier's own evidence reports a verified peer");
	for (const evidence of produced) {
		assert.equal(evidence.kind, "agp-session");
		assert.equal(evidence.proved, false, JSON.stringify(evidence));
	}
	assert.ok(produced.some((e) => e.principal !== null), "some records carry a principal, asserted");
});
