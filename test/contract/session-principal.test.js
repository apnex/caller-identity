// session-principal - CONTRACT.md's row, through CI1 and CI2, for zorg's E18.
//
// A host using caller-identity over AGP's production in-process carrier (@agp/transport-loopback), applying
// the asserted node rule to each peer's node name whatever that carrier's own evidence says, records for each
// admitted session the asserted principal the rule gives, keyed by the peer's node and the host node's own
// session identifier, and forgets it by sweeping AGP's connection snapshot every 30 seconds by an injected
// clock port, never sooner than 60 seconds after the session closed. A rule that fails refuses its session; a
// host ruling that never answers is denied at the admission deadline, so AGP releases its connection; and a
// snapshot that cannot be read changes no record and is reported to the host's diagnostic port.
import assert from "node:assert/strict";
import { test } from "node:test";
import { assertedNodeRule, createCallerIdentity } from "@apnex/caller-identity";
import { ManualClock } from "../support/manual-clock.js";
import {
	closePeer, eventually, newFabric, openSilentConnection, present, request, startHost, startPeer, stopAll,
} from "../support/loopback-host.js";

const START = 1_000_000;
const SWEEP = 30_000;
/** The time of the k-th sweep after the host started, when every sweep runs on time. */
const sweep = (k) => START + k * SWEEP;
const record = (node, session, principal) => ({ node, session, principal, proved: false });

/** A host on a fresh fabric, with a manual clock at START, stopped after the test. */
async function setUp(t, { before, start = START, ...options } = {}) {
	const clock = new ManualClock(start);
	const fabric = newFabric();
	const parts = [];
	t.after(() => stopAll(...parts));
	if (before !== undefined) parts.push(...await before(fabric));
	const host = await startHost(fabric, { clock, ...options });
	parts.push(host);
	const peer = async (name, peerOptions) => {
		const node = await startPeer(fabric, name, peerOptions);
		parts.push(node);
		return node;
	};
	return { clock, fabric, host, peer, parts };
}

// CI1 - the asserted node rule.

test("CI1: the asserted node rule gives the node name up to its first dot, asserted, and none for a name with no dot or a first part that breaks the pattern", () => {
	const verified = Object.freeze({ locality: "process-local", protection: "confidentiality-and-integrity", authentication: { kind: "verified", principal: "x", method: "m" } });
	const apply = (remoteNodeId) => assertedNodeRule.apply({ localNodeId: "hub", remoteNodeId, localSessionId: "000001", remoteSessionId: "000002", direction: "inbound", peerEvidence: verified });
	assert.deepEqual(apply("alice.5c2e9f0a1b3d4e6f"), { principal: "alice", proved: false });
	assert.equal(apply("alice"), null, "no dot");
	assert.equal(apply("Alice.5c2e"), null, "upper case breaks the pattern");
	assert.equal(apply("-alice.5c2e"), null, "a leading hyphen breaks the pattern");
	assert.equal(apply(".5c2e"), null, "an empty first part breaks the pattern");
	assert.equal(apply("al_ice.5c2e"), null, "an underscore breaks the pattern");
	assert.equal(apply(`${"a".repeat(64)}.5c2e`), null, "64 characters break the pattern");
	assert.deepEqual(apply(`${"a".repeat(63)}.5c2e`), { principal: "a".repeat(63), proved: false }, "63 characters fit");
	assert.deepEqual(apply("bob.dev.5c2e9f0a"), { principal: "bob", proved: false }, "several dots: up to the first");
	assert.deepEqual(apply("0-a.x"), { principal: "0-a", proved: false });
	assert.deepEqual(apply("alice."), { principal: "alice", proved: false }, "a dot with nothing after it");
});

for (const [name, principal, what] of [
	["alice.5c2e9f0a1b3d4e6f", "alice", "a name with a dot"],
	["alice", null, "a name with no dot"],
	["al_ice.5c2e9f0a1b3d4e6f", null, "a name whose first part breaks the pattern"],
	[`${"a".repeat(64)}.5c2e9f0a1b3d4e6f`, null, "a name whose first part is longer than the pattern allows"],
	["bob.dev.5c2e9f0a1b3d4e6f", "bob", "a name with several dots"],
]) {
	test(`CI1, E18: over the in-process carrier, whose evidence is a verified peer, ${what} gives ${principal === null ? "no principal" : `the asserted principal ${principal}`}`, async (t) => {
		const seen = [];
		const ruling = { async evaluate(request) { seen.push(request); return { decision: "allow" }; } };
		const { host, peer } = await setUp(t, { ruling });
		// AGP's own node names are lower case, so a first part breaking the pattern is one AGP accepts.
		const node = await peer(name);
		const session = await host.sessionWith(name);
		const request = seen.find((r) => r.remoteNodeId === name);
		assert.equal(request.localSessionId, session, "the record's key is the host node's own session identifier");
		assert.equal(request.peerEvidence.authentication.kind, "verified", "the carrier reports a verified peer");
		assert.equal(request.peerEvidence.locality, "process-local");
		assert.deepEqual(host.identity.sessionPrincipal(name, session), record(name, session, principal));
		assert.equal(node.nodeId, name);
	});
}

// CI1 - a rule that fails refuses the session.

for (const [what, apply] of [
	["throws", () => { throw new Error("the rule failed"); }],
	["returns undefined, a malformed result", () => undefined],
	["returns a string, a malformed result", () => "alice"],
	["returns a principal that is not a string, a malformed result", () => ({ principal: 7, proved: false })],
	["returns a certainty that is not a boolean, a malformed result", () => ({ principal: "alice", proved: "no" })],
	["returns a promise", async () => ({ principal: "alice", proved: false })],
]) {
	test(`CI1, E18: over the in-process carrier, a rule that ${what} refuses the session: AGP refuses it and nothing is recorded`, async (t) => {
		let applied = 0;
		const rule = { apply: (request) => { applied += 1; return apply(request); } };
		const { host, peer } = await setUp(t, { rule, sessionIds: ["00f00d"] });
		await peer("alice.1");
		const refusal = await host.refused("00f00d");
		assert.equal(applied, 1, "the rule was asked once");
		assert.equal(refusal.data.direction, "inbound");
		assert.equal(refusal.data.reason, "INTERNAL_ERROR", "AGP refuses a session whose admission faulted");
		assert.equal(host.connections().length, 0, "AGP holds no connection for it");
		assert.equal(host.identity.sessionPrincipal("alice.1", "00f00d"), null, "nothing is recorded");
	});
}

/** Runs `body` with a process-level observer of unhandled rejections, removed after; returns what it saw. */
async function observingUnhandledRejections(body) {
	const escaped = [];
	const observe = (reason) => { escaped.push(reason); };
	process.on("unhandledRejection", observe);
	try {
		await body();
		// Node reports an unhandled rejection once the microtasks after it have run; give it a turn of timers.
		await new Promise((resolve) => setTimeout(resolve, 50));
	} finally {
		process.off("unhandledRejection", observe);
	}
	return escaped;
}

for (const when of ["at once", "later"]) {
	test(`CI1, E18: over the in-process carrier, a rule that returns a promise rejecting ${when} refuses the session, nothing is recorded, no rejection escapes, and the host serves the next peer`, async (t) => {
		let rejectLater;
		const rule = {
			apply(request) {
				if (request.remoteNodeId !== "alice.1") return assertedNodeRule.apply(request);
				if (when === "at once") return Promise.reject(new Error("the rule's promise rejected at once"));
				return new Promise((_, reject) => { rejectLater = () => reject(new Error("the rule's promise rejected later")); });
			},
		};
		const { host, peer } = await setUp(t, { rule, sessionIds: ["00f00d", "00f00e"] });
		const escaped = await observingUnhandledRejections(async () => {
			await peer("alice.1");
			const refusal = await host.refused("00f00d");
			assert.equal(refusal.data.reason, "INTERNAL_ERROR", "AGP refuses a session whose admission faulted");
			assert.equal(host.connections().length, 0, "AGP holds no connection for it");
			assert.equal(host.identity.sessionPrincipal("alice.1", "00f00d"), null, "nothing is recorded");
			if (when === "later") {
				assert.equal(typeof rejectLater, "function", "the promise is still unsettled after the refusal");
				rejectLater();
			}
		});
		assert.deepEqual(escaped, [], "no rejection escapes to the host's runtime");
		assert.equal(host.identity.sessionPrincipal("alice.1", "00f00d"), null, "the rejection records nothing");
		const bob = await peer("bob.1");
		assert.equal(await host.sessionWith("bob.1"), "00f00e");
		const served = await request(host, bob, { after: when });
		assert.deepEqual(served.payload, { after: when });
		assert.deepEqual(served.evidence, { kind: "agp-session", node: "bob.1", principal: "bob", proved: false }, "the host serves the next peer");
	});
}

// CI2 - admitting a session.

test("CI2, E18: an admitted session's record holds its asserted principal, keyed by peer node and the host's session identifier, and stays while the session is open", async (t) => {
	const { clock, host, peer } = await setUp(t);
	await peer("alice.5c2e9f0a1b3d4e6f");
	const session = await host.sessionWith("alice.5c2e9f0a1b3d4e6f");
	assert.deepEqual(host.identity.sessionPrincipal("alice.5c2e9f0a1b3d4e6f", session), record("alice.5c2e9f0a1b3d4e6f", session, "alice"));
	assert.equal(host.identity.sessionPrincipal("alice.5c2e9f0a1b3d4e6f", "ffffff"), null, "another session identifier has no record");
	assert.equal(host.identity.sessionPrincipal("bob.5c2e9f0a1b3d4e6f", session), null, "another node has no record");
	clock.advanceTo(sweep(20));
	assert.deepEqual(host.identity.sessionPrincipal("alice.5c2e9f0a1b3d4e6f", session), record("alice.5c2e9f0a1b3d4e6f", session, "alice"), "kept across ten minutes of sweeps while open");
});

test("CI2: every peer is admitted unless the host gives an admission ruling; a session the ruling refuses has no record", async (t) => {
	const ruling = { async evaluate(request) { return request.remoteNodeId.startsWith("mallory.") ? { decision: "deny", reasonCode: "POLICY" } : { decision: "allow" }; } };
	const { host, peer } = await setUp(t, { ruling, sessionIds: ["0000a1", "0000a2"] });
	await peer("alice.1");
	await peer("mallory.1");
	assert.deepEqual(host.identity.sessionPrincipal("alice.1", await host.sessionWith("alice.1")), record("alice.1", "0000a1", "alice"));
	await eventually(() => !present(host, "mallory.1", "0000a2"), "the hub to refuse mallory");
	assert.equal(host.identity.sessionPrincipal("mallory.1", "0000a2"), null);
});

test("CI2: the host starts the sweeping with its node and stops it with the node; records stay readable after the stop", async (t) => {
	const clock = new ManualClock(START);
	const identity = createCallerIdentity({ rule: assertedNodeRule, clock });
	let reads = 0;
	const source = { connections: () => { reads += 1; return { items: [] }; } };
	await identity.admission.evaluate({ localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: "000001", remoteSessionId: "000009", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } });
	clock.advanceBy(10 * SWEEP);
	assert.equal(reads, 0, "no sweep runs before the host starts it");
	identity.start(source);
	assert.throws(() => identity.start(source), /already sweeping/);
	clock.advanceBy(SWEEP - 1);
	assert.equal(reads, 0, "the first sweep is 30 seconds after the start");
	clock.advanceBy(1);
	assert.equal(reads, 1);
	clock.advanceBy(SWEEP);
	assert.equal(reads, 2, "every 30 seconds by the clock");
	identity.stop();
	assert.deepEqual(clock.pending(), [], "stopping cancels the next sweep");
	clock.advanceBy(10 * SWEEP);
	assert.equal(reads, 2, "no sweep runs after the stop");
	assert.deepEqual(identity.sessionPrincipal("alice.1", "000001"), record("alice.1", "000001", "alice"), "absence noted at one sweep forgets nothing");
	identity.start(source);
	clock.advanceBy(3 * SWEEP);
	assert.equal(identity.sessionPrincipal("alice.1", "000001"), null, "started again, the sweeps forget it");
});

test("CI2: by default the clock is performance.now() and its timer, and a sweep never runs before 30 seconds have passed by the clock", async () => {
	const identity = createCallerIdentity({ rule: assertedNodeRule });
	let reads = 0;
	identity.start({ connections: () => { reads += 1; return { items: [] }; } });
	identity.stop();
	assert.equal(reads, 0);
	// A scheduler that fires early by the clock is made to wait for the clock.
	const clock = new ManualClock(START);
	const early = { now: () => clock.now(), schedule: (delay, run) => clock.schedule(delay > 10_000 ? delay - 10_000 : delay, run) };
	const timed = createCallerIdentity({ rule: assertedNodeRule, clock: early });
	timed.start({ connections: () => { reads += 1; return { items: [] }; } });
	clock.advanceTo(START + SWEEP - 1);
	assert.equal(reads, 0, "fired early, it reschedules for the rest");
	clock.advanceTo(START + SWEEP);
	assert.equal(reads, 1);
	timed.stop();
});

// CI2 - forgetting a session, by sweeping.

const found = (host, node, session, principal = node.slice(0, node.indexOf("."))) =>
	assert.deepEqual(host.identity.sessionPrincipal(node, session), record(node, session, principal), `${node} ${session} is found`);
const gone = (host, node, session) =>
	assert.equal(host.identity.sessionPrincipal(node, session), null, `${node} ${session} is forgotten`);

test("CI2, E18: a session closed 1 millisecond after a sweep is found 59 seconds after the close, and is gone after the sweep 90 seconds after the last sweep that found it", async (t) => {
	const { clock, host, peer } = await setUp(t);
	const alice = await peer("alice.1");
	const session = await host.sessionWith("alice.1");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, session);
	clock.advanceTo(sweep(1) + 1 + 59_000);
	found(host, "alice.1", session);
	clock.advanceTo(sweep(4) - 1);
	found(host, "alice.1", session);
	clock.advanceTo(sweep(4));
	gone(host, "alice.1", session);
});

test("CI2, E18: a session closed at the instant of a sweep is found until 60 seconds after its close when that sweep finds it absent, and until the sweep 90 seconds later when it still finds it", async (t) => {
	const { clock, host, peer } = await setUp(t, { sessionIds: ["000a01", "000a02"] });
	const alice = await peer("alice.1");
	const bob = await peer("bob.1");
	clock.advanceTo(sweep(2) - 1);
	// The close lands before the sweep of the same instant runs.
	clock.setTime(sweep(2));
	await closePeer(host, alice, "000a01");
	clock.runDue();
	clock.advanceTo(sweep(2) + 59_999);
	found(host, "alice.1", "000a01");
	clock.advanceTo(sweep(4));
	gone(host, "alice.1", "000a01");
	// The sweep of the instant runs before the close lands.
	clock.advanceTo(sweep(5));
	await closePeer(host, bob, "000a02");
	clock.advanceTo(sweep(8) - 1);
	found(host, "bob.1", "000a02");
	clock.advanceTo(sweep(8));
	gone(host, "bob.1", "000a02");
});

test("CI2, E18: a session admitted while pending at a sweep, and established and closed between that sweep and the next, is still found 59 seconds after its close", async (t) => {
	let release;
	const gate = (request) => request.remoteNodeId === "dan.1" ? new Promise((resolve) => { release = resolve; }) : undefined;
	const { clock, host, peer } = await setUp(t, { gate });
	clock.advanceTo(sweep(1) - 5_000);
	const dan = await peer("dan.1");
	await eventually(() => release, "caller-identity to admit dan before AGP commits the session");
	const pending = host.connections();
	assert.equal(pending.length, 1);
	assert.equal(pending[0].identityState, "pending", "AGP has not committed the session");
	const session = pending[0].localSessionId;
	found(host, "dan.1", session);
	clock.advanceTo(sweep(1));
	release();
	assert.equal(await host.sessionWith("dan.1"), session);
	clock.advanceTo(sweep(1) + 1_000);
	await closePeer(host, dan, session);
	clock.advanceTo(sweep(1) + 1_000 + 59_000);
	found(host, "dan.1", session);
	clock.advanceTo(sweep(4) - 1);
	found(host, "dan.1", session);
	clock.advanceTo(sweep(4));
	gone(host, "dan.1", session);
});

test("CI2, E18: a sweep run 10 seconds late keeps a record 10 seconds longer, and nothing keeps it shorter", async (t) => {
	const { clock, host, peer } = await setUp(t);
	const alice = await peer("alice.1");
	const session = await host.sessionWith("alice.1");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, session);
	clock.advanceTo(sweep(2) - 1);
	clock.setTime(sweep(2) + 10_000);
	clock.runDue();
	assert.deepEqual(clock.pending(), [sweep(3) + 10_000], "the next sweep is 30 seconds after the late one");
	clock.advanceTo(sweep(4));
	found(host, "alice.1", session);
	clock.advanceTo(sweep(4) + 10_000 - 1);
	found(host, "alice.1", session);
	clock.advanceTo(sweep(4) + 10_000);
	gone(host, "alice.1", session);
});

test("CI2: the first sweep at least 60 seconds after absence was first seen forgets the record; a sweep 59 seconds after it keeps the record", async (t) => {
	const { clock, host, peer } = await setUp(t);
	const alice = await peer("alice.1");
	const session = await host.sessionWith("alice.1");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, session);
	clock.advanceTo(sweep(2));
	const firstAbsent = sweep(2);
	clock.setTime(firstAbsent + 59_000);
	clock.runDue();
	found(host, "alice.1", session);
	clock.advanceTo(firstAbsent + 59_000 + SWEEP - 1);
	found(host, "alice.1", session);
	clock.advanceTo(firstAbsent + 59_000 + SWEEP);
	gone(host, "alice.1", session);
});

test("CI2, E18: another peer's pending connection with the same session identifier keeps the record until AGP's opening time-out ends it", async (t) => {
	const { clock, fabric, host, peer } = await setUp(t, { sessionIds: ["00c0de", "00c0de"], openTimeoutMs: 1_500 });
	const alice = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "00c0de");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, "00c0de");
	const channel = await openSilentConnection(fabric);
	t.after(() => channel.abort({ kind: "forced-stop", code: "test-done" }));
	await eventually(() => host.connections().some((c) => c.identityState === "pending" && c.localSessionId === "00c0de"), "the silent connection pending under 00c0de");
	clock.advanceTo(sweep(5));
	assert.ok(host.connections().some((c) => c.identityState === "pending" && c.localSessionId === "00c0de"), "still pending through four sweeps");
	found(host, "alice.1", "00c0de");
	await eventually(() => !present(host, "alice.1", "00c0de"), "AGP's opening time-out to end the pending connection");
	clock.advanceTo(sweep(6));
	clock.advanceTo(sweep(8) - 1);
	found(host, "alice.1", "00c0de");
	clock.advanceTo(sweep(8));
	gone(host, "alice.1", "00c0de");
});

test("CI2, E18: a session refused after admission, before it was established, is forgotten the same way, from the moment it was admitted", async (t) => {
	// The hub dials a node it expects to be dave.1; erin.1 answers, caller-identity admits it, and AGP then refuses it.
	const before = async (fabric) => [await startPeer(fabric, "erin.1", { listen: "erin", address: "nowhere" })];
	const { clock, host } = await setUp(t, { before, sessionIds: ["0e0e0e"], dial: [{ address: "erin", expect: "dave.1" }] });
	await eventually(() => host.identity.sessionPrincipal("erin.1", "0e0e0e"), "caller-identity to admit erin.1");
	await eventually(() => host.connections().length === 0, "AGP to refuse the session");
	found(host, "erin.1", "0e0e0e");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(3) - 1);
	found(host, "erin.1", "0e0e0e");
	clock.advanceTo(sweep(3));
	gone(host, "erin.1", "0e0e0e");
});

test("CI2, E18: a reconnection under a new session has a record of its own, and the old session's record is forgotten as its own", async (t) => {
	const { clock, host, peer } = await setUp(t, { sessionIds: ["000101", "000102"] });
	const first = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "000101");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, first, "000101");
	await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "000102");
	found(host, "alice.1", "000101");
	found(host, "alice.1", "000102");
	clock.advanceTo(sweep(4));
	gone(host, "alice.1", "000101");
	found(host, "alice.1", "000102");
});

test("CI2, E18: one session number used by two nodes gives each its own record, kept and forgotten on its own", async (t) => {
	const { clock, host, peer } = await setUp(t, { sessionIds: ["00abcd", "00abcd"] });
	const alice = await peer("alice.1");
	await peer("bob.1");
	assert.equal(await host.sessionWith("alice.1"), "00abcd");
	assert.equal(await host.sessionWith("bob.1"), "00abcd");
	found(host, "alice.1", "00abcd");
	found(host, "bob.1", "00abcd");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, "00abcd");
	clock.advanceTo(sweep(4));
	gone(host, "alice.1", "00abcd");
	found(host, "bob.1", "00abcd");
});

test("CI2, E18: a key admitted again replaces its record, with the time of its new admission and no absence noted", async (t) => {
	const { clock, host, peer } = await setUp(t, { sessionIds: ["00beef", "00beef"] });
	const first = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "00beef");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, first, "00beef");
	clock.advanceTo(sweep(2));
	// Absence of the first session was noted at sweep 2; the same key is admitted again 10 seconds later.
	clock.advanceTo(sweep(2) + 10_000);
	const second = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "00beef");
	clock.advanceTo(sweep(2) + 11_000);
	await closePeer(host, second, "00beef");
	clock.advanceTo(sweep(4));
	found(host, "alice.1", "00beef");
	clock.advanceTo(sweep(5) - 1);
	found(host, "alice.1", "00beef");
	clock.advanceTo(sweep(5));
	gone(host, "alice.1", "00beef");
});

test("CI2, E18: a key admitted again replaces its record's principal and its certainty, both changed, from proved to asserted and back", async (t) => {
	// Over the carrier, whose evidence verifies the peer's transport name: the first and third admissions claim
	// proof for that verified principal itself, so are proved (CI4); the second gives the asserted node rule's.
	let admissions = 0;
	const verified = [];
	const rule = {
		apply(request) {
			admissions += 1;
			verified.push(request.peerEvidence.authentication.principal);
			return admissions === 2 ? assertedNodeRule.apply(request) : { principal: request.peerEvidence.authentication.principal, proved: true };
		},
	};
	const { host, peer } = await setUp(t, { rule, sessionIds: ["00beef", "00beef", "00beef"] });
	const held = () => host.identity.sessionPrincipal("alice.1", "00beef");
	const first = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "00beef");
	assert.match(verified[0], /^t-\d+$/, "the carrier verifies a transport principal");
	assert.deepEqual(held(), { node: "alice.1", session: "00beef", principal: verified[0], proved: true });
	await closePeer(host, first, "00beef");
	const second = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "00beef");
	assert.deepEqual(held(), { node: "alice.1", session: "00beef", principal: "alice", proved: false }, "principal and certainty both replaced");
	await closePeer(host, second, "00beef");
	await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "00beef");
	assert.notEqual(verified[2], verified[0], "a new transport, a new verified principal");
	assert.deepEqual(held(), { node: "alice.1", session: "00beef", principal: verified[2], proved: true }, "replaced again, proved again");
});

/**
 * A host whose ruling holds bob.1's admission until the test denies it, so bob's connection stays pending,
 * under the session identifier alice.1's closed session had, for exactly as long as the test chooses.
 */
async function setUpCollision(t) {
	let deny;
	let entered = false;
	const ruling = {
		evaluate(request) {
			if (request.remoteNodeId !== "bob.1") return Promise.resolve({ decision: "allow" });
			entered = true;
			return new Promise((resolve) => { deny = () => resolve({ decision: "deny", reasonCode: "POLICY" }); });
		},
	};
	const parts = await setUp(t, { ruling, sessionIds: ["00d00d", "00d00d"], openTimeoutMs: 2_000, admissionDeadlineMs: 2_000 });
	t.after(() => deny?.());
	const alice = await parts.peer("alice.1");
	assert.equal(await parts.host.sessionWith("alice.1"), "00d00d");
	/** Bob's connection, pending under 00d00d from now until `end()` denies it and AGP drops it. */
	const collide = async () => {
		await parts.peer("bob.1");
		await eventually(() => entered, "bob's admission to reach the host's ruling");
		const entries = parts.host.connections();
		assert.equal(entries.length, 1, "only bob's connection is held");
		assert.equal(entries[0].identityState, "pending");
		assert.equal(entries[0].localSessionId, "00d00d", "bob is pending under alice's old session identifier");
		return async () => {
			deny();
			await eventually(() => parts.host.connections().length === 0, "AGP to drop bob's denied connection");
			assert.equal(parts.host.identity.sessionPrincipal("bob.1", "00d00d"), null, "a denied session is not recorded");
		};
	};
	return { ...parts, alice, collide };
}

test("CI2, E18: another peer pending with a closed session's identifier only after that session's absence was noted changes nothing: the record is forgotten 60 seconds after absence was first noted", async (t) => {
	// The verifier's Q9: alice closes at sweep 1 + 1 ms, absence is noted at sweep 2, and bob is pending
	// under the same identifier from 1 ms before sweep 3 to 1 ms after it.
	const { clock, host, alice, collide } = await setUpCollision(t);
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, "00d00d");
	clock.advanceTo(sweep(2));
	clock.advanceTo(sweep(3) - 1);
	const end = await collide();
	clock.advanceTo(sweep(3));
	clock.advanceTo(sweep(3) + 1);
	await end();
	clock.advanceTo(sweep(4) - 1);
	found(host, "alice.1", "00d00d");
	clock.advanceTo(sweep(4));
	gone(host, "alice.1", "00d00d");
});

test("CI2, E18: another peer pending with a closed session's identifier at the sweep right after the close delays the noting of absence to the next sweep", async (t) => {
	// Alice closes at sweep 1 + 1 ms; bob is pending under the same identifier from 1 ms before sweep 2 to
	// 1 ms after it, so sweep 2 finds the identifier present and absence is first noted at sweep 3.
	const { clock, host, alice, collide } = await setUpCollision(t);
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, "00d00d");
	clock.advanceTo(sweep(2) - 1);
	const end = await collide();
	clock.advanceTo(sweep(2));
	clock.advanceTo(sweep(2) + 1);
	await end();
	clock.advanceTo(sweep(4));
	found(host, "alice.1", "00d00d", "alice");
	clock.advanceTo(sweep(5) - 1);
	found(host, "alice.1", "00d00d");
	clock.advanceTo(sweep(5));
	gone(host, "alice.1", "00d00d");
});

test("CI2: once absence is noted, no matching entry clears it, pending or admitted; before it is noted, either counts as presence", async () => {
	const clock = new ManualClock(START);
	let items = [];
	const identity = createCallerIdentity({ rule: assertedNodeRule, clock });
	const request = (node, session) => ({ localNodeId: "hub", remoteNodeId: node, localSessionId: session, remoteSessionId: "000009", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } });
	const pending = (session) => ({ identityState: "pending", localSessionId: session });
	const admitted = (node, session) => ({ identityState: "admitted", remoteNodeId: node, sessionId: session });
	await identity.admission.evaluate(request("alice.1", "000001"));
	await identity.admission.evaluate(request("carol.1", "000002"));
	identity.start({ connections: () => ({ items }) });
	const held = (node, session) => identity.sessionPrincipal(node, session) !== null;
	// Sweep 1 finds both sessions present, one through a pending entry and one admitted.
	items = [pending("000001"), admitted("carol.1", "000002")];
	clock.advanceTo(sweep(1));
	// Sweep 2 finds both absent: absence is noted for both.
	items = [];
	clock.advanceTo(sweep(2));
	// Sweeps 3 and 4 find matching entries again; neither clears the noted absence.
	items = [pending("000001"), admitted("carol.1", "000002")];
	clock.advanceTo(sweep(3));
	assert.ok(held("alice.1", "000001") && held("carol.1", "000002"), "sweep 1 counted both as present, so absence was first noted at sweep 2, 30 seconds ago");
	clock.advanceTo(sweep(4) - 1);
	assert.ok(held("alice.1", "000001") && held("carol.1", "000002"));
	clock.advanceTo(sweep(4));
	assert.equal(identity.sessionPrincipal("alice.1", "000001"), null, "a pending match after noted absence is not its session");
	assert.equal(identity.sessionPrincipal("carol.1", "000002"), null, "an admitted match after noted absence is not its session");
	identity.stop();
});

// CI2 - the admission deadline.

test("CI2, E18: a host ruling that never answers is denied at the admission deadline, and another peer's record sharing that session identifier is then forgotten as any absent session's is", async (t) => {
	let entered = false;
	let answerLate;
	const ruling = {
		evaluate(request) {
			if (request.remoteNodeId !== "bob.1") return Promise.resolve({ decision: "allow" });
			entered = true;
			return new Promise((resolve) => { answerLate = resolve; });
		},
	};
	// No admission deadline is given: the default, 10 seconds on the clock port, applies.
	const { clock, host, peer } = await setUp(t, { ruling, sessionIds: ["00abcd", "00abcd"], openTimeoutMs: 250 });
	t.after(() => answerLate?.({ decision: "allow" }));
	const alice = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "00abcd");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, "00abcd");
	clock.advanceTo(sweep(2) - 1_000);
	await peer("bob.1");
	await eventually(() => entered, "bob's admission to reach the host's ruling");
	// AGP's opening time-out ends bob's opening, but AGP keeps the connection pending while it awaits admission.
	const expired = await eventually(() => host.connections().find((c) => c.identityState === "pending" && c.lastTransition.event === "OpenExpired"),
		"AGP's opening time-out on bob's connection");
	assert.equal(expired.localSessionId, "00abcd");
	clock.advanceTo(sweep(2));
	found(host, "alice.1", "00abcd");
	clock.advanceTo(sweep(2) + 9_000 - 1);
	await new Promise((resolve) => setTimeout(resolve, 20));
	assert.ok(present(host, "alice.1", "00abcd"), "before the deadline, AGP still awaits the ruling");
	clock.advanceTo(sweep(2) + 9_000);
	await eventually(() => host.connections().length === 0, "AGP to release bob's connection once the deadline denies it");
	assert.equal((await host.refused("00abcd")).data.reason, "OpenExpired", "AGP reports the expired opening only once it releases the connection");
	assert.equal(host.identity.sessionPrincipal("bob.1", "00abcd"), null, "a denied session is not recorded");
	answerLate({ decision: "allow" });
	await new Promise((resolve) => setTimeout(resolve, 20));
	assert.equal(host.identity.sessionPrincipal("bob.1", "00abcd"), null, "the ruling's late answer records nothing");
	found(host, "alice.1", "00abcd");
	clock.advanceTo(sweep(3));
	clock.advanceTo(sweep(5) - 1);
	found(host, "alice.1", "00abcd");
	clock.advanceTo(sweep(5));
	gone(host, "alice.1", "00abcd");
});

test("CI2: the admission port answers within the deadline the host gives: a ruling's answer in time is AGP's, one not answered by then is a denial with code POLICY", async () => {
	const clock = new ManualClock(START);
	const answers = [];
	const ruling = { evaluate: () => new Promise((resolve, reject) => answers.push({ resolve, reject })) };
	const identity = createCallerIdentity({ rule: assertedNodeRule, clock, admission: ruling, admissionDeadlineMs: 2_500 });
	const request = (session) => ({ localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: session, remoteSessionId: "000009", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } });
	const settled = (promise) => { const state = { done: false }; promise.then((v) => Object.assign(state, { done: true, value: v }), (e) => Object.assign(state, { done: true, error: e })); return state; };
	const tick = () => new Promise((resolve) => setImmediate(resolve));
	// Not answered by the deadline.
	const late = settled(identity.admission.evaluate(request("000001")));
	clock.advanceBy(2_499);
	await tick();
	assert.equal(late.done, false, "before the deadline, the port awaits the ruling");
	clock.advanceBy(1);
	await tick();
	assert.deepEqual(late.value, { decision: "deny", reasonCode: "POLICY" });
	answers[0].resolve({ decision: "allow" });
	await tick();
	assert.equal(identity.sessionPrincipal("alice.1", "000001"), null, "the late answer records nothing");
	// Answered in time: the ruling's answer, and the deadline is cancelled.
	const allowed = settled(identity.admission.evaluate(request("000002")));
	assert.deepEqual(clock.pending(), [START + 2_500 + 2_500]);
	answers[1].resolve({ decision: "allow" });
	await tick();
	assert.deepEqual(allowed.value, { decision: "allow" });
	assert.deepEqual(clock.pending(), [], "an answer in time cancels the deadline");
	assert.deepEqual(identity.sessionPrincipal("alice.1", "000002"), record("alice.1", "000002", "alice"));
	// A ruling that rejects in time refuses the session, as AGP treats a faulted admission.
	const faulted = settled(identity.admission.evaluate(request("000003")));
	answers[2].reject(new Error("the ruling failed"));
	await tick();
	assert.match(String(faulted.error), /the ruling failed/);
	assert.equal(identity.sessionPrincipal("alice.1", "000003"), null);
	for (const admissionDeadlineMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, "10000"]) {
		assert.throws(() => createCallerIdentity({ rule: assertedNodeRule, admissionDeadlineMs }), /admission deadline/);
	}
});

test("CI2: a ruling's answer is judged by when it comes on the clock port: an allow or a rejection at or after the deadline is a denial with code POLICY whether its answer or the deadline's timer runs first, and records nothing; an answer just before the deadline is taken", async () => {
	const DEADLINE = 10_000;
	const request = (session) => ({ localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: session, remoteSessionId: "000009", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } });
	const tick = () => new Promise((resolve) => setImmediate(resolve));
	const outcome = (promise) => promise.then((value) => ({ value }), (error) => ({ error }));
	let n = 0;
	/** Asks a ruling that answers `how` when the clock reads START + `at`, the timer first or the answer first. */
	async function ask({ at, how, timerFirst }) {
		const clock = new ManualClock(START);
		let answer;
		const ruling = { evaluate: () => new Promise((resolve, reject) => { answer = { resolve, reject }; }) };
		let applied = 0;
		const rule = { apply: (r) => { applied += 1; return assertedNodeRule.apply(r); } };
		const identity = createCallerIdentity({ rule, clock, admission: ruling, admissionDeadlineMs: DEADLINE });
		const session = String(++n).padStart(6, "0");
		const pending = outcome(identity.admission.evaluate(request(session)));
		await tick();
		if (timerFirst) {
			// The deadline's timer runs, late, at the answer's time, and only then the answer comes.
			clock.setTime(START + at);
			clock.runDue();
		} else {
			// The clock passes the deadline with its timer still queued; the answer's callback runs first.
			clock.setTime(START + at);
		}
		if (how === "allow") answer.resolve({ decision: "allow" });
		else answer.reject(new Error("the ruling failed"));
		await tick();
		clock.runDue();
		await tick();
		return { session, result: await pending, record: identity.sessionPrincipal("alice.1", session), applied, pendingTimers: clock.pending() };
	}
	for (const how of ["allow", "reject"]) {
		for (const timerFirst of [false, true]) {
			for (const at of [DEADLINE, DEADLINE + 1, 25_000]) {
				const seen = await ask({ at, how, timerFirst });
				const label = `${how} at +${at}, ${timerFirst ? "timer first" : "answer first"}`;
				assert.deepEqual(seen.result, { value: { decision: "deny", reasonCode: "POLICY" } }, label);
				assert.equal(seen.record, null, `${label}: nothing recorded`);
				assert.equal(seen.applied, 0, `${label}: no rule applied`);
				assert.deepEqual(seen.pendingTimers, [], `${label}: no timer left`);
			}
		}
	}
	// Just before the deadline, the answer is the ruling's: an allow is taken and recorded, a rejection refuses.
	const taken = await ask({ at: DEADLINE - 1, how: "allow", timerFirst: false });
	assert.deepEqual(taken.result, { value: { decision: "allow" } });
	assert.equal(taken.applied, 1);
	assert.deepEqual(taken.record, record("alice.1", taken.session, "alice"));
	assert.deepEqual(taken.pendingTimers, [], "an answer in time cancels the deadline");
	const refused = await ask({ at: DEADLINE - 1, how: "reject", timerFirst: false });
	assert.match(String(refused.result.error), /the ruling failed/);
	assert.equal(refused.record, null);
});

test("CI2: on the default clock, an asynchronous ruling that answers only after a short deadline is denied with code POLICY and records nothing", async () => {
	const deadline = 20;
	let entered;
	let answered;
	const ruling = {
		async evaluate() {
			entered = performance.now();
			await Promise.resolve();
			// A busy host: the answer's continuation runs before the deadline's timer can.
			while (performance.now() - entered < 50) { /* busy */ }
			answered = performance.now();
			return { decision: "allow" };
		},
	};
	const identity = createCallerIdentity({ rule: assertedNodeRule, admission: ruling, admissionDeadlineMs: deadline });
	const result = await identity.admission.evaluate({ localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: "000001", remoteSessionId: "000009", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } });
	assert.ok(answered - entered >= 50, "the ruling answered after its deadline");
	assert.deepEqual(result, { decision: "deny", reasonCode: "POLICY" });
	assert.equal(identity.sessionPrincipal("alice.1", "000001"), null);
});

test("CI2: a timer wakeup is not the deadline: with a clock whose timer fires early, again and again, the port reads the clock and waits for the time remaining, so an allow or a rejection just before the deadline is the ruling's, and a ruling that never answers is denied only once the clock shows the deadline passed", async () => {
	const DEADLINE = 10_000;
	const request = (session) => ({ localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: session, remoteSessionId: "000009", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } });
	const settled = (promise) => { const state = { done: false }; promise.then((v) => Object.assign(state, { done: true, value: v }), (e) => Object.assign(state, { done: true, error: e })); return state; };
	const tick = () => new Promise((resolve) => setImmediate(resolve));
	const make = () => {
		const clock = new ManualClock(START);
		const delays = [];
		// A scheduler that wakes at half the delay it was asked for, every time.
		const early = { now: () => clock.now(), schedule: (delay, run) => { delays.push(delay); return clock.schedule(delay / 2, run); } };
		const answers = [];
		const ruling = { evaluate: () => new Promise((resolve, reject) => answers.push({ resolve, reject })) };
		const identity = createCallerIdentity({ rule: assertedNodeRule, clock: early, admission: ruling, admissionDeadlineMs: DEADLINE });
		return { clock, delays, answers, identity };
	};
	// An allow just before the deadline, after many early wakeups, is taken.
	{
		const { clock, delays, answers, identity } = make();
		const allowed = settled(identity.admission.evaluate(request("000001")));
		clock.advanceTo(START + DEADLINE - 1);
		await tick();
		assert.equal(allowed.done, false, "an early wakeup denies nothing");
		assert.ok(delays.length > 2, "each early wakeup waits again");
		assert.ok(delays.every((d) => Number.isInteger(d) && d > 0), "for the time remaining, rounded up");
		answers[0].resolve({ decision: "allow" });
		await tick();
		assert.deepEqual(allowed.value, { decision: "allow" });
		assert.deepEqual(identity.sessionPrincipal("alice.1", "000001"), record("alice.1", "000001", "alice"));
		assert.deepEqual(clock.pending(), [], "an answer in time cancels the deadline's current timer");
	}
	// A rejection just before the deadline refuses the session, as a faulted admission.
	{
		const { clock, answers, identity } = make();
		const faulted = settled(identity.admission.evaluate(request("000002")));
		clock.advanceTo(START + DEADLINE - 0.25);
		await tick();
		assert.equal(faulted.done, false);
		answers[0].reject(new Error("the ruling failed"));
		await tick();
		assert.match(String(faulted.error), /the ruling failed/);
		assert.deepEqual(clock.pending(), []);
	}
	// A ruling that never answers is denied at the deadline on the clock, not at an early wakeup.
	{
		const { clock, answers, identity } = make();
		const late = settled(identity.admission.evaluate(request("000003")));
		clock.advanceTo(START + DEADLINE - 0.25);
		await tick();
		assert.equal(late.done, false, "not before the deadline");
		clock.advanceTo(START + DEADLINE);
		await tick();
		assert.deepEqual(late.value, { decision: "deny", reasonCode: "POLICY" });
		assert.deepEqual(clock.pending(), []);
		answers[0].resolve({ decision: "allow" });
		await tick();
		assert.equal(identity.sessionPrincipal("alice.1", "000003"), null, "the late answer records nothing");
	}
});

test("CI2: on the default clock, whose timer can wake before its delay has passed on performance.now(), an asynchronous ruling that answers just before a short integer deadline is taken", async () => {
	const deadline = 20;
	const realSetTimeout = globalThis.setTimeout;
	let wakeups = 0;
	// The runtime's timer, made to wake early: at a quarter of its delay, rounded down.
	globalThis.setTimeout = (callback, delay, ...args) => realSetTimeout(() => { wakeups += 1; callback(...args); }, Math.floor(delay / 4));
	let timely = 0;
	try {
		for (let trial = 1; trial <= 40 && timely < 5; trial += 1) {
			let observed;
			let wokenBefore;
			const ruling = {
				evaluate() {
					const work = (async () => {
						const entered = performance.now();
						while (performance.now() - entered < deadline - 5) await new Promise((resolve) => setImmediate(resolve));
						return { decision: "allow" };
					})();
					// Registered before caller-identity's own handler, so it observes the answer first.
					work.then(() => { observed = performance.now(); wokenBefore = wakeups; });
					return work;
				},
			};
			const identity = createCallerIdentity({ rule: assertedNodeRule, admission: ruling, admissionDeadlineMs: deadline });
			const session = String(trial).padStart(6, "0");
			wakeups = 0;
			// The port captures its deadline after this timestamp: an answer observed before before + deadline is in time.
			const before = performance.now();
			const result = await identity.admission.evaluate({ localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: session, remoteSessionId: "000009", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } });
			// A trial counts when the deadline's timer woke early, before the answer, and the answer came in
			// time; on a host too slow for either, the trial shows nothing about an early wakeup.
			if (wokenBefore < 1 || observed - before >= deadline) continue;
			timely += 1;
			assert.deepEqual(result, { decision: "allow" }, `trial ${trial}: answered ${observed - before} ms after the start of a ${deadline} ms deadline`);
			assert.deepEqual(identity.sessionPrincipal("alice.1", session), record("alice.1", session, "alice"));
		}
	} finally {
		globalThis.setTimeout = realSetTimeout;
	}
	assert.ok(timely > 0, "at least one ruling answered before its deadline, after an early wakeup");
});

test("CI2: a sweep timer that wakes early, again and again, waits again for the time remaining, rounded up, and each sweep runs only at its time on the clock", () => {
	const start = START + 0.25;
	const clock = new ManualClock(start);
	const delays = [];
	// A scheduler that wakes at half the delay it was asked for, every time.
	const early = { now: () => clock.now(), schedule: (delay, run) => { delays.push(delay); return clock.schedule(delay / 2, run); } };
	const identity = createCallerIdentity({ rule: assertedNodeRule, clock: early });
	const reads = [];
	identity.start({ connections: () => { reads.push(clock.now()); return { items: [] }; } });
	clock.advanceTo(start + SWEEP - 0.25);
	assert.deepEqual(reads, [], "no sweep before 30 seconds by the clock");
	assert.ok(delays.length > 2, "each early wakeup waits again");
	assert.ok(delays.every((d) => Number.isInteger(d) && d > 0), "for the time remaining, rounded up");
	clock.advanceTo(start + SWEEP);
	assert.deepEqual(reads, [start + SWEEP], "the first sweep at its time");
	clock.advanceTo(start + 2 * SWEEP - 0.25);
	assert.deepEqual(reads, [start + SWEEP], "no second sweep before its time");
	clock.advanceTo(start + 2 * SWEEP);
	assert.deepEqual(reads, [start + SWEEP, start + 2 * SWEEP]);
	identity.stop();
	assert.deepEqual(clock.pending(), []);
});

// CI2 - a snapshot that cannot be read, and stopping twice.

test("CI2, E18: a snapshot that throws is reported to the diagnostic port and keeps every record; read again, the record is forgotten by the first readable sweep 60 seconds after absence was first seen", async (t) => {
	const failure = new Error("the snapshot cannot be read");
	let broken = false;
	const reports = [];
	const diagnostic = { report: (d) => reports.push(d) };
	const sweepSource = (operations) => ({ connections: () => { if (broken) throw failure; return operations.connections(); } });
	const { clock, host, peer } = await setUp(t, { diagnostic, sweepSource, sessionIds: ["000a01", "000a02"] });
	const alice = await peer("alice.1");
	await peer("bob.1");
	assert.equal(await host.sessionWith("alice.1"), "000a01");
	assert.equal(await host.sessionWith("bob.1"), "000a02");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, "000a01");
	clock.advanceTo(sweep(2));
	// Absence of alice's session was first seen at sweep 2; on time, sweep 4 would forget it.
	assert.deepEqual(reports, [], "a readable snapshot reports nothing");
	broken = true;
	clock.advanceTo(sweep(6));
	assert.deepEqual(reports, [3, 4, 5, 6].map((k) => ({ kind: "snapshot-unreadable", at: sweep(k), error: failure })), "each failure is reported");
	assert.ok(reports.every((r) => Object.isFrozen(r)));
	found(host, "alice.1", "000a01");
	found(host, "bob.1", "000a02");
	assert.deepEqual(clock.pending(), [sweep(7)], "the sweeping goes on");
	broken = false;
	clock.advanceTo(sweep(7) - 1);
	found(host, "alice.1", "000a01");
	clock.advanceTo(sweep(7));
	gone(host, "alice.1", "000a01");
	found(host, "bob.1", "000a02");
	assert.equal(reports.length, 4);
});

/** A host whose snapshot reader fails while `broken` is set, with the reader itself and its reports. */
async function setUpBreakable(t, options) {
	const reports = [];
	const state = { broken: false, reader: undefined, reports };
	const sweepSource = (operations) => (state.reader = {
		connections: () => { if (state.broken) throw new Error("a brief snapshot failure"); return operations.connections(); },
	});
	const parts = await setUp(t, { start: 0, sweepSource, diagnostic: { report: (d) => reports.push(d.at) }, ...options });
	return { ...parts, state };
}

test("CI2, E18: a failure of 2 milliseconds at the first sweep after a close delays the noting of absence by one sweep interval", async (t) => {
	// The verifier's V8 schedule: started at 0, sweeps at 30,000, 60,000, 90,000 and so on.
	const { clock, host, peer, state } = await setUpBreakable(t, { sessionIds: ["000c01"] });
	const alice = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "000c01");
	clock.advanceTo(30_000);
	clock.advanceTo(30_001);
	await closePeer(host, alice, "000c01");
	clock.advanceTo(59_999);
	state.broken = true;
	clock.advanceTo(60_001);
	state.broken = false;
	assert.deepEqual(state.reports, [60_000], "the one failed sweep is reported");
	assert.equal(state.reader.connections().items.length, 0, "the snapshot is readable again at 60,001, and shows the close");
	// Without the failure, absence is noted at 60,000 and the record forgotten at 120,000; the failed sweep
	// changed nothing, so absence is first noted at 90,000, one sweep interval later.
	clock.advanceTo(120_003);
	found(host, "alice.1", "000c01");
	clock.advanceTo(149_999);
	found(host, "alice.1", "000c01");
	clock.advanceTo(150_000);
	gone(host, "alice.1", "000c01");
	assert.deepEqual(state.reports, [60_000]);
});

test("CI2, E18: a failure at the sweep where a record falls due forgets it at the next readable sweep", async (t) => {
	const { clock, host, peer, state } = await setUpBreakable(t, { sessionIds: ["000c02"] });
	const alice = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "000c02");
	clock.advanceTo(30_000);
	clock.advanceTo(30_001);
	await closePeer(host, alice, "000c02");
	// Absence is first noted at 60,000; the record falls due at the sweep at 120,000.
	clock.advanceTo(119_999);
	found(host, "alice.1", "000c02");
	state.broken = true;
	clock.advanceTo(120_001);
	state.broken = false;
	assert.deepEqual(state.reports, [120_000], "the failed sweep where the record fell due is reported");
	found(host, "alice.1", "000c02");
	clock.advanceTo(149_999);
	found(host, "alice.1", "000c02");
	clock.advanceTo(150_000);
	gone(host, "alice.1", "000c02");
	assert.deepEqual(state.reports, [120_000]);
});

test("CI2: a diagnostic port that throws, or none, never stops the sweeping, and a snapshot that throws without one still changes no record", async () => {
	for (const diagnostic of [undefined, { report: () => { throw new Error("the diagnostic port failed"); } }]) {
		const clock = new ManualClock(START);
		const identity = createCallerIdentity({ rule: assertedNodeRule, clock, ...(diagnostic === undefined ? {} : { diagnostic }) });
		await identity.admission.evaluate({ localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: "000001", remoteSessionId: "000009", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } });
		let broken = true;
		let reads = 0;
		identity.start({ connections: () => { reads += 1; if (broken) throw new Error("unreadable"); return { items: [] }; } });
		clock.advanceTo(sweep(5));
		assert.equal(reads, 5, "a sweep every 30 seconds, failures and all");
		assert.deepEqual(identity.sessionPrincipal("alice.1", "000001"), record("alice.1", "000001", "alice"));
		broken = false;
		clock.advanceTo(sweep(8) - 1);
		assert.ok(identity.sessionPrincipal("alice.1", "000001"), "absence first seen at sweep 6, the first readable one");
		clock.advanceTo(sweep(8));
		assert.equal(identity.sessionPrincipal("alice.1", "000001"), null);
		identity.stop();
	}
	assert.throws(() => createCallerIdentity({ rule: assertedNodeRule, diagnostic: {} }), /diagnostic port/);
});

test("CI2, E18: the sweeping stopped twice: the second stop changes nothing, records stay readable, and it starts again", async (t) => {
	const { clock, host, peer } = await setUp(t, { sessionIds: ["000b01"] });
	const alice = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "000b01");
	clock.advanceTo(sweep(1) + 1);
	host.identity.stop();
	assert.deepEqual(clock.pending(), [], "the first stop cancels the next sweep");
	host.identity.stop();
	assert.deepEqual(clock.pending(), [], "the second stop changes nothing");
	found(host, "alice.1", "000b01");
	await closePeer(host, alice, "000b01");
	clock.advanceTo(sweep(10));
	found(host, "alice.1", "000b01");
	// Stopped, it is not sweeping, so it can be started again.
	host.identity.start(host.node.operations);
	assert.deepEqual(clock.pending(), [sweep(11)], "started again, the first sweep is 30 seconds later");
	clock.advanceTo(sweep(11));
	found(host, "alice.1", "000b01");
	clock.advanceTo(sweep(13) - 1);
	found(host, "alice.1", "000b01");
	clock.advanceTo(sweep(13));
	gone(host, "alice.1", "000b01");
});

test("D2-E3, CI1, CI2, D54, D55: SessionRule.apply, IdentityAdmissionPort.evaluate and ConnectionSource.connections read results as plain data through shape-check, with zero getter calls and zero unhandled rejections on non-plain or thrown values", async () => {
	const clock = new ManualClock(START);
	const admission = { localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: "000001", remoteSessionId: "000002", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } };
	let getters = 0;
	const escaped = await observingUnhandledRejections(async () => {
		// 1. SessionRule.apply: non-plain results, non-native thenables, nested rejected promises, and thrown objects holding a rejected promise.
		const ruleCases = [
			() => ({ get principal() { getters++; return "alice"; }, proved: false, p: Promise.reject(new Error("rule getter promise")) }),
			() => ({ then(resolve) { getters++; resolve({ principal: "alice", proved: false }); }, p: Promise.reject(new Error("rule thenable promise")) }),
			() => Object.create({ principal: "alice", proved: false }),
			() => ({ principal: "alice", proved: false, p: Promise.reject(new Error("rule nested promise")) }),
			() => { throw Object.assign(new Error("rule threw"), { p: Promise.reject(new Error("rule thrown promise")) }); },
		];
		for (const apply of ruleCases) {
			const identity = createCallerIdentity({ rule: { apply }, clock });
			await assert.rejects(identity.admission.evaluate(admission));
			assert.equal(identity.sessionPrincipal("alice.1", "000001"), null);
		}

		// 2. IdentityAdmissionPort.evaluate: non-plain results, non-native thenables, invalid denial reasonCode, nested rejected promises, and thrown/rejected promises.
		const admissionCases = [
			() => ({ get decision() { getters++; return "allow"; }, p: Promise.reject(new Error("admission getter promise")) }),
			() => ({ then(resolve) { getters++; resolve({ decision: "allow" }); }, p: Promise.reject(new Error("admission thenable promise")) }),
			() => Promise.resolve({ decision: "deny" }),
			() => Promise.resolve({ decision: "deny", reasonCode: "NOT_AN_AGP_CODE" }),
			() => Promise.resolve({ decision: "allow", extra: Promise.reject(new Error("admission nested promise")) }),
			() => Promise.reject(Object.assign(new Error("admission rejected"), { p: Promise.reject(new Error("admission rejected nested")) })),
			() => { throw Object.assign(new Error("admission threw"), { p: Promise.reject(new Error("admission thrown nested")) }); },
		];
		for (const evaluate of admissionCases) {
			const identity = createCallerIdentity({ rule: assertedNodeRule, admission: { evaluate }, clock });
			await assert.rejects(identity.admission.evaluate(admission));
			assert.equal(identity.sessionPrincipal("alice.1", "000001"), null);
		}
		// Valid AGP denial codes pass as plain data.
		for (const reasonCode of ["POLICY", "EXPECTED_NODE_MISMATCH", "SECURITY_EVIDENCE", "CAPACITY"]) {
			const identity = createCallerIdentity({ rule: assertedNodeRule, admission: { evaluate: () => ({ decision: "deny", reasonCode }) }, clock });
			assert.deepEqual(await identity.admission.evaluate(admission), { decision: "deny", reasonCode });
			assert.equal(identity.sessionPrincipal("alice.1", "000001"), null);
		}

		// 3. ConnectionSource.connections: non-plain results, getters, nested rejected promises, and thrown objects holding a rejected promise.
		const snapshotCases = [
			() => ({ get items() { getters++; return []; }, p: Promise.reject(new Error("snapshot getter promise")) }),
			() => ({ items: [{ identityState: "admitted", get remoteNodeId() { getters++; return "alice.1"; }, sessionId: "000001", p: Promise.reject(new Error("entry getter promise")) }] }),
			() => ({ items: [{ identityState: "admitted", remoteNodeId: "alice.1" }] }),
			() => ({ items: [{ identityState: "pending" }] }),
			() => Object.create({ items: [] }),
			() => { throw Object.assign(new Error("snapshot threw"), { p: Promise.reject(new Error("snapshot thrown promise")) }); },
		];
		for (const connections of snapshotCases) {
			const reports = [];
			const tickClock = new ManualClock(START);
			const identity = createCallerIdentity({
				rule: assertedNodeRule,
				clock: tickClock,
				diagnostic: { report(d) { reports.push(d); throw Object.assign(new Error("diagnostic threw"), { p: Promise.reject(new Error("diagnostic thrown promise")) }); } },
			});
			await identity.admission.evaluate(admission);
			identity.start({ connections });
			tickClock.advanceBy(SWEEP);
			assert.equal(reports.length, 1, "unreadable snapshot reported to diagnostic");
			assert.deepEqual(identity.sessionPrincipal("alice.1", "000001"), record("alice.1", "000001", "alice"), "record kept when snapshot is not plain data");
			identity.stop();
		}
	});
	assert.equal(getters, 0, "no getter on any plug-in result was invoked");
	assert.deepEqual(escaped, [], "every rejected promise was observed");
});
