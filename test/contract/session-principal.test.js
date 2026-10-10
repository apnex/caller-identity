// session-principal - CONTRACT.md's row, through CI1 and CI2, for zorg's E18.
//
// A host using caller-identity over AGP's production in-process carrier (@agp/transport-loopback), applying
// the asserted node rule to each peer's node name whatever that carrier's own evidence says, records for each
// admitted session the asserted principal the rule gives, keyed by the peer's node and the host node's own
// session identifier, and forgets it by sweeping AGP's connection snapshot every 30 seconds by an injected
// clock port, never sooner than 60 seconds after the session closed.
import assert from "node:assert/strict";
import { test } from "node:test";
import { assertedNodeRule, createCallerIdentity } from "@apnex/caller-identity";
import { ManualClock } from "../support/manual-clock.js";
import {
	closePeer, eventually, newFabric, openSilentConnection, present, startHost, startPeer, stopAll,
} from "../support/loopback-host.js";

const START = 1_000_000;
const SWEEP = 30_000;
/** The time of the k-th sweep after the host started, when every sweep runs on time. */
const sweep = (k) => START + k * SWEEP;
const record = (node, session, principal) => ({ node, session, principal, proved: false });

/** A host on a fresh fabric, with a manual clock at START, stopped after the test. */
async function setUp(t, { before, ...options } = {}) {
	const clock = new ManualClock(START);
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

test("CI2: a key admitted again replaces the principal and certainty its record held", async () => {
	const clock = new ManualClock(START);
	let admissions = 0;
	const rule = { apply: () => ({ principal: `principal-${++admissions}`, proved: false }) };
	const identity = createCallerIdentity({ rule, clock });
	const request = { localNodeId: "hub", remoteNodeId: "alice.1", localSessionId: "000001", remoteSessionId: "000009", direction: "inbound", peerEvidence: { locality: "network", protection: "none", authentication: { kind: "none" } } };
	assert.deepEqual(await identity.admission.evaluate(request), { decision: "allow" });
	assert.deepEqual(identity.sessionPrincipal("alice.1", "000001"), record("alice.1", "000001", "principal-1"));
	await identity.admission.evaluate({ ...request, remoteSessionId: "00000a" });
	assert.deepEqual(identity.sessionPrincipal("alice.1", "000001"), record("alice.1", "000001", "principal-2"));
});

test("CI2: a later sweep that finds the session present clears the absence noted, so the record is kept 60 seconds from when absence is next seen", async (t) => {
	const { clock, fabric, host, peer } = await setUp(t, { sessionIds: ["00d00d", "00d00d"], openTimeoutMs: 1_500 });
	const alice = await peer("alice.1");
	assert.equal(await host.sessionWith("alice.1"), "00d00d");
	clock.advanceTo(sweep(1));
	clock.advanceTo(sweep(1) + 1);
	await closePeer(host, alice, "00d00d");
	clock.advanceTo(sweep(2));
	// Absence was noted at sweep 2; a connection pending under the same session identifier is present at sweep 3.
	const channel = await openSilentConnection(fabric);
	t.after(() => channel.abort({ kind: "forced-stop", code: "test-done" }));
	await eventually(() => host.connections().some((c) => c.identityState === "pending" && c.localSessionId === "00d00d"), "the silent connection pending under 00d00d");
	clock.advanceTo(sweep(3));
	await eventually(() => !present(host, "alice.1", "00d00d"), "AGP's opening time-out to end the pending connection");
	clock.advanceTo(sweep(4));
	clock.advanceTo(sweep(6) - 1);
	found(host, "alice.1", "00d00d");
	clock.advanceTo(sweep(6));
	gone(host, "alice.1", "00d00d");
});
