// loopback-host - a host using caller-identity over AGP's production in-process carrier (@agp/transport-loopback),
// as E18 asks: the host's AGP node is given caller-identity's admission port, the host starts and stops the
// sweeping with its node, and asks for each request's evidence as the request is received.
//
// The host node is named "hub", and its own session identifiers can be scripted, so two peers can be given one
// session number. A gate can hold AGP's receipt of the port's answer after caller-identity has recorded the
// session, keeping the connection pending - not yet committed - as AGP asks the port before it commits.
import { createNode } from "@agp/node";
import { createLoopbackFabric } from "@agp/transport-loopback";
import { assertedNodeRule, createCallerIdentity } from "@apnex/caller-identity";

let fabricSequence = 0;
const HUB = "hub";
export const SERVICE = "svc";

/** A fresh fabric of AGP's in-process carrier, with room for a small topology. */
export function newFabric() {
	return createLoopbackFabric({
		fabricId: `caller-identity-${process.pid}-${++fabricSequence}`,
		// AGP's own topology tests' limits, which fit a node's default channel limits.
		limits: {
			maxTransports: 256,
			maxListeners: 64,
			maxPendingAcquisitions: 256,
			maxActiveChannels: 128,
			maxPacketBytes: 16_777_216,
			maxBufferedPacketsPerChannel: 1_024,
			maxBufferedBytesPerChannel: 33_554_432,
			maxQueuedPacketsTotal: 65_536,
			maxQueuedBytesTotal: 268_435_456,
			maxPendingSendBytesTotal: 17_179_869_184,
		},
	});
}

/** Polls until `probe` gives a value that is not undefined, null or false, in real time. */
export async function eventually(probe, description, timeoutMs = 5_000) {
	const deadline = performance.now() + timeoutMs;
	for (;;) {
		const value = await probe();
		if (value !== undefined && value !== null && value !== false) return value;
		if (performance.now() > deadline) throw new Error(`did not observe ${description}`);
		await new Promise((resolve) => setTimeout(resolve, 2));
	}
}

/** Session identifiers for the host node: the scripted ones first, then fresh ones. */
class ScriptedIds {
	#script;
	#count = 0;
	constructor(script) {
		this.#script = [...script];
	}
	push(...ids) {
		this.#script.push(...ids);
	}
	next(scope) {
		this.#count += 1;
		if (scope === "session") return this.#script.length > 0 ? this.#script.shift() : (0xa00000 + this.#count).toString(16);
		return `${scope}-hub-${this.#count}`;
	}
}

let transportSequence = 0;
function transport(fabric, name, { listen, targets = [] }) {
	const builder = fabric.createTransport({
		transportName: `t-${++transportSequence}`,
		capabilities: { listen: listen !== undefined, connect: targets.length > 0 },
	});
	return builder.createPort({
		listeners: listen === undefined ? new Map() : new Map([[`listen.${listen}`, { fabricId: fabric.fabricId, address: listen }]]),
		targets: new Map(targets.map((address) => [`to.${address}`, { fabricId: fabric.fabricId, address }])),
	});
}

/**
 * The hub's port of the in-process carrier, with every channel it accepts reporting `peerEvidence` in place of
 * the carrier's own; packets still cross the carrier. Trusted-development WebSocket security reports no
 * authentication, which the in-process carrier never does, so this is how a test puts that evidence before
 * AGP's admission of a real session.
 */
function reportingEvidence(port, peerEvidence) {
	const relabel = (channel) => Object.freeze({
		peerEvidence,
		...(channel.sendAwaitsReceiverCapacity === undefined ? {} : { sendAwaitsReceiverCapacity: channel.sendAwaitsReceiverCapacity }),
		send: (packet, signal) => channel.send(packet, signal),
		read: (signal) => channel.read(signal),
		close: (intent, signal) => channel.close(intent, signal),
		abort: (intent) => channel.abort(intent),
	});
	return {
		resolveTarget: (reference) => port.resolveTarget(reference),
		resolveListener(reference) {
			const capability = port.resolveListener(reference);
			if (capability === undefined) return undefined;
			return {
				listen: (options, callbacks, signal) => capability.listen(options, {
					accept: (value) => callbacks.accept({ ...value, channel: relabel(value.channel) }),
					capacityRejected: (kind) => callbacks.capacityRejected(kind),
				}, signal),
			};
		},
	};
}

const timers = (openTimeoutMs) => ({ holdTimeMs: 0, openTimeoutMs, routeAckTimeoutMs: 2_000 });
const noReconnect = { enabled: false, initialDelayMs: 5, maximumDelayMs: 50, multiplier: 2, jitterRatio: 0 };

/**
 * Starts the host: an AGP node named "hub" listening on the fabric, composing caller-identity with the
 * asserted node rule and the given clock, serving SERVICE, and recording each request with its evidence.
 * `dial` names addresses the hub itself dials, each with the node it expects there. `sweepSource` wraps the
 * node's operations reader the sweeps are given, so a test can make the snapshot unreadable; `peerEvidence`
 * replaces the carrier's evidence on every channel the hub accepts.
 */
export async function startHost(fabric, {
	clock, rule = assertedNodeRule, sessionIds = [], ruling, gate, openTimeoutMs = 2_000, dial = [], agpClock,
	admissionDeadlineMs, diagnostic, sweepSource = (operations) => operations, peerEvidence,
} = {}) {
	const identity = createCallerIdentity({
		rule,
		clock,
		...(ruling === undefined ? {} : { admission: ruling }),
		...(admissionDeadlineMs === undefined ? {} : { admissionDeadlineMs }),
		...(diagnostic === undefined ? {} : { diagnostic }),
	});
	const ids = new ScriptedIds(sessionIds);
	const admission = gate === undefined ? identity.admission : {
		async evaluate(request) {
			const result = await identity.admission.evaluate(request);
			await gate(request);
			return result;
		},
	};
	const node = createNode({
		nodeId: HUB,
		listen: { transportRef: `listen.${HUB}` },
		...(dial.length === 0 ? {} : {
			peers: dial.map(({ address, expect }) => ({ adjacencyId: address, expectedNodeId: expect, transportRef: `to.${address}`, reconnect: noReconnect })),
		}),
		identityAdmission: { mode: "port" },
		timers: timers(openTimeoutMs),
	}, {
		transport: peerEvidence === undefined
			? transport(fabric, HUB, { listen: HUB, targets: dial.map((d) => d.address) })
			: reportingEvidence(transport(fabric, HUB, { listen: HUB, targets: dial.map((d) => d.address) }), peerEvidence),
		identityAdmission: admission,
		ids,
		...(agpClock === undefined ? {} : { clock: agpClock }),
	});
	const requests = [];
	await node.expose(SERVICE, (payload, context) => {
		// The host asks as it receives the request, before anything else is done with it (CI3).
		requests.push({ payload, delivery: context.delivery, evidence: identity.evidence(context.delivery) });
	});
	await node.expose("hub-client", () => {});
	// AGP's operational events, for a test to observe AGP refusing a session before its identity was committed.
	const events = [];
	const subscription = node.operations.events();
	(async () => { for await (const event of subscription) events.push(event); })().catch(() => {});
	await node.start();
	identity.start(sweepSource(node.operations));
	return {
		node,
		identity,
		ids,
		requests,
		events,
		/** AGP's closing, before its identity was committed, of the connection under the hub's own `session`. */
		refused: (session) => eventually(() => events.find((e) => e.kind === "connection.preidentity-closed" && e.data.localSessionId === session),
			`AGP to refuse the connection under ${session}`),
		/** The connection entries of the hub's snapshot. */
		connections: () => node.operations.connections().items,
		/** The hub's own session identifier for an established session with `peer`. */
		sessionWith: (peer) => eventually(() => node.operations.connections().items.find(
			(c) => c.identityState === "admitted" && c.remoteNodeId === peer && c.state === "Established")?.sessionId,
		`an established session with ${peer}`),
		/** Sends a request from the hub to its own service: a delivery with no ingress. */
		async localRequest(payload) {
			const count = requests.length;
			await node.send("hub-client", SERVICE, payload);
			return eventually(() => requests[count], "the local request");
		},
		async stop() {
			identity.stop();
			subscription.close();
			await node.stop({ drainTimeoutMs: 100 }).catch(() => {});
		},
	};
}

/** Whether the hub's snapshot holds a connection, admitted or pending, for `peer` and `session`. */
export function present(host, peer, session) {
	return host.connections().some((c) => c.identityState === "admitted"
		? c.remoteNodeId === peer && c.sessionId === session
		: c.localSessionId === session);
}

/**
 * Starts a peer node named `name` that dials `address` (the hub's by default), expecting `expect` there,
 * and exposes an endpoint it sends from. `listen` makes it listen too, and `transit` lets it relay.
 */
export async function startPeer(fabric, name, { address = HUB, expect = HUB, listen, transit = false, openTimeoutMs = 2_000 } = {}) {
	const node = createNode({
		nodeId: name,
		...(listen === undefined ? {} : { listen: { transportRef: `listen.${listen}` } }),
		peers: [{ adjacencyId: address, expectedNodeId: expect, transportRef: `to.${address}`, reconnect: noReconnect }],
		transit: { enabled: transit, defaultHopLimit: 16 },
		timers: timers(openTimeoutMs),
	}, { transport: transport(fabric, name, { listen, targets: [address] }) });
	await node.expose(sourceEndpoint(name), () => {});
	await node.start();
	return node;
}

/** The endpoint a peer sends its requests from, its own so every route back to it is distinct. */
export const sourceEndpoint = (name) => `from-${name.replace(/[^a-z0-9-]/g, "-")}`.slice(0, 48);

/**
 * Waits until `node` has a route to the hub's service and the hub has acknowledged the route back to the
 * node's endpoint - from `via`, the node next to the hub, when the request is relayed - then sends one
 * request and waits for the hub to receive it.
 */
export async function request(host, node, payload = {}, via = node) {
	const source = sourceEndpoint(node.nodeId);
	await eventually(() => node.operations.routes().selected.some((r) => r.endpoint === SERVICE), `a route from ${node.nodeId} to ${SERVICE}`);
	await eventually(() => via.operations.routeExports().items.some((r) => r.endpoint === source && r.remoteNodeId === HUB && r.state === "acked"),
		`the hub's acknowledgement of ${source}`);
	const count = host.requests.length;
	await node.send(source, SERVICE, payload);
	return eventually(() => host.requests[count], `the request from ${node.nodeId}`);
}

/** Stops a peer and waits until the hub's snapshot no longer holds its session. */
export async function closePeer(host, node, session) {
	await node.stop({ drainTimeoutMs: 100 });
	await eventually(() => !present(host, node.nodeId, session), `the hub to drop ${node.nodeId}'s session ${session}`);
}

/**
 * Opens a bare channel of the in-process carrier to the hub that never sends AGP's OPEN: the hub holds it as
 * a pending connection, naming only its own session identifier, until AGP's opening time-out ends it.
 */
export async function openSilentConnection(fabric) {
	const port = transport(fabric, "silent", { targets: [HUB] });
	const channel = await port.resolveTarget(`to.${HUB}`).connect(
		{ channel: { maxPacketBytes: 1_048_576, maxBufferedPackets: 64, maxBufferedBytes: 4_194_304 } },
		new AbortController().signal,
	);
	return channel;
}

/** Stops nodes and hosts, ignoring any already stopped. */
export async function stopAll(...parts) {
	await Promise.allSettled(parts.filter(Boolean).map((part) => part.identity ? part.stop() : part.stop({ drainTimeoutMs: 100 })));
}
