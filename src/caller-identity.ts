/**
 * caller-identity's composition of CI1 to CI4: the identity-admission port a host gives its AGP node, the
 * sweeps the host starts and stops with that node, and the evidence of each request.
 */
import type {
	IdentityAdmissionPort,
	IdentityAdmissionRequest,
	IdentityAdmissionResult,
	NodeId,
	SessionId,
} from "@agp/core";
import { defaultClock, type Cancellable, type ClockPort } from "./clock.js";
import type {
	AgpSessionEvidence,
	CallerIdentity,
	CallerIdentityOptions,
	ConnectionSource,
	DeliveryEvidenceInput,
	RuledPrincipal,
	SessionPrincipal,
	SessionRule,
} from "./identity-types.js";
import { SessionRecords } from "./session-records.js";

/** How often, by the host's clock, the connection snapshot is swept (CI2). */
export const SWEEP_INTERVAL_MS = 30_000;

const ALLOW: IdentityAdmissionResult = Object.freeze({ decision: "allow" });

/** Creates one caller-identity instance for one host node. */
export function createCallerIdentity(options: CallerIdentityOptions): CallerIdentity {
	if (typeof options !== "object" || options === null) throw new TypeError("caller-identity needs options");
	const rule = options.rule;
	if (typeof rule !== "object" || rule === null || typeof rule.apply !== "function") {
		throw new TypeError("caller-identity needs the host's rule: an object with apply(request)");
	}
	const ruling = options.admission;
	if (ruling !== undefined && (typeof ruling !== "object" || ruling === null || typeof ruling.evaluate !== "function")) {
		throw new TypeError("an admission ruling is an identity-admission port: an object with evaluate(request)");
	}
	const clock = options.clock ?? defaultClock;
	if (typeof clock !== "object" || clock === null || typeof clock.now !== "function" || typeof clock.schedule !== "function") {
		throw new TypeError("a clock port is an object with now() and schedule(delayMs, callback)");
	}
	return new Instance(rule, ruling, clock);
}

/** What a rule gave, checked, with `proved` held to CI4. */
function ruled(rule: SessionRule, request: IdentityAdmissionRequest): { principal: string | null; proved: boolean } {
	const given: RuledPrincipal | null = rule.apply(request);
	if (given === null) return { principal: null, proved: false };
	if (typeof given !== "object" || typeof given.principal !== "string" || typeof given.proved !== "boolean") {
		throw new TypeError("a rule gives null or { principal: string, proved: boolean }");
	}
	// CI4: proved only for a principal the transport's own proof established - AGP's evidence of a verified
	// peer. A rule cannot make a principal proved over evidence that proved nothing.
	const verified = request.peerEvidence?.authentication?.kind === "verified";
	return { principal: given.principal, proved: given.proved && verified };
}

class Instance implements CallerIdentity {
	readonly admission: IdentityAdmissionPort;
	readonly #rule: SessionRule;
	readonly #ruling: IdentityAdmissionPort | undefined;
	readonly #clock: ClockPort;
	readonly #records = new SessionRecords();
	#source: ConnectionSource | undefined;
	#timer: Cancellable | undefined;
	#due = 0;
	/** Counts each start, so a callback scheduled before a stop never sweeps after it. */
	#generation = 0;

	constructor(rule: SessionRule, ruling: IdentityAdmissionPort | undefined, clock: ClockPort) {
		this.#rule = rule;
		this.#ruling = ruling;
		this.#clock = clock;
		this.admission = Object.freeze({ evaluate: (request: IdentityAdmissionRequest) => this.#evaluate(request) });
	}

	async #evaluate(request: IdentityAdmissionRequest): Promise<IdentityAdmissionResult> {
		const result = this.#ruling === undefined ? ALLOW : await this.#ruling.evaluate(request);
		if (result.decision !== "allow") return result;
		const { principal, proved } = ruled(this.#rule, request);
		this.#records.admit(request.remoteNodeId, request.localSessionId, principal, proved, this.#clock.now());
		return result;
	}

	start(connections: ConnectionSource): void {
		if (typeof connections !== "object" || connections === null || typeof connections.connections !== "function") {
			throw new TypeError("sweeping needs the node's operations reader: an object with connections()");
		}
		if (this.#source !== undefined) throw new Error("caller-identity is already sweeping");
		this.#source = connections;
		this.#generation += 1;
		this.#arm();
	}

	stop(): void {
		this.#timer?.cancel();
		this.#timer = undefined;
		this.#source = undefined;
		this.#generation += 1;
	}

	/** Schedules the next sweep 30 seconds by the clock from now. */
	#arm(): void {
		this.#due = this.#clock.now() + SWEEP_INTERVAL_MS;
		this.#schedule(SWEEP_INTERVAL_MS);
	}

	#schedule(delayMs: number): void {
		const generation = this.#generation;
		this.#timer = this.#clock.schedule(delayMs, () => {
			if (generation === this.#generation) this.#tick();
		});
	}

	#tick(): void {
		const source = this.#source;
		if (source === undefined) return;
		const now = this.#clock.now();
		if (now < this.#due) {
			// The scheduler ran early by the clock; a sweep runs only once 30 seconds have passed by it.
			this.#schedule(this.#due - now);
			return;
		}
		let snapshot;
		try {
			snapshot = source.connections();
		} catch {
			// A snapshot that cannot be read changes no record: nothing keeps a record shorter (CI2).
			snapshot = undefined;
		}
		if (snapshot !== undefined) this.#records.sweep(snapshot, now);
		this.#arm();
	}

	sessionPrincipal(node: NodeId, session: SessionId): SessionPrincipal | null {
		const record = this.#records.find(node, session);
		if (record === undefined) return null;
		return Object.freeze({ node, session, principal: record.principal, proved: record.proved });
	}

	evidence(delivery: DeliveryEvidenceInput): AgpSessionEvidence {
		const node = delivery?.source?.originNodeId;
		if (typeof (node as unknown) !== "string") throw new TypeError("a delivery context names its origin in source.originNodeId");
		const ingressNode = delivery.ingressNodeId;
		const ingressSession = delivery.ingressSessionId;
		const record = ingressNode === node && ingressSession !== undefined
			? this.#records.find(ingressNode, ingressSession)
			: undefined;
		return Object.freeze({
			kind: "agp-session",
			node,
			principal: record === undefined ? null : record.principal,
			proved: record === undefined ? false : record.proved,
		});
	}
}
