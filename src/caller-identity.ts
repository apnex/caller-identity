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
	DiagnosticPort,
	RuledPrincipal,
	SessionPrincipal,
	SessionRule,
} from "./identity-types.js";
import { SessionRecords } from "./session-records.js";

/** How often, by the host's clock, the connection snapshot is swept (CI2). */
export const SWEEP_INTERVAL_MS = 30_000;

/** How long the admission port waits for the host's admission ruling, by default: AGP's default opening time-out (CI2). */
export const DEFAULT_ADMISSION_DEADLINE_MS = 10_000;

const ALLOW: IdentityAdmissionResult = Object.freeze({ decision: "allow" });
/** The answer to an admission whose ruling has not answered by the deadline (CI2). */
const DEADLINE_DENIAL: IdentityAdmissionResult = Object.freeze({ decision: "deny", reasonCode: "POLICY" });

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
	const deadlineMs = options.admissionDeadlineMs ?? DEFAULT_ADMISSION_DEADLINE_MS;
	if (typeof deadlineMs !== "number" || !Number.isFinite(deadlineMs) || deadlineMs <= 0) {
		throw new TypeError("an admission deadline is a positive, finite number of milliseconds");
	}
	const diagnostic = options.diagnostic;
	if (diagnostic !== undefined && (typeof diagnostic !== "object" || diagnostic === null || typeof diagnostic.report !== "function")) {
		throw new TypeError("a diagnostic port is an object with report(diagnostic)");
	}
	return new Instance(rule, ruling, deadlineMs, clock, diagnostic);
}

/** What a rule gave, checked, with `proved` held to CI4. */
function ruled(rule: SessionRule, request: IdentityAdmissionRequest): { principal: string | null; proved: boolean } {
	const given: RuledPrincipal | null = rule.apply(request);
	if (given === null) return { principal: null, proved: false };
	if (consumedThenable(given)) throw new TypeError("a rule answers at once: a promise it returns is refused");
	if (typeof given !== "object") throw new TypeError("a rule gives null or { principal: string, proved: boolean }");
	// CI1, CI4: each is read once, and the values read are the ones checked and recorded, so an accessor
	// cannot give one principal to the check and another to the record. A read that throws refuses the session.
	const principal: unknown = given.principal;
	const claimed: unknown = given.proved;
	if (typeof principal !== "string" || typeof claimed !== "boolean") {
		throw new TypeError("a rule gives null or { principal: string, proved: boolean }");
	}
	return { principal, proved: claimed && provenBy(request, principal) };
}

/**
 * CI1: a rule that returns a promise, or any thenable, is refused like any other malformed result; its own
 * outcome is consumed, a rejection included, at once or later, so that nothing escapes to the host's
 * runtime. The outcome is observed, never used: a promise is not a principal answered at once.
 */
function consumedThenable(given: unknown): boolean {
	if ((typeof given !== "object" && typeof given !== "function") || given === null) return false;
	let then: unknown;
	try {
		then = (given as { then?: unknown }).then;
	} catch {
		// A result whose then cannot even be read is malformed, and refused all the same.
		return true;
	}
	if (typeof then !== "function") return false;
	// Promise.resolve adopts the thenable; its outcome, or a then that throws, settles a promise observed here.
	Promise.resolve(given as PromiseLike<unknown>).then(ignore, ignore);
	return true;
}

function ignore(): void {}

/**
 * CI4: whether AGP's evidence proved exactly this principal - a verified peer whose verified principal is
 * this one. Any other principal, one a rule derived from the verified one included, is asserted: mapping
 * proof to another principal is verified-principal's, outside Delta 1.
 */
function provenBy(request: IdentityAdmissionRequest, principal: string): boolean {
	const authentication = request.peerEvidence?.authentication;
	return authentication?.kind === "verified" && authentication.principal === principal;
}

class Instance implements CallerIdentity {
	readonly admission: IdentityAdmissionPort;
	readonly #rule: SessionRule;
	readonly #ruling: IdentityAdmissionPort | undefined;
	readonly #deadlineMs: number;
	readonly #clock: ClockPort;
	readonly #diagnostic: DiagnosticPort | undefined;
	readonly #records = new SessionRecords();
	#source: ConnectionSource | undefined;
	#timer: Cancellable | undefined;
	#due = 0;
	/** Counts each start, so a callback scheduled before a stop never sweeps after it. */
	#generation = 0;

	constructor(
		rule: SessionRule,
		ruling: IdentityAdmissionPort | undefined,
		deadlineMs: number,
		clock: ClockPort,
		diagnostic: DiagnosticPort | undefined,
	) {
		this.#rule = rule;
		this.#ruling = ruling;
		this.#deadlineMs = deadlineMs;
		this.#clock = clock;
		this.#diagnostic = diagnostic;
		this.admission = Object.freeze({ evaluate: (request: IdentityAdmissionRequest) => this.#evaluate(request) });
	}

	async #evaluate(request: IdentityAdmissionRequest): Promise<IdentityAdmissionResult> {
		const result = this.#ruling === undefined ? ALLOW : await this.#ruleWithin(this.#ruling, request);
		if (result.decision !== "allow") return result;
		const { principal, proved } = ruled(this.#rule, request);
		this.#records.admit(request.remoteNodeId, request.localSessionId, principal, proved, this.#clock.now());
		return result;
	}

	/**
	 * The host's ruling, answered within the admission deadline (CI2): a ruling that has not answered by then
	 * is taken as a denial with code POLICY, so AGP is never left awaiting it - AGP releases a connection only
	 * once its admission settles - and its later answer, whatever it is, is ignored and records nothing. A
	 * ruling that throws or rejects in time refuses the session, as AGP treats a faulted admission.
	 *
	 * An answer is judged by when it comes on the clock port, not by which callback runs first: an answer,
	 * allow, deny or rejection, that comes at or after the deadline is the POLICY denial, even if it runs
	 * before the deadline's timer. The timer remains for a ruling that never answers.
	 */
	#ruleWithin(ruling: IdentityAdmissionPort, request: IdentityAdmissionRequest): Promise<IdentityAdmissionResult> {
		return new Promise<IdentityAdmissionResult>((resolve, reject) => {
			let settled = false;
			// The absolute deadline on the clock port, captured as admission begins.
			const deadlineAt = this.#clock.now() + this.#deadlineMs;
			// A timer wakeup is not an event: on each, the clock is read, and only once it shows the deadline
			// passed is the ruling denied. A timer that runs early is scheduled again for the time remaining,
			// rounded up, so the answer's path and the timer's both judge by the clock alone.
			let deadline: Cancellable;
			const wake = (): void => {
				if (settled) return;
				const now = this.#clock.now();
				if (now < deadlineAt) {
					deadline = this.#clock.schedule(Math.ceil(deadlineAt - now), wake);
					return;
				}
				settled = true;
				resolve(DEADLINE_DENIAL);
			};
			deadline = this.#clock.schedule(this.#deadlineMs, wake);
			const answer = (settle: () => void): void => {
				// After the decision, any settlement is ignored; it was consumed by the handlers below.
				if (settled) return;
				settled = true;
				deadline.cancel();
				// Equality convention: an answer at the deadline is late. An answer only counts if it comes
				// strictly before deadlineAt; otherwise it is the POLICY denial, and no rule runs, nothing is recorded.
				if (this.#clock.now() >= deadlineAt) {
					resolve(DEADLINE_DENIAL);
					return;
				}
				settle();
			};
			let ruled: Promise<IdentityAdmissionResult>;
			try {
				ruled = Promise.resolve(ruling.evaluate(request));
			} catch (error) {
				answer(() => reject(error));
				return;
			}
			ruled.then(
				(result) => answer(() => resolve(result)),
				(error: unknown) => answer(() => reject(error)),
			);
		});
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
		const generation = this.#generation;
		const now = this.#clock.now();
		if (now < this.#due) {
			// The scheduler ran early by the clock; a sweep runs only once 30 seconds have passed by it.
			this.#schedule(Math.ceil(this.#due - now));
			return;
		}
		let snapshot;
		try {
			snapshot = source.connections();
		} catch (error) {
			// A snapshot that cannot be read changes no record: nothing keeps a record shorter (CI2). It can
			// keep records longer, so the host is told.
			snapshot = undefined;
			this.#report(now, error);
		}
		// The host's diagnostic port may have stopped, or restarted, the sweeping; that start armed its own.
		if (this.#generation !== generation) return;
		if (snapshot !== undefined) this.#records.sweep(snapshot, now);
		this.#arm();
	}

	/** Reports an unreadable snapshot to the host's diagnostic port, if it gave one; a port that throws is ignored. */
	#report(at: number, error: unknown): void {
		if (this.#diagnostic === undefined) return;
		try {
			this.#diagnostic.report(Object.freeze({ kind: "snapshot-unreadable", at, error }));
		} catch {
			// The diagnostic port is the host's; its failure must not stop the sweeping.
		}
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
