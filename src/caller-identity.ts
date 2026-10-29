/**
 * caller-identity's composition of CI1 to CI4 and CI6: the identity-admission port a host gives its AGP node,
 * the sweeps the host starts and stops with that node, credential verification, and the evidence of each request.
 */
import type {
	ConnectionListSnapshot,
	IdentityAdmissionPort,
	IdentityAdmissionRequest,
	IdentityAdmissionResult,
	IdentityDenialCode,
	NodeId,
	SessionId,
} from "@agp/core";
import { observePromises, readPlainJson } from "@apnex/shape-check";
import { defaultClock, type Cancellable, type ClockPort } from "./clock.js";
import type {
	AgpSessionEvidence,
	AuthorizationAssociation,
	CallerIdentity,
	CallerIdentityAdmissionPort,
	CallerIdentityMode,
	CallerIdentityOptions,
	ConnectionSource,
	DeliveryEvidenceInput,
	DiagnosticPort,
	IdentityAdmissionEvaluateOptions,
	RedeemedAdmissionVerifier,
	RequestEvidence,
	RuledPrincipal,
	SessionPrincipal,
	SessionRule,
	VerifiedCredential,
	VerifiedPrincipalEvidence,
} from "./identity-types.js";
import { SessionRecords } from "./session-records.js";
import {
	assertValidVerifiedCredential,
	isValidBoundedIdentifier,
	isValidIssuer,
	runVerifiers,
	validateClock,
	validateVerifiers,
} from "./verified-principal.js";

/** How often, by the host's clock, the connection snapshot is swept (CI2). */
export const SWEEP_INTERVAL_MS = 30_000;

/** How long the admission port waits for the host's admission ruling, by default: AGP's default opening time-out (CI2). */
export const DEFAULT_ADMISSION_DEADLINE_MS = 10_000;

const ALLOW: IdentityAdmissionResult = Object.freeze({ decision: "allow" });
const ALLOW_UNAUTHENTICATED: IdentityAdmissionResult & { readonly authorizationAssociation: AuthorizationAssociation } = Object.freeze({
	decision: "allow",
	authorizationAssociation: Object.freeze({ mode: "unauthenticated" as const }),
});
/** The answer to an admission whose ruling has not answered by the deadline (CI2). */
const DEADLINE_DENIAL: IdentityAdmissionResult = Object.freeze({ decision: "deny", reasonCode: "POLICY" });
const SECURITY_DENIAL: IdentityAdmissionResult = Object.freeze({ decision: "deny", reasonCode: "SECURITY_EVIDENCE" });

/** Creates one caller-identity instance for one host node. */
export function createCallerIdentity(options: CallerIdentityOptions): CallerIdentity {
	if (typeof options !== "object" || options === null) throw new TypeError("caller-identity needs options");
	const mode = options.mode;
	if (mode !== undefined && mode !== "unauthenticated" && mode !== "authenticated") {
		throw new TypeError("caller-identity mode must be \"unauthenticated\", \"authenticated\", or undefined");
	}
	const rule = options.rule;
	if (mode !== "authenticated") {
		if (typeof rule !== "object" || rule === null || typeof rule.apply !== "function") {
			throw new TypeError("caller-identity needs the host's rule: an object with apply(request)");
		}
	} else if (rule !== undefined && (typeof rule !== "object" || rule === null || typeof rule.apply !== "function")) {
		throw new TypeError("when supplied, the host's rule must be an object with apply(request)");
	}
	const redeemedVerifier = options.redeemedVerifier;
	if (mode === "authenticated") {
		if (typeof redeemedVerifier !== "object" || redeemedVerifier === null || typeof redeemedVerifier.verifyRedeemed !== "function") {
			throw new TypeError("caller-identity in \"authenticated\" mode requires redeemedVerifier with verifyRedeemed(input)");
		}
	} else if (redeemedVerifier !== undefined && (typeof redeemedVerifier !== "object" || redeemedVerifier === null || typeof redeemedVerifier.verifyRedeemed !== "function")) {
		throw new TypeError("when supplied, redeemedVerifier must be an object with verifyRedeemed(input)");
	}
	const verifiers = options.verifiers === undefined ? Object.freeze([]) : validateVerifiers(options.verifiers);
	const ruling = options.admission;
	if (ruling !== undefined && (typeof ruling !== "object" || ruling === null || typeof ruling.evaluate !== "function")) {
		throw new TypeError("an admission ruling is an identity-admission port: an object with evaluate(request)");
	}
	const clock = options.clock === undefined ? defaultClock : validateClock(options.clock);
	const deadlineMs = options.admissionDeadlineMs ?? DEFAULT_ADMISSION_DEADLINE_MS;
	if (typeof deadlineMs !== "number" || !Number.isFinite(deadlineMs) || deadlineMs <= 0) {
		throw new TypeError("an admission deadline is a positive, finite number of milliseconds");
	}
	const diagnostic = options.diagnostic;
	if (diagnostic !== undefined && (typeof diagnostic !== "object" || diagnostic === null || typeof diagnostic.report !== "function")) {
		throw new TypeError("a diagnostic port is an object with report(diagnostic)");
	}
	return new Instance(rule, mode, redeemedVerifier, verifiers, ruling, deadlineMs, clock, diagnostic);
}

const DENIAL_CODES = new Set<IdentityDenialCode>(["POLICY", "EXPECTED_NODE_MISMATCH", "SECURITY_EVIDENCE", "CAPACITY"]);

/** What a rule gave, read as plain data through shape-check (CI1; zorg's D54, D55), with `proved` held to CI4. */
function ruled(rule: SessionRule, request: IdentityAdmissionRequest): { principal: string | null; proved: boolean } {
	let raw: RuledPrincipal | null;
	try {
		raw = rule.apply(request);
	} catch (error) {
		observePromises(error);
		throw error;
	}
	const plain = readPlainJson(raw);
	if (!plain.ok) throw new TypeError("a rule gives null or { principal: string, proved: boolean } as plain data");
	if (plain.value === null) return { principal: null, proved: false };
	if (typeof plain.value !== "object" || Array.isArray(plain.value)) {
		throw new TypeError("a rule gives null or { principal: string, proved: boolean } as plain data");
	}
	const keys = Object.keys(plain.value);
	const { principal, proved } = plain.value as { readonly principal?: unknown; readonly proved?: unknown };
	if (keys.length !== 2 || typeof principal !== "string" || typeof proved !== "boolean") {
		throw new TypeError("a rule gives null or { principal: string, proved: boolean } as plain data");
	}
	return { principal, proved: proved && provenBy(request, principal) };
}

/**
 * Reads an admission ruling's settled answer as plain data (CI2; zorg's D54, D55): `{decision: "allow"}` or
 * `{decision: "deny", reasonCode}` with an AGP `IdentityDenialCode`, or undefined when it is anything else.
 */
function readAdmissionResult(value: unknown): IdentityAdmissionResult | undefined {
	const plain = readPlainJson(value);
	if (!plain.ok || plain.value === null || typeof plain.value !== "object" || Array.isArray(plain.value)) return undefined;
	const keys = Object.keys(plain.value);
	const { decision, reasonCode } = plain.value as { readonly decision?: unknown; readonly reasonCode?: unknown };
	if (decision === "allow" && keys.length === 1) return ALLOW;
	if (decision === "deny" && keys.length === 2 && typeof reasonCode === "string" && DENIAL_CODES.has(reasonCode as IdentityDenialCode)) {
		return Object.freeze({ decision: "deny", reasonCode: reasonCode as IdentityDenialCode });
	}
	return undefined;
}

/**
 * Reads `options` and `options.redeemedAdmission` via own enumerable data descriptors only (CI2, CI6, D54):
 * never invokes a getter, rejects symbol properties or non-plain objects, and requires a valid bounded identifier
 * `redemptionId` and non-null object `lifecycle` (preserving exact object identity of `lifecycle`).
 */
function readRedeemedAdmissionOption(options: unknown): { readonly redemptionId: string; readonly lifecycle: object } | null {
	if (typeof options !== "object" || options === null || Array.isArray(options)) return null;
	const optProto = Object.getPrototypeOf(options);
	if (optProto !== Object.prototype && optProto !== null) return null;
	if (Object.getOwnPropertySymbols(options).length > 0) return null;
	for (const key of Object.getOwnPropertyNames(options)) {
		const desc = Object.getOwnPropertyDescriptor(options, key);
		if (desc === undefined || !desc.enumerable || !("value" in desc)) return null;
	}
	const raDesc = Object.getOwnPropertyDescriptor(options, "redeemedAdmission");
	if (raDesc === undefined || !raDesc.enumerable || !("value" in raDesc)) return null;
	const ra = raDesc.value as unknown;
	if (typeof ra !== "object" || ra === null || Array.isArray(ra)) return null;
	const raProto = Object.getPrototypeOf(ra);
	if (raProto !== Object.prototype && raProto !== null) return null;
	if (Object.getOwnPropertySymbols(ra).length > 0) return null;
	const raKeys = Object.getOwnPropertyNames(ra);
	if (raKeys.length !== 2) return null;
	const idDesc = Object.getOwnPropertyDescriptor(ra, "redemptionId");
	const lcDesc = Object.getOwnPropertyDescriptor(ra, "lifecycle");
	if (
		idDesc === undefined ||
		lcDesc === undefined ||
		!idDesc.enumerable ||
		!lcDesc.enumerable ||
		!("value" in idDesc) ||
		!("value" in lcDesc) ||
		!isValidBoundedIdentifier(idDesc.value) ||
		typeof lcDesc.value !== "object" ||
		lcDesc.value === null
	) {
		return null;
	}
	return { redemptionId: idDesc.value, lifecycle: lcDesc.value as object };
}

/**
 * Reads `redeemedVerifier.verifyRedeemed`'s settled answer as plain data through `readPlainJson` (CI2, CI6, D54, D55).
 */
function readRedeemedVerifyResult(
	raw: unknown,
):
	| { readonly ok: true; readonly issuer: string; readonly principal: string; readonly instanceBinding: string }
	| { readonly ok: false; readonly reasonCode: IdentityDenialCode } {
	const plain = readPlainJson(raw);
	if (!plain.ok || plain.value === null || typeof plain.value !== "object" || Array.isArray(plain.value)) {
		return { ok: false, reasonCode: "SECURITY_EVIDENCE" };
	}
	const obj = plain.value as Record<string, unknown>;
	const keys = Object.keys(obj);
	if (obj.ok === true) {
		if (
			keys.length === 4 &&
			isValidIssuer(obj.issuer) &&
			isValidBoundedIdentifier(obj.principal) &&
			isValidBoundedIdentifier(obj.instanceBinding)
		) {
			return {
				ok: true,
				issuer: obj.issuer,
				principal: obj.principal,
				instanceBinding: obj.instanceBinding,
			};
		}
		return { ok: false, reasonCode: "SECURITY_EVIDENCE" };
	}
	if (obj.ok === false) {
		if (keys.length === 1) {
			return { ok: false, reasonCode: "SECURITY_EVIDENCE" };
		}
		if (keys.length === 2 && typeof obj.reasonCode === "string" && DENIAL_CODES.has(obj.reasonCode as IdentityDenialCode)) {
			return { ok: false, reasonCode: obj.reasonCode as IdentityDenialCode };
		}
	}
	return { ok: false, reasonCode: "SECURITY_EVIDENCE" };
}

/**
 * Reads a connection snapshot as plain data (CI2; zorg's D54, D55): `{items}` where each item is a plain object
 * whose `identityState` is `"admitted"` (with string `remoteNodeId` and `sessionId`) or `"pending"` (with string
 * `localSessionId`). Anything else throws a TypeError after `readPlainJson` has observed any native promises.
 */
function readConnectionSnapshot(raw: unknown): ConnectionListSnapshot {
	const plain = readPlainJson(raw);
	if (!plain.ok || plain.value === null || typeof plain.value !== "object" || Array.isArray(plain.value)) {
		throw new TypeError("a connection snapshot must be a plain JSON object with an items array");
	}
	const items = (plain.value as { readonly items?: unknown }).items;
	if (!Array.isArray(items)) {
		throw new TypeError("a connection snapshot must be a plain JSON object with an items array");
	}
	for (const entry of items) {
		if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
			throw new TypeError("each connection snapshot entry must be a plain JSON object");
		}
		const state = (entry as { readonly identityState?: unknown }).identityState;
		if (state === "admitted") {
			const { remoteNodeId, sessionId } = entry as { readonly remoteNodeId?: unknown; readonly sessionId?: unknown };
			if (typeof remoteNodeId !== "string" || typeof sessionId !== "string") {
				throw new TypeError("an admitted connection entry must carry string remoteNodeId and sessionId");
			}
		} else if (state === "pending") {
			const { localSessionId } = entry as { readonly localSessionId?: unknown };
			if (typeof localSessionId !== "string") {
				throw new TypeError("a pending connection entry must carry a string localSessionId");
			}
		} else {
			throw new TypeError("a connection entry's identityState must be admitted or pending");
		}
	}
	return plain.value as unknown as ConnectionListSnapshot;
}

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
	readonly admission: CallerIdentityAdmissionPort;
	readonly #rule: SessionRule | undefined;
	readonly #mode: CallerIdentityMode | undefined;
	readonly #redeemedVerifier: RedeemedAdmissionVerifier | undefined;
	readonly #verifiers: readonly { readonly issuer: string; readonly verify: (credential: unknown) => unknown }[];
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
		rule: SessionRule | undefined,
		mode: CallerIdentityMode | undefined,
		redeemedVerifier: RedeemedAdmissionVerifier | undefined,
		verifiers: readonly { readonly issuer: string; readonly verify: (credential: unknown) => unknown }[],
		ruling: IdentityAdmissionPort | undefined,
		deadlineMs: number,
		clock: ClockPort,
		diagnostic: DiagnosticPort | undefined,
	) {
		this.#rule = rule;
		this.#mode = mode;
		this.#redeemedVerifier = redeemedVerifier;
		this.#verifiers = verifiers;
		this.#ruling = ruling;
		this.#deadlineMs = deadlineMs;
		this.#clock = clock;
		this.#diagnostic = diagnostic;
		const evaluate = (request: IdentityAdmissionRequest, options?: IdentityAdmissionEvaluateOptions) =>
			this.#evaluate(request, options);
		this.admission = mode === "authenticated"
			? Object.freeze({ supportsRedeemedAdmission: true, evaluate })
			: Object.freeze({ evaluate });
	}

	async #evaluate(
		request: IdentityAdmissionRequest,
		options?: IdentityAdmissionEvaluateOptions,
	): Promise<IdentityAdmissionResult & { readonly authorizationAssociation?: AuthorizationAssociation }> {
		const deadlineAt = this.#clock.now() + this.#deadlineMs;
		if (this.#ruling !== undefined) {
			const result = await this.#ruleWithin(this.#ruling, request, deadlineAt);
			if (result.decision !== "allow") return result;
		}
		if (this.#mode === "authenticated") {
			return this.#evaluateAuthenticated(request, options, deadlineAt);
		}
		const { principal, proved } = ruled(this.#rule!, request);
		this.#records.admit(request.remoteNodeId, request.localSessionId, principal, proved, this.#clock.now());
		return this.#mode === "unauthenticated" ? ALLOW_UNAUTHENTICATED : ALLOW;
	}

	/**
	 * Evaluates `"authenticated"` session admission within the remaining `deadlineAt` budget on `#clock` (CI2, CI6).
	 */
	#evaluateAuthenticated(
		request: IdentityAdmissionRequest,
		options: unknown,
		deadlineAt: number,
	): Promise<IdentityAdmissionResult & { readonly authorizationAssociation?: AuthorizationAssociation }> {
		if (this.#clock.now() >= deadlineAt) {
			return Promise.resolve(DEADLINE_DENIAL);
		}
		const redeemed = options === undefined ? null : readRedeemedAdmissionOption(options);
		if (redeemed === null) {
			observePromises(options);
			return Promise.resolve(SECURITY_DENIAL);
		}
		const verifier = this.#redeemedVerifier!;
		const input = Object.freeze({
			redemptionId: redeemed.redemptionId,
			lifecycle: redeemed.lifecycle,
			remoteNodeId: request.remoteNodeId,
		});
		return new Promise((resolve) => {
			let settled = false;
			const remaining = Math.max(1, Math.ceil(deadlineAt - this.#clock.now()));
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
			deadline = this.#clock.schedule(remaining, wake);
			const answer = (finish: (now: number) => void): void => {
				if (settled) return;
				settled = true;
				deadline.cancel();
				const now = this.#clock.now();
				if (now >= deadlineAt) {
					resolve(DEADLINE_DENIAL);
					return;
				}
				finish(now);
			};
			const settleResult = (result: unknown): void => {
				const parsed = readRedeemedVerifyResult(result);
				answer((now) => {
					if (!parsed.ok) {
						resolve(Object.freeze({ decision: "deny", reasonCode: parsed.reasonCode }));
						return;
					}
					this.#records.admit(request.remoteNodeId, request.localSessionId, parsed.principal, true, now);
					resolve(
						Object.freeze({
							decision: "allow",
							authorizationAssociation: Object.freeze({
								mode: "authenticated" as const,
								issuer: parsed.issuer,
								principal: parsed.principal,
								instanceBinding: parsed.instanceBinding,
							}),
						}),
					);
				});
			};
			let raw: unknown;
			try {
				raw = verifier.verifyRedeemed(input);
			} catch (error) {
				observePromises(error);
				answer(() => resolve(SECURITY_DENIAL));
				return;
			}
			let native = false;
			try {
				native = raw instanceof Promise;
			} catch (error) {
				observePromises(error);
				observePromises(raw);
				answer(() => resolve(SECURITY_DENIAL));
				return;
			}
			if (native) {
				try {
					Reflect.apply(Promise.prototype.then, raw, [
						(result: unknown) => settleResult(result),
						(error: unknown) => {
							observePromises(error);
							answer(() => resolve(SECURITY_DENIAL));
						},
					]);
				} catch (error) {
					observePromises(error);
					observePromises(raw);
					answer(() => resolve(SECURITY_DENIAL));
				}
				return;
			}
			settleResult(raw);
		});
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
	#ruleWithin(ruling: IdentityAdmissionPort, request: IdentityAdmissionRequest, deadlineAt: number): Promise<IdentityAdmissionResult> {
		return new Promise<IdentityAdmissionResult>((resolve, reject) => {
			let settled = false;
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
			const settleResult = (result: unknown): void => {
				const checked = readAdmissionResult(result);
				answer(() => {
					if (checked !== undefined) resolve(checked);
					else reject(new TypeError("an admission ruling gives { decision: \"allow\" } or { decision: \"deny\", reasonCode } as plain data"));
				});
			};
			let raw: unknown;
			try {
				raw = ruling.evaluate(request);
			} catch (error) {
				observePromises(error);
				answer(() => reject(error));
				return;
			}
			let native = false;
			try {
				native = raw instanceof Promise;
			} catch (error) {
				observePromises(error);
				observePromises(raw);
				answer(() => reject(error));
				return;
			}
			if (native) {
				try {
					Reflect.apply(Promise.prototype.then, raw, [
						(result: unknown) => settleResult(result),
						(error: unknown) => {
							observePromises(error);
							answer(() => reject(error));
						},
					]);
				} catch (error) {
					observePromises(error);
					observePromises(raw);
					answer(() => reject(error));
				}
				return;
			}
			settleResult(raw);
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
		let snapshot: ConnectionListSnapshot | undefined;
		try {
			snapshot = readConnectionSnapshot(source.connections());
		} catch (error) {
			// A snapshot that cannot be read changes no record: nothing keeps a record shorter (CI2). It can
			// keep records longer, so the host is told.
			observePromises(error);
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
		} catch (diagnosticError) {
			// The diagnostic port is the host's; its failure must not stop the sweeping.
			observePromises(diagnosticError);
		}
	}

	sessionPrincipal(node: NodeId, session: SessionId): SessionPrincipal | null {
		const record = this.#records.find(node, session);
		if (record === undefined) return null;
		return Object.freeze({ node, session, principal: record.principal, proved: record.proved });
	}

	verify(credential: unknown): Promise<VerifiedCredential | null> {
		return runVerifiers(this.#verifiers, credential, this.#clock, this);
	}

	evidence(delivery: DeliveryEvidenceInput): AgpSessionEvidence;
	evidence(delivery: DeliveryEvidenceInput, verified: VerifiedCredential): VerifiedPrincipalEvidence;
	evidence(delivery: DeliveryEvidenceInput, verified?: VerifiedCredential): RequestEvidence {
		const node = delivery?.source?.originNodeId;
		if (typeof (node as unknown) !== "string") throw new TypeError("a delivery context names its origin in source.originNodeId");
		if (verified !== undefined) {
			const cred = assertValidVerifiedCredential(verified, this, this.#clock);
			return Object.freeze({
				kind: "verified-principal",
				node,
				principal: cred.principal,
				issuer: cred.issuer,
				proved: true,
				expiresAt: cred.expiresAt,
			});
		}
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
