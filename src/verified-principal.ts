/**
 * verified-principal (CI6): bounded identifier validation, plain-object `CredentialVerifier` validation,
 * credential verification across configured verifiers with `readPlainJson` and `observePromises`, and
 * provenance-branded `VerifiedCredential` minting and checking.
 */
import { observePromises, readPlainJson } from "@apnex/shape-check";
import { defaultClock, type ClockPort } from "./clock.js";
import type {
	CredentialVerifier,
	VerifiedCredential,
	VerifyCredentialOptions,
} from "./identity-types.js";

/** Provenance metadata held in a private `WeakMap` for every `VerifiedCredential` minted by `caller-identity`. */
interface ProvenanceBrand {
	readonly owner: object | null;
	readonly clock: ClockPort;
}

const PROVENANCE = new WeakMap<VerifiedCredential, ProvenanceBrand>();

/**
 * Checks that `value` is a bounded identifier string of 1 to 256 Unicode scalar values (`Array.from(value).length`
 * from 1 to 256) with no control character (`U+0000..U+001F` or `U+007F..U+009F`) and no lone surrogate (`U+D800..U+DFFF`).
 */
export function isValidBoundedIdentifier(value: unknown): value is string {
	if (typeof value !== "string") return false;
	const scalars = Array.from(value);
	if (scalars.length < 1 || scalars.length > 256) return false;
	for (const ch of scalars) {
		const code = ch.codePointAt(0);
		if (code === undefined) return false;
		if (code <= 0x1f || (code >= 0x7f && code <= 0x9f) || (code >= 0xd800 && code <= 0xdfff)) {
			return false;
		}
	}
	return true;
}

/** Checks that `value` is a valid canonical `issuer` namespace (1 to 256 scalar values, never `"agp-transport"`). */
export function isValidIssuer(value: unknown): value is string {
	return isValidBoundedIdentifier(value) && value !== "agp-transport";
}

/** Validates and snapshots a plain-object `CredentialVerifier[]` array at construction (CI6). */
export function validateVerifiers(verifiers: unknown): readonly { readonly issuer: string; readonly verify: (credential: unknown) => unknown }[] {
	if (!Array.isArray(verifiers)) {
		throw new TypeError("verifiers must be an array of plain CredentialVerifier objects");
	}
	const checked: { readonly issuer: string; readonly verify: (credential: unknown) => unknown }[] = [];
	for (const entry of verifiers) {
		if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
			throw new TypeError("each CredentialVerifier must be a plain object with issuer and verify");
		}
		const proto = Object.getPrototypeOf(entry);
		if (proto !== Object.prototype && proto !== null) {
			throw new TypeError("each CredentialVerifier must be a plain object (Object.prototype or null prototype)");
		}
		if (Object.getOwnPropertySymbols(entry).length > 0) {
			throw new TypeError("each CredentialVerifier must have no symbol properties");
		}
		const names = Object.getOwnPropertyNames(entry);
		if (names.length !== 2) {
			throw new TypeError("each CredentialVerifier must have exactly own data properties issuer and verify");
		}
		const issuerDesc = Object.getOwnPropertyDescriptor(entry, "issuer");
		const verifyDesc = Object.getOwnPropertyDescriptor(entry, "verify");
		if (
			issuerDesc === undefined ||
			verifyDesc === undefined ||
			!issuerDesc.enumerable ||
			!verifyDesc.enumerable ||
			!("value" in issuerDesc) ||
			!("value" in verifyDesc) ||
			!isValidIssuer(issuerDesc.value) ||
			typeof verifyDesc.value !== "function"
		) {
			throw new TypeError("each CredentialVerifier must have own enumerable data properties issuer (a valid non-agp-transport identifier) and verify (a function)");
		}
		checked.push(
			Object.freeze({
				issuer: issuerDesc.value,
				verify: verifyDesc.value as (credential: unknown) => unknown,
			}),
		);
	}
	return Object.freeze(checked);
}

/** Validates a `ClockPort` object. */
export function validateClock(clock: unknown): ClockPort {
	if (typeof clock !== "object" || clock === null || typeof (clock as ClockPort).now !== "function" || typeof (clock as ClockPort).schedule !== "function") {
		throw new TypeError("a clock port is an object with now() and schedule(delayMs, callback)");
	}
	return clock as ClockPort;
}

/** Awaits a native `Promise` using `Promise.prototype.then`, or settles synchronously; returns `{ ok: true, value }` or `{ ok: false }`. */
async function settleNativePromiseOrValue(raw: unknown): Promise<{ readonly ok: true; readonly value: unknown } | { readonly ok: false }> {
	let native = false;
	try {
		native = raw instanceof Promise;
	} catch (error) {
		observePromises(error);
		observePromises(raw);
		return { ok: false };
	}
	if (!native) {
		return { ok: true, value: raw };
	}
	return new Promise((resolve) => {
		try {
			Reflect.apply(Promise.prototype.then, raw, [
				(value: unknown) => resolve({ ok: true, value }),
				(error: unknown) => {
					observePromises(error);
					resolve({ ok: false });
				},
			]);
		} catch (error) {
			observePromises(error);
			observePromises(raw);
			resolve({ ok: false });
		}
	});
}

/** Reads one verifier's settled return value as plain data (CI6, D54, D55). */
function readVerifierOutput(
	raw: unknown,
	nowAtCompletion: number,
): { readonly principal: string; readonly expiresAt: number | null; readonly session: string | null } | null {
	const plain = readPlainJson(raw);
	if (!plain.ok || plain.value === null) return null;
	if (typeof plain.value !== "object" || Array.isArray(plain.value)) return null;
	const obj = plain.value as Record<string, unknown>;
	const keys = Object.keys(obj);
	for (const k of keys) {
		if (k !== "principal" && k !== "expiresAt" && k !== "session") return null;
	}
	if (!isValidBoundedIdentifier(obj.principal)) return null;
	let expiresAt: number | null = null;
	if ("expiresAt" in obj) {
		if (typeof obj.expiresAt !== "number" || !Number.isFinite(obj.expiresAt) || !(nowAtCompletion < obj.expiresAt)) {
			return null;
		}
		expiresAt = obj.expiresAt;
	}
	let session: string | null = null;
	if ("session" in obj) {
		if (!isValidBoundedIdentifier(obj.session)) return null;
		session = obj.session;
	}
	return { principal: obj.principal, expiresAt, session };
}

/** Runs validated verifiers against `credential` on `clock` and mints a provenance-branded `VerifiedCredential` or `null` (CI6). */
export async function runVerifiers(
	verifiers: readonly { readonly issuer: string; readonly verify: (credential: unknown) => unknown }[],
	credential: unknown,
	clock: ClockPort,
	owner: object | null,
): Promise<VerifiedCredential | null> {
	const accepted: { readonly issuer: string; readonly principal: string; readonly expiresAt: number | null; readonly session: string | null }[] = [];
	for (const verifier of verifiers) {
		clock.now();
		let raw: unknown;
		try {
			raw = verifier.verify(credential);
		} catch (error) {
			observePromises(error);
			clock.now();
			continue;
		}
		const settled = await settleNativePromiseOrValue(raw);
		const nowAfter = clock.now();
		if (!settled.ok) continue;
		const parsed = readVerifierOutput(settled.value, nowAfter);
		if (parsed === null) continue;
		accepted.push({
			issuer: verifier.issuer,
			principal: parsed.principal,
			expiresAt: parsed.expiresAt,
			session: parsed.session,
		});
	}
	if (accepted.length === 0) return null;
	const first = accepted[0]!;
	let minExpiresAt: number | null = first.expiresAt;
	let agreedSession: string | null = null;
	let sessionConflict = false;
	for (const item of accepted) {
		if (item.issuer !== first.issuer || item.principal !== first.principal) {
			return null;
		}
		if (item.expiresAt !== null) {
			minExpiresAt = minExpiresAt === null ? item.expiresAt : Math.min(minExpiresAt, item.expiresAt);
		}
		if (item.session !== null && !sessionConflict) {
			if (agreedSession === null) {
				agreedSession = item.session;
			} else if (agreedSession !== item.session) {
				agreedSession = null;
				sessionConflict = true;
			}
		}
	}
	const verified: VerifiedCredential = Object.freeze({
		kind: "verified-credential",
		principal: first.principal,
		issuer: first.issuer,
		proved: true,
		expiresAt: minExpiresAt,
		session: sessionConflict ? null : agreedSession,
	});
	PROVENANCE.set(verified, { owner, clock });
	return verified;
}

/**
 * Standalone credential verification (`verified-principal`, CI6): validates `verifiers` and `options`, runs all
 * verifiers on `options?.clock ?? defaultClock`, and resolves a brand-tagged `VerifiedCredential` or `null`.
 */
export async function verifyCredential(
	verifiers: readonly CredentialVerifier[],
	credential: unknown,
	options?: VerifyCredentialOptions,
): Promise<VerifiedCredential | null> {
	const checked = validateVerifiers(verifiers);
	if (options !== undefined && (typeof options !== "object" || options === null || Array.isArray(options))) {
		throw new TypeError("verifyCredential options must be an object when supplied");
	}
	const clock = options?.clock === undefined ? defaultClock : validateClock(options.clock);
	return runVerifiers(checked, credential, clock, null);
}

/**
 * Validates that `verified` carries the provenance brand of a `VerifiedCredential` minted either by `owner`
 * (`CallerIdentity` instance) or by standalone `verifyCredential` on the exact same `clock` (`=== clock`), and
 * that `verified.expiresAt === null || clock.now() < verified.expiresAt` (CI6).
 */
export function assertValidVerifiedCredential(
	verified: unknown,
	owner: object,
	clock: ClockPort,
): VerifiedCredential {
	if (typeof verified !== "object" || verified === null) {
		throw new TypeError("verified must be a VerifiedCredential minted by caller-identity");
	}
	const brand = PROVENANCE.get(verified as VerifiedCredential);
	if (brand === undefined) {
		throw new TypeError("verified must carry caller-identity's VerifiedCredential provenance brand");
	}
	if (brand.owner !== null) {
		if (brand.owner !== owner) {
			throw new TypeError("verified was minted by a different CallerIdentity instance");
		}
	} else if (brand.clock !== clock) {
		throw new TypeError("verified was minted by verifyCredential on a different ClockPort");
	}
	const cred = verified as VerifiedCredential;
	if (cred.expiresAt !== null && !(clock.now() < cred.expiresAt)) {
		throw new TypeError("verified credential has expired on the clock port");
	}
	return cred;
}
