/**
 * The public types of caller-identity: the host's rule (CI1), what the component is created with (CI2, CI6),
 * the evidence record of a request (CI3, CI4, CI6), credential verification (CI6), and the parts of AGP's
 * surface it reads.
 */
import type {
	ConnectionListSnapshot,
	EndpointDeliveryContext,
	IdentityAdmissionPort,
	IdentityAdmissionRequest,
	IdentityAdmissionResult,
	IdentityDenialCode,
	NodeId,
	SessionId,
} from "@agp/core";
import type { ClockPort } from "./clock.js";

/** What a host's rule gives for a session: a principal, and whether the evidence proved it. */
export interface RuledPrincipal {
	readonly principal: string;
	readonly proved: boolean;
}

/**
 * A host's rule (CI1): turns a session's evidence - AGP's identity-admission request, carrying the peer's
 * node name and the transport's own evidence - into a principal or into none (`null`), at once. A rule that
 * throws, or returns anything else - a promise included, whose outcome is consumed - refuses the session.
 */
export interface SessionRule {
	apply(request: IdentityAdmissionRequest): RuledPrincipal | null;
}

/** The part of AGP's operations reader the sweeps read: the connection snapshot. */
export interface ConnectionSource {
	connections(): ConnectionListSnapshot;
}

/**
 * A sweep whose connection snapshot could not be read (CI2): it changed no record, and so may keep records
 * longer than the bound of 60 to 90 seconds after a close, by every sweep at which the snapshot cannot be
 * read - at least one sweep interval however brief the failure, since absence is noted, and a record
 * forgotten, only at a sweep that reads the snapshot.
 */
export interface SnapshotUnreadable {
	readonly kind: "snapshot-unreadable";
	/** When the sweep ran, by the host's clock port. */
	readonly at: number;
	/** What reading the snapshot threw. */
	readonly error: unknown;
}

/** Everything caller-identity reports to a host's diagnostic port; `kind` says which. */
export type CallerIdentityDiagnostic = SnapshotUnreadable;

/**
 * A host's diagnostic port (CI2): told of each failure that lengthens how long records are kept. A report
 * that throws is ignored, so a broken port never stops the sweeping.
 */
export interface DiagnosticPort {
	report(diagnostic: CallerIdentityDiagnostic): void;
}

/**
 * What one `CredentialVerifier` returns when a credential establishes a principal (CI6): a plain object with
 * `principal` (1 to 256 Unicode scalar values, no control characters or lone surrogates), optional finite
 * `expiresAt` in milliseconds on the host's `ClockPort`, and optional `session` (1 to 256 scalar values).
 */
export interface CredentialVerifierResult {
	readonly principal: string;
	readonly expiresAt?: number;
	readonly session?: string;
}

/**
 * A host's credential verifier (`verified-principal`, CI6): a plain object with canonical `issuer` namespace
 * (1 to 256 Unicode scalar values, never `"agp-transport"`) and `verify(credential)`.
 */
export interface CredentialVerifier {
	readonly issuer: string;
	verify(credential: unknown): CredentialVerifierResult | null | Promise<CredentialVerifierResult | null>;
}

/** Options for standalone `verifyCredential` (CI6). */
export interface VerifyCredentialOptions {
	readonly clock?: ClockPort;
}

/**
 * The brand-tagged, deeply frozen result of `verifyCredential` or `callerIdentity.verify` (CI6), passed to
 * `callerIdentity.evidence(delivery, verified)` to produce a `verified-principal` evidence record.
 */
export interface VerifiedCredential {
	readonly kind: "verified-credential";
	readonly principal: string;
	readonly issuer: string;
	readonly proved: true;
	readonly expiresAt: number | null;
	readonly session: string | null;
}

/** Input passed to `RedeemedAdmissionVerifier.verifyRedeemed` during `"authenticated"` session admission (CI2, CI6). */
export interface RedeemedAdmissionVerifyInput {
	readonly redemptionId: string;
	readonly lifecycle: object;
	readonly remoteNodeId: string;
}

/** Plain-data result of `RedeemedAdmissionVerifier.verifyRedeemed` (CI2, CI6). */
export type RedeemedAdmissionVerifyResult =
	| {
			readonly ok: true;
			readonly issuer: string;
			readonly principal: string;
			readonly instanceBinding: string;
	  }
	| {
			readonly ok: false;
			readonly reasonCode?: IdentityDenialCode;
	  };

/** Verifier of redeemed admission records in `"authenticated"` mode (CI2, CI6). */
export interface RedeemedAdmissionVerifier {
	verifyRedeemed(input: RedeemedAdmissionVerifyInput): RedeemedAdmissionVerifyResult | Promise<RedeemedAdmissionVerifyResult>;
}

/**
 * The authorization association returned on `IdentityAdmissionResult` when `mode` is `"unauthenticated"` or
 * `"authenticated"` (CI2, CI6, D71).
 */
export type AuthorizationAssociation =
	| { readonly mode: "unauthenticated" }
	| {
			readonly mode: "authenticated";
			readonly issuer: string;
			readonly principal: string;
			readonly instanceBinding: string;
	  };

/** Options passed by AGP's controller to `IdentityAdmissionPort.evaluate(request, options)` in redeemed admission (CI2, CI6, D71). */
export interface IdentityAdmissionEvaluateOptions {
	readonly redeemedAdmission?: {
		readonly redemptionId: string;
		readonly lifecycle: object;
	};
}

/**
 * `caller-identity`'s identity-admission port (CI2, CI6), compatible with AGP's `IdentityAdmissionPort` both
 * before and after AGP publishes `agp.admission-acquisition/v2`.
 */
export interface CallerIdentityAdmissionPort extends IdentityAdmissionPort {
	readonly supportsRedeemedAdmission?: boolean;
	evaluate(
		request: IdentityAdmissionRequest,
		options?: IdentityAdmissionEvaluateOptions,
	): Promise<IdentityAdmissionResult & { readonly authorizationAssociation?: AuthorizationAssociation }>;
}

/** Explicit session-admission mode (CI2, CI6). */
export type CallerIdentityMode = "unauthenticated" | "authenticated";

/** What caller-identity is created with (CI2, CI6). */
export interface CallerIdentityOptions {
	/**
	 * The host's session rule; required in legacy and `"unauthenticated"` modes, optional in `"authenticated"`
	 * mode where the session principal comes from `redeemedVerifier`.
	 */
	readonly rule?: SessionRule;
	/** Explicit session-admission mode (`"unauthenticated"` or `"authenticated"`). */
	readonly mode?: CallerIdentityMode;
	/** Verifier of redeemed admission records, required when `mode === "authenticated"`. */
	readonly redeemedVerifier?: RedeemedAdmissionVerifier;
	/** Credential verifiers for `verified-principal` (`verify` and `evidence(delivery, verified)`). */
	readonly verifiers?: readonly CredentialVerifier[];
	/** The host's own admission ruling; absent, every peer is admitted (subject to `mode`). */
	readonly admission?: IdentityAdmissionPort;
	/**
	 * How long, in milliseconds on the clock port, the admission port waits for the host's admission ruling
	 * (and `redeemedVerifier` in `"authenticated"` mode) before it answers AGP with a denial, code `POLICY` (CI2);
	 * absent, 10000, AGP's default opening time-out.
	 */
	readonly admissionDeadlineMs?: number;
	/** The host's clock; absent, `performance.now()` and `setTimeout`. */
	readonly clock?: ClockPort;
	/** The host's diagnostic port; absent, failures that lengthen retention are reported nowhere. */
	readonly diagnostic?: DiagnosticPort;
}

/** The principal recorded for one session, and how it was established. */
export interface SessionPrincipal {
	readonly node: NodeId;
	readonly session: SessionId;
	readonly principal: string | null;
	readonly proved: boolean;
}

/** The parts of a request's delivery context that the evidence is built from (CI3, CI6). */
export type DeliveryEvidenceInput = Pick<EndpointDeliveryContext, "source" | "ingressNodeId" | "ingressSessionId">;

/**
 * The evidence of a request that arrived over an AGP session (CI3): exactly these four fields. `node` is
 * always the origin node; `principal` and `proved` are the session's record only when the origin is the
 * ingress node and a record exists for that ingress node and session.
 */
export interface AgpSessionEvidence {
	readonly kind: "agp-session";
	readonly node: NodeId;
	readonly principal: string | null;
	readonly proved: boolean;
}

/**
 * The evidence of a request whose caller presented a credential verified by a host `CredentialVerifier` (CI6):
 * `node` is `delivery.source.originNodeId`, `principal` and `issuer` come from the `VerifiedCredential`,
 * `proved` is `true`, and `expiresAt` is the credential's expiry on the clock port or `null`.
 */
export interface VerifiedPrincipalEvidence {
	readonly kind: "verified-principal";
	readonly node: NodeId;
	readonly principal: string;
	readonly issuer: string;
	readonly proved: true;
	readonly expiresAt: number | null;
}

/**
 * Every kind of request evidence (CI3, CI4, CI6): `kind` says what produced a record (`"agp-session"` or
 * `"verified-principal"`).
 */
export type RequestEvidence = AgpSessionEvidence | VerifiedPrincipalEvidence;

/** One caller-identity instance, as a host embeds it (CI2, CI3, CI4, CI6). */
export interface CallerIdentity {
	/** The identity-admission port to give the host's AGP node, which records each session it admits (CI2, CI6). */
	readonly admission: CallerIdentityAdmissionPort;
	/** Starts sweeping the host node's connection snapshot every 30 seconds by the clock; the host calls it when it starts its node. */
	start(connections: ConnectionSource): void;
	/** Stops sweeping; the host calls it when it stops its node. Records already held stay readable. */
	stop(): void;
	/** The record held for a peer node and the host's own session identifier for it, or `null` when none is held. */
	sessionPrincipal(node: NodeId, session: SessionId): SessionPrincipal | null;
	/** Verifies a credential against the configured `verifiers` (CI6), resolving a brand-tagged `VerifiedCredential` or `null`. */
	verify(credential: unknown): Promise<VerifiedCredential | null>;
	/** The evidence of a request from its delivery context, and from a `VerifiedCredential` when supplied (CI3, CI4, CI6). */
	evidence(delivery: DeliveryEvidenceInput): AgpSessionEvidence;
	evidence(delivery: DeliveryEvidenceInput, verified: VerifiedCredential): VerifiedPrincipalEvidence;
	evidence(delivery: DeliveryEvidenceInput, verified?: VerifiedCredential): RequestEvidence;
}
