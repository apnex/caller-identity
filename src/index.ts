/**
 * Public surface of caller-identity: exactly the capabilities CONTRACT.md lists, and nothing else.
 * createCallerIdentity - session-principal (CI2), request-evidence (CI3, CI4), and verified-principal (CI6):
 *   the identity-admission port a host gives its AGP node, the sweeps it starts and stops with that node,
 *   credential verification, and each request's evidence.
 * assertedNodeRule - session-principal (CI1): the rule for AGP's trusted-development security.
 * verifyCredential - verified-principal (CI6): standalone credential verification across configured verifiers.
 */
export { createCallerIdentity } from "./caller-identity.js";
export { assertedNodeRule } from "./asserted-node-rule.js";
export { verifyCredential } from "./verified-principal.js";
export type { Cancellable, ClockPort } from "./clock.js";
export type {
	AgpSessionEvidence,
	AuthorizationAssociation,
	CallerIdentity,
	CallerIdentityAdmissionPort,
	CallerIdentityDiagnostic,
	CallerIdentityMode,
	CallerIdentityOptions,
	ConnectionSource,
	CredentialVerifier,
	CredentialVerifierResult,
	DeliveryEvidenceInput,
	DiagnosticPort,
	IdentityAdmissionEvaluateOptions,
	RedeemedAdmissionVerifier,
	RedeemedAdmissionVerifyInput,
	RedeemedAdmissionVerifyResult,
	RequestEvidence,
	RuledPrincipal,
	SessionPrincipal,
	SessionRule,
	SnapshotUnreadable,
	VerifiedCredential,
	VerifiedPrincipalEvidence,
	VerifyCredentialOptions,
} from "./identity-types.js";
