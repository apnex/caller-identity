/**
 * Public surface of caller-identity: exactly the capabilities CONTRACT.md lists, and nothing else.
 * createCallerIdentity - session-principal (CI2) and request-evidence (CI3, CI4): the identity-admission port
 *   a host gives its AGP node, the sweeps it starts and stops with that node, and each request's evidence.
 * assertedNodeRule - session-principal (CI1): the rule for AGP's trusted-development security.
 * verified-principal is left out of zorg's Delta 1 (zorg's D37).
 */
export { createCallerIdentity } from "./caller-identity.js";
export { assertedNodeRule } from "./asserted-node-rule.js";
export type { Cancellable, ClockPort } from "./clock.js";
export type {
	AgpSessionEvidence,
	CallerIdentity,
	CallerIdentityOptions,
	ConnectionSource,
	DeliveryEvidenceInput,
	RequestEvidence,
	RuledPrincipal,
	SessionPrincipal,
	SessionRule,
} from "./identity-types.js";
