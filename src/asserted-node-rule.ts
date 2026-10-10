/**
 * The asserted node rule (CONTRACT.md, CI1), for AGP's trusted-development security.
 *
 * It reads only the peer's node name, as AGP's identity-admission request gives it in `remoteNodeId`, and
 * ignores the transport's own evidence. The principal is the name up to its first dot, when there is a dot
 * and that part matches the name pattern; otherwise there is none. Every principal it gives is asserted.
 */
import type { IdentityAdmissionRequest } from "@agp/core";
import type { RuledPrincipal, SessionRule } from "./identity-types.js";

/** The name pattern of zorg's EM1 (D22), which operation-proxy's node names begin with (PX1). */
const PRINCIPAL_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** The asserted node rule: `alice.5c2e9f0a1b3d4e6f` gives `alice`, asserted; a name with no dot gives none. */
export const assertedNodeRule: SessionRule = Object.freeze({
	apply(request: IdentityAdmissionRequest): RuledPrincipal | null {
		const name: unknown = request.remoteNodeId;
		if (typeof name !== "string") return null;
		const dot = name.indexOf(".");
		if (dot < 0) return null;
		const principal = name.slice(0, dot);
		if (!PRINCIPAL_PATTERN.test(principal)) return null;
		return Object.freeze({ principal, proved: false });
	},
});
