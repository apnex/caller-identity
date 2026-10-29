// A TypeScript host composing caller-identity as zorg's CI5 and CI6 say zorg-hub will, compiled by public-types.test.js
// and never run: it gives caller-identity the asserted node rule or redeemedVerifier + verifiers, supplies its
// admission port to the host's AGP node, starts and stops the sweeping with that node, and answers each request
// with its agp-session or verified-principal evidence, without a cast.
import type { EndpointDeliveryContext } from "@agp/core";
import { createNode } from "@agp/node";
import {
	assertedNodeRule,
	createCallerIdentity,
	verifyCredential,
	type AgpSessionEvidence,
	type CallerIdentity,
	type ClockPort,
	type CredentialVerifier,
	type RedeemedAdmissionVerifier,
	type RequestEvidence,
	type VerifiedCredential,
	type VerifiedPrincipalEvidence,
} from "@apnex/caller-identity";

const clock: ClockPort = { now: () => performance.now(), schedule: (delayMs, run) => { const h = setTimeout(run, delayMs); return { cancel: () => clearTimeout(h) }; } };
const verifier: CredentialVerifier = {
	issuer: "zorg-hub",
	verify: (cred) => (cred === "ok" ? { principal: "alice", expiresAt: 2_000_000, session: "s1" } : null),
};
const redeemedVerifier: RedeemedAdmissionVerifier = {
	verifyRedeemed: ({ remoteNodeId }) => ({
		ok: true,
		issuer: "zorg-hub",
		principal: "alice",
		instanceBinding: remoteNodeId,
	}),
};
const identity: CallerIdentity = createCallerIdentity({ rule: assertedNodeRule, verifiers: [verifier], clock });
const authIdentity: CallerIdentity = createCallerIdentity({ mode: "authenticated", redeemedVerifier, verifiers: [verifier], clock });
const node = createNode({ nodeId: "hub" as never, identityAdmission: { mode: "port" } }, { identityAdmission: identity.admission });
const authNode = createNode({ nodeId: "hub-auth" as never, identityAdmission: { mode: "port" } }, { identityAdmission: authIdentity.admission });
void authNode;

export async function host(): Promise<void> {
	await node.expose("svc" as never, async (_payload, context) => {
		const sessionEvidence: AgpSessionEvidence = identity.evidence(context.delivery);
		const cred: VerifiedCredential | null = await identity.verify("ok");
		const standalone: VerifiedCredential | null = await verifyCredential([verifier], "ok", { clock });
		if (cred !== null) {
			const vp: VerifiedPrincipalEvidence = identity.evidence(context.delivery, cred);
			const issuer: string = vp.issuer;
			const expiresAt: number | null = vp.expiresAt;
			void issuer;
			void expiresAt;
		}
		const evidence: RequestEvidence = standalone !== null
			? identity.evidence(context.delivery, standalone)
			: sessionEvidence;
		const principal: string | null = evidence.principal;
		void principal;
	});
	await node.start();
	identity.start(node.operations);
	identity.stop();
	await node.stop();
}

export function answer(delivery: EndpointDeliveryContext): RequestEvidence {
	return identity.evidence(delivery);
}
