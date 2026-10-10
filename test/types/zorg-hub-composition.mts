// A TypeScript host composing caller-identity as zorg's CI5 says zorg-hub will, compiled by public-types.test.js
// and never run: it gives caller-identity the asserted node rule, supplies its admission port to the host's AGP
// node, starts and stops the sweeping with that node, and answers each request with its evidence, without a cast.
import type { EndpointDeliveryContext } from "@agp/core";
import { createNode } from "@agp/node";
import { assertedNodeRule, createCallerIdentity, type CallerIdentity, type ClockPort, type RequestEvidence } from "@apnex/caller-identity";

const clock: ClockPort = { now: () => performance.now(), schedule: (delayMs, run) => { const h = setTimeout(run, delayMs); return { cancel: () => clearTimeout(h) }; } };
const identity: CallerIdentity = createCallerIdentity({ rule: assertedNodeRule, clock });
const node = createNode({ nodeId: "hub" as never, identityAdmission: { mode: "port" } }, { identityAdmission: identity.admission });

export async function host(): Promise<void> {
	await node.expose("svc" as never, (_payload, context) => {
		const evidence: RequestEvidence = identity.evidence(context.delivery);
		const principal: string | null = evidence.kind === "agp-session" ? evidence.principal : null;
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
