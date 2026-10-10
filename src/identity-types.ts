/**
 * The public types of caller-identity: the host's rule (CI1), what the component is created with (CI2), the
 * evidence record of a request (CI3, CI4), and the parts of AGP's surface it reads, as AGP at 1723c9d
 * declares them.
 */
import type {
	ConnectionListSnapshot,
	EndpointDeliveryContext,
	IdentityAdmissionPort,
	IdentityAdmissionRequest,
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
 * node name and the transport's own evidence - into a principal or into none (`null`).
 */
export interface SessionRule {
	apply(request: IdentityAdmissionRequest): RuledPrincipal | null;
}

/** The part of AGP's operations reader the sweeps read: the connection snapshot. */
export interface ConnectionSource {
	connections(): ConnectionListSnapshot;
}

/** What caller-identity is created with. */
export interface CallerIdentityOptions {
	/** The host's rule; none is built in, and `assertedNodeRule` is the one the component offers. */
	readonly rule: SessionRule;
	/** The host's own admission ruling; absent, every peer is admitted. */
	readonly admission?: IdentityAdmissionPort;
	/** The host's clock; absent, `performance.now()` and `setTimeout`. */
	readonly clock?: ClockPort;
}

/** The principal recorded for one session, and how it was established. */
export interface SessionPrincipal {
	readonly node: NodeId;
	readonly session: SessionId;
	readonly principal: string | null;
	readonly proved: boolean;
}

/** The parts of a request's delivery context that the evidence is built from (CI3). */
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
 * Every kind of request evidence (CI4): `kind` says what produced a record, so a later kind of evidence is a
 * new variant here rather than a change to `agp-session`.
 */
export type RequestEvidence = AgpSessionEvidence;

/** One caller-identity instance, as a host embeds it. */
export interface CallerIdentity {
	/** The identity-admission port to give the host's AGP node, which records each session it admits (CI2). */
	readonly admission: IdentityAdmissionPort;
	/** Starts sweeping the host node's connection snapshot every 30 seconds by the clock; the host calls it when it starts its node. */
	start(connections: ConnectionSource): void;
	/** Stops sweeping; the host calls it when it stops its node. Records already held stay readable. */
	stop(): void;
	/** The record held for a peer node and the host's own session identifier for it, or `null` when none is held. */
	sessionPrincipal(node: NodeId, session: SessionId): SessionPrincipal | null;
	/** The evidence of a request, from its delivery context, asked as the request is received (CI3). */
	evidence(delivery: DeliveryEvidenceInput): RequestEvidence;
}
