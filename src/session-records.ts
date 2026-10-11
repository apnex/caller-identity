/**
 * The session records of CI2: one per admitted session, keyed by the peer's node and the host node's own
 * session identifier for it, forgotten by sweeping AGP's connection snapshot rather than by AGP's events,
 * which may be dropped.
 *
 * A session is present in a snapshot when an admitted connection has the record's peer as `remoteNodeId`
 * and its session identifier as `sessionId`, or when a pending connection - not yet committed, naming only
 * the host's own session identifier - has it as `localSessionId`. Each record keeps when its session was
 * last found present, from the moment it was admitted; the first sweep that finds it absent notes when
 * absence was first seen; and the first sweep at which at least 60 seconds have passed since then forgets
 * the record.
 *
 * Once absence is noted, no later sweep clears it: a session AGP has dropped from its snapshot has closed
 * and never returns, so an entry matching the record afterwards - another peer's pending connection with
 * the same session identifier, or a new session of the same peer reusing it - is not its session. A new
 * session is admitted afresh, and its admission replaces the record. Before absence is noted, a pending or
 * admitted match counts as presence, since a pending entry names no peer and may be the record's own.
 */
import type { ConnectionListSnapshot, NodeId, SessionId } from "@agp/core";

/** How long after absence was first seen a record is kept, at least (CI2). */
export const FORGET_AFTER_ABSENT_MS = 60_000;

/** One session's record. */
interface SessionRecord {
	readonly principal: string | null;
	readonly proved: boolean;
	/** When the session was last found present, starting at the moment it was admitted. */
	lastPresentAt: number;
	/** When a sweep first found the session absent, or `null`; once set, only a new admission resets it. */
	absentSince: number | null;
}

/** The records, by peer node and then by the host's own session identifier. */
export class SessionRecords {
	readonly #byNode = new Map<NodeId, Map<SessionId, SessionRecord>>();

	/** Records an admitted session, replacing any record held for the same key, with no absence noted. */
	admit(node: NodeId, session: SessionId, principal: string | null, proved: boolean, at: number): void {
		let sessions = this.#byNode.get(node);
		if (sessions === undefined) {
			sessions = new Map();
			this.#byNode.set(node, sessions);
		}
		sessions.set(session, { principal, proved, lastPresentAt: at, absentSince: null });
	}

	/** The record held for a key, if any. */
	find(node: NodeId, session: SessionId): { readonly principal: string | null; readonly proved: boolean } | undefined {
		return this.#byNode.get(node)?.get(session);
	}

	/** Applies one sweep, at time `at`, against one connection snapshot. */
	sweep(snapshot: ConnectionListSnapshot, at: number): void {
		const admitted = new Map<NodeId, Set<SessionId>>();
		const pending = new Set<SessionId>();
		for (const connection of snapshot.items) {
			if (connection.identityState === "admitted") {
				let sessions = admitted.get(connection.remoteNodeId);
				if (sessions === undefined) {
					sessions = new Set();
					admitted.set(connection.remoteNodeId, sessions);
				}
				sessions.add(connection.sessionId);
			} else if (connection.identityState === "pending") {
				pending.add(connection.localSessionId);
			}
		}
		for (const [node, sessions] of this.#byNode) {
			for (const [session, record] of sessions) {
				if (record.absentSince !== null) {
					// Noted absence is final: whatever matches now is not this record's session (CI2).
					if (at - record.absentSince >= FORGET_AFTER_ABSENT_MS) sessions.delete(session);
				} else if (admitted.get(node)?.has(session) === true || pending.has(session)) {
					record.lastPresentAt = at;
				} else {
					record.absentSince = at;
				}
			}
			if (sessions.size === 0) this.#byNode.delete(node);
		}
	}
}
