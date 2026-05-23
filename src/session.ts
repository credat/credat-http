import type { ChallengeMessage } from "@credat/sdk";
import type { IChallengeStore, ISessionStore, SessionAuth, StoredChallenge } from "./types.js";

/**
 * In-memory challenge store. Challenges are single-use (consumed on lookup)
 * and time-bounded by `maxAgeMs`. Suitable for single-process deployments.
 */
export class ChallengeStore implements IChallengeStore {
	private readonly store = new Map<string, StoredChallenge>();

	constructor(private readonly maxAgeMs: number) {}

	async set(nonce: string, challenge: ChallengeMessage): Promise<void> {
		this.evictExpired();
		this.store.set(nonce, { challenge, createdAt: Date.now() });
	}

	async consume(nonce: string): Promise<StoredChallenge | undefined> {
		this.evictExpired();
		const entry = this.store.get(nonce);
		if (!entry) return undefined;
		this.store.delete(nonce);
		return entry;
	}

	private evictExpired(): void {
		const cutoff = Date.now() - this.maxAgeMs;
		for (const [k, v] of this.store) {
			if (v.createdAt < cutoff) this.store.delete(k);
		}
	}
}

/**
 * In-memory bearer-token session store. Each session carries its own
 * `expiresAt`; expired entries are evicted lazily on access.
 */
export class SessionStore implements ISessionStore {
	private readonly store = new Map<string, SessionAuth>();

	async set(sessionToken: string, auth: SessionAuth): Promise<void> {
		this.evictExpired();
		this.store.set(sessionToken, auth);
	}

	async get(sessionToken: string): Promise<SessionAuth | undefined> {
		this.evictExpired();
		const session = this.store.get(sessionToken);
		if (!session) return undefined;
		if (session.expiresAt < Date.now()) {
			this.store.delete(sessionToken);
			return undefined;
		}
		return session;
	}

	async delete(sessionToken: string): Promise<boolean> {
		return this.store.delete(sessionToken);
	}

	private evictExpired(): void {
		const now = Date.now();
		for (const [k, v] of this.store) {
			if (v.expiresAt < now) this.store.delete(k);
		}
	}
}
