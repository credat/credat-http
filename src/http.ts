import { createAuthenticateHandler, createChallengeHandler } from "./handlers.js";
import { createProtect, type ProtectResult } from "./protect.js";
import { ChallengeStore, SessionStore } from "./session.js";
import type {
	CredatHttpHooks,
	CredatHttpOptions,
	IChallengeStore,
	ISessionStore,
	ProtectOptions,
	SessionAuth,
} from "./types.js";

const DEFAULT_CHALLENGE_MAX_AGE_MS = 5 * 60 * 1000;
const DEFAULT_SESSION_MAX_AGE_MS = 60 * 60 * 1000;
const DEFAULT_PATHS = {
	challenge: "/credat/challenge",
	authenticate: "/credat/authenticate",
} as const;

export interface CredatHttpHandlers {
	challenge: (request: Request) => Promise<Response>;
	authenticate: (request: Request) => Promise<Response>;
}

export class CredatHttp {
	readonly paths: { challenge: string; authenticate: string };

	private readonly challengeStore: IChallengeStore;
	private readonly sessionStore: ISessionStore;
	private readonly hooks?: CredatHttpHooks;
	private readonly challengeHandler: (req: Request) => Promise<Response>;
	private readonly authenticateHandler: (req: Request) => Promise<Response>;
	private readonly protectFn: ReturnType<typeof createProtect>;

	constructor(options: CredatHttpOptions) {
		if (!options.serverDid) {
			throw new Error("CredatHttp: serverDid is required");
		}
		if (!options.ownerPublicKey || options.ownerPublicKey.length === 0) {
			throw new Error("CredatHttp: ownerPublicKey is required");
		}

		const challengeMaxAge = options.challengeMaxAgeMs ?? DEFAULT_CHALLENGE_MAX_AGE_MS;
		const sessionMaxAge = options.sessionMaxAgeMs ?? DEFAULT_SESSION_MAX_AGE_MS;

		this.paths = {
			challenge: options.paths?.challenge ?? DEFAULT_PATHS.challenge,
			authenticate: options.paths?.authenticate ?? DEFAULT_PATHS.authenticate,
		};
		this.hooks = options.hooks;
		this.challengeStore = options.challengeStore ?? new ChallengeStore(challengeMaxAge);
		this.sessionStore = options.sessionStore ?? new SessionStore();

		this.challengeHandler = createChallengeHandler(
			{ serverDid: options.serverDid },
			this.challengeStore,
			this.hooks,
		);
		this.authenticateHandler = createAuthenticateHandler(
			{
				ownerPublicKey: options.ownerPublicKey,
				agentPublicKey: options.agentPublicKey,
				resolveAgentKey: options.resolveAgentKey,
				challengeMaxAgeMs: challengeMaxAge,
				sessionMaxAgeMs: sessionMaxAge,
			},
			this.challengeStore,
			this.sessionStore,
			this.hooks,
		);
		this.protectFn = createProtect(this.sessionStore, this.hooks);
	}

	/** Framework-agnostic handlers for the two handshake endpoints. */
	handlers(): CredatHttpHandlers {
		return {
			challenge: this.challengeHandler,
			authenticate: this.authenticateHandler,
		};
	}

	/** Route guard. Returns `{ ok, auth }` on success or `{ ok: false, response }` on rejection. */
	protect(opts: ProtectOptions = {}): (req: Request) => Promise<ProtectResult> {
		return this.protectFn(opts);
	}

	/** Look up a session by its bearer token. */
	async getSession(sessionToken: string): Promise<SessionAuth | undefined> {
		return this.sessionStore.get(sessionToken);
	}

	/** Revoke a session, forcing re-authentication on next request. */
	async revokeSession(sessionToken: string): Promise<boolean> {
		return this.sessionStore.delete(sessionToken);
	}
}
