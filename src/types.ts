import type { ChallengeMessage, DelegationConstraints, DelegationResult } from "@credat/sdk";

// ── Utility ──

export type MaybePromise<T> = T | Promise<T>;

// ── Constraint types (mirror @credat/mcp) ──

export interface ConstraintContext {
	transactionValue?: number;
	domain?: string;
	[key: string]: unknown;
}

export interface ConstraintViolation {
	constraint: string;
	message: string;
}

// ── Store interfaces ──

export interface StoredChallenge {
	challenge: ChallengeMessage;
	createdAt: number;
}

export interface SessionAuth {
	delegationResult: DelegationResult & { valid: true };
	authenticatedAt: number;
	expiresAt: number;
}

export interface IChallengeStore {
	set(nonce: string, challenge: ChallengeMessage): MaybePromise<void>;
	consume(nonce: string): MaybePromise<StoredChallenge | undefined>;
}

export interface ISessionStore {
	set(sessionToken: string, auth: SessionAuth): MaybePromise<void>;
	get(sessionToken: string): MaybePromise<SessionAuth | undefined>;
	delete(sessionToken: string): MaybePromise<boolean>;
}

// ── Observability hooks ──

export interface ChallengeIssuedEvent {
	nonce: string;
	timestamp: number;
}

export interface AuthenticatedEvent {
	sessionToken: string;
	agentDid: string;
	ownerDid: string;
	scopes: string[];
	timestamp: number;
}

export interface AuthFailedEvent {
	code: string;
	reason: string;
	agentDid?: string;
	timestamp: number;
}

export interface AccessDeniedEvent {
	sessionToken?: string;
	code: string;
	reason: string;
	agentDid?: string;
	requiredScopes?: string[];
	grantedScopes?: string[];
	violations?: ConstraintViolation[];
	timestamp: number;
}

export interface CredatHttpHooks {
	/** Fired when a challenge nonce is issued */
	onChallengeIssued?: (event: ChallengeIssuedEvent) => void;
	/** Fired when authentication succeeds and a session is created */
	onAuthenticated?: (event: AuthenticatedEvent) => void;
	/** Fired when the authenticate handler rejects (bad nonce, verification failure, ...) */
	onAuthFailed?: (event: AuthFailedEvent) => void;
	/** Fired when a protected route rejects (missing session, scope/constraint violation) */
	onAccessDenied?: (event: AccessDeniedEvent) => void;
}

// ── Configuration ──

export interface CredatHttpOptions {
	/** DID the server identifies itself as (e.g. "did:web:api.example.com") */
	serverDid: string;

	/** Owner public key used to verify delegations */
	ownerPublicKey: Uint8Array;

	/** Static agent public key (single-agent scenarios) */
	agentPublicKey?: Uint8Array;

	/** Resolve an agent's public key from their DID (multi-agent scenarios) */
	resolveAgentKey?: (agentDid: string) => Promise<Uint8Array>;

	/** Max age for challenges before they expire. Default: 5 minutes. */
	challengeMaxAgeMs?: number;

	/** Max age for authenticated sessions. Default: 1 hour. */
	sessionMaxAgeMs?: number;

	/** Custom challenge store (default: in-memory) */
	challengeStore?: IChallengeStore;

	/** Custom session store (default: in-memory) */
	sessionStore?: ISessionStore;

	/** Observability hooks */
	hooks?: CredatHttpHooks;

	/** Override default endpoint paths. */
	paths?: {
		challenge?: string;
		authenticate?: string;
	};
}

// ── Protect ──

export interface ProtectOptions {
	/** All of these scopes must be granted */
	scopes?: string[];

	/** At least one of these scopes must be granted */
	anyScope?: string[];

	/** Constraint context — either a static object or a function deriving it from the request */
	constraintContext?: ConstraintContext | ((request: Request) => MaybePromise<ConstraintContext>);
}

// ── Auth context ──

export interface AuthContext {
	agentDid: string;
	ownerDid: string;
	scopes: string[];
	constraints?: DelegationConstraints;
	sessionToken: string;
}

// ── Response shapes ──

export interface AuthenticateSuccessResponse {
	authenticated: true;
	sessionToken: string;
	expiresAt: number;
	agent: string;
	scopes: string[];
}

export interface AuthErrorBody {
	error: string;
	code: string;
	details?: string[];
}

export type { ChallengeMessage, DelegationConstraints, DelegationResult };
