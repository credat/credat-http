import type { PresentationMessage } from "@credat/sdk";
import { createChallenge, verifyPresentation } from "@credat/sdk";
import { authErrorResponse, CredatHttpErrorCodes } from "./errors.js";
import type {
	CredatHttpHooks,
	CredatHttpOptions,
	IChallengeStore,
	ISessionStore,
} from "./types.js";

function randomToken(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function createChallengeHandler(
	config: { serverDid: string },
	challengeStore: IChallengeStore,
	hooks?: CredatHttpHooks,
): (request: Request) => Promise<Response> {
	return async (_request: Request): Promise<Response> => {
		const challenge = createChallenge({ from: config.serverDid });
		await challengeStore.set(challenge.nonce, challenge);
		hooks?.onChallengeIssued?.({ nonce: challenge.nonce, timestamp: Date.now() });
		return Response.json(challenge);
	};
}

type AuthenticateConfig = Pick<
	CredatHttpOptions,
	"ownerPublicKey" | "agentPublicKey" | "resolveAgentKey" | "challengeMaxAgeMs" | "sessionMaxAgeMs"
>;

export function createAuthenticateHandler(
	config: AuthenticateConfig,
	challengeStore: IChallengeStore,
	sessionStore: ISessionStore,
	hooks?: CredatHttpHooks,
): (request: Request) => Promise<Response> {
	const sessionMaxAge = config.sessionMaxAgeMs ?? 60 * 60 * 1000;

	return async (request: Request): Promise<Response> => {
		let body: { presentation?: PresentationMessage };
		try {
			body = (await request.json()) as { presentation?: PresentationMessage };
		} catch {
			return authErrorResponse(
				"Invalid JSON body",
				CredatHttpErrorCodes.INVALID_REQUEST,
				undefined,
				400,
			);
		}

		const presentation = body.presentation;
		if (!presentation || typeof presentation !== "object") {
			return authErrorResponse(
				"Missing 'presentation' in request body",
				CredatHttpErrorCodes.INVALID_REQUEST,
				undefined,
				400,
			);
		}

		const stored = await challengeStore.consume(presentation.nonce);
		if (!stored) {
			const reason = "Unknown or expired challenge nonce. Request a new challenge.";
			hooks?.onAuthFailed?.({
				code: CredatHttpErrorCodes.CHALLENGE_NOT_FOUND,
				reason,
				agentDid: presentation.from,
				timestamp: Date.now(),
			});
			return authErrorResponse(reason, CredatHttpErrorCodes.CHALLENGE_NOT_FOUND);
		}

		let agentPublicKey: Uint8Array;
		if (config.agentPublicKey) {
			agentPublicKey = config.agentPublicKey;
		} else if (config.resolveAgentKey) {
			try {
				agentPublicKey = await config.resolveAgentKey(presentation.from);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Unknown error";
				const reason = `Failed to resolve agent public key for ${presentation.from}: ${message}`;
				hooks?.onAuthFailed?.({
					code: CredatHttpErrorCodes.CONFIGURATION_ERROR,
					reason,
					agentDid: presentation.from,
					timestamp: Date.now(),
				});
				return authErrorResponse(reason, CredatHttpErrorCodes.CONFIGURATION_ERROR);
			}
		} else {
			const reason = "No agentPublicKey configured and no resolveAgentKey callback provided.";
			hooks?.onAuthFailed?.({
				code: CredatHttpErrorCodes.CONFIGURATION_ERROR,
				reason,
				timestamp: Date.now(),
			});
			return authErrorResponse(reason, CredatHttpErrorCodes.CONFIGURATION_ERROR);
		}

		const result = await verifyPresentation(presentation, {
			challenge: stored.challenge,
			ownerPublicKey: config.ownerPublicKey,
			agentPublicKey,
			challengeMaxAgeMs: config.challengeMaxAgeMs,
		});

		if (!result.valid) {
			const details = result.errors.map((e) => `${e.code}: ${e.message}`);
			const code = result.errors[0]?.code ?? CredatHttpErrorCodes.HANDSHAKE_VERIFICATION_FAILED;
			hooks?.onAuthFailed?.({
				code,
				reason: "Authentication failed.",
				agentDid: presentation.from,
				timestamp: Date.now(),
			});
			return Response.json({ error: "Authentication failed.", code, details }, { status: 401 });
		}

		const sessionToken = randomToken();
		const expiresAt = Date.now() + sessionMaxAge;
		await sessionStore.set(sessionToken, {
			delegationResult: result,
			authenticatedAt: Date.now(),
			expiresAt,
		});

		hooks?.onAuthenticated?.({
			sessionToken,
			agentDid: result.agent,
			ownerDid: result.owner,
			scopes: result.scopes,
			timestamp: Date.now(),
		});

		return Response.json({
			authenticated: true,
			sessionToken,
			expiresAt,
			agent: result.agent,
			scopes: result.scopes,
		});
	};
}
