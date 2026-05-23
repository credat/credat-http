import { hasAllScopes, hasAnyScope } from "@credat/sdk";
import { validateConstraints } from "./constraints.js";
import { CredatHttpErrorCodes, constraintErrorResponse, scopeErrorResponse } from "./errors.js";
import type { AuthContext, CredatHttpHooks, ISessionStore, ProtectOptions } from "./types.js";

const BEARER_PREFIX = /^Bearer\s+/i;

function readBearer(request: Request): string | undefined {
	const header = request.headers.get("authorization");
	if (!header || !BEARER_PREFIX.test(header)) return undefined;
	return header.replace(BEARER_PREFIX, "").trim();
}

export type ProtectResult = { ok: true; auth: AuthContext } | { ok: false; response: Response };

export function createProtect(sessionStore: ISessionStore, hooks?: CredatHttpHooks) {
	return function protect(opts: ProtectOptions = {}) {
		return async function protectHandler(request: Request): Promise<ProtectResult> {
			const token = readBearer(request);
			if (!token) {
				const reason =
					"Missing or invalid Authorization header. Provide 'Authorization: Bearer <sessionToken>' from /credat/authenticate.";
				hooks?.onAccessDenied?.({
					code: CredatHttpErrorCodes.NOT_AUTHENTICATED,
					reason,
					timestamp: Date.now(),
				});
				return {
					ok: false,
					response: Response.json(
						{ error: reason, code: CredatHttpErrorCodes.NOT_AUTHENTICATED },
						{ status: 401 },
					),
				};
			}

			const session = await sessionStore.get(token);
			if (!session) {
				const reason = "Session not found or expired. Re-authenticate via /credat/authenticate.";
				hooks?.onAccessDenied?.({
					sessionToken: token,
					code: CredatHttpErrorCodes.SESSION_EXPIRED,
					reason,
					timestamp: Date.now(),
				});
				return {
					ok: false,
					response: Response.json(
						{ error: reason, code: CredatHttpErrorCodes.SESSION_EXPIRED },
						{ status: 401 },
					),
				};
			}

			const { delegationResult } = session;

			if (opts.scopes && opts.scopes.length > 0) {
				if (!hasAllScopes(delegationResult, opts.scopes)) {
					const missing = opts.scopes.filter((s) => !delegationResult.scopes.includes(s));
					hooks?.onAccessDenied?.({
						sessionToken: token,
						code: CredatHttpErrorCodes.INSUFFICIENT_SCOPES,
						reason: `Missing scopes: ${missing.join(", ")}`,
						agentDid: delegationResult.agent,
						requiredScopes: opts.scopes,
						grantedScopes: delegationResult.scopes,
						timestamp: Date.now(),
					});
					return { ok: false, response: scopeErrorResponse(opts.scopes, delegationResult.scopes) };
				}
			}

			if (opts.anyScope && opts.anyScope.length > 0) {
				if (!hasAnyScope(delegationResult, opts.anyScope)) {
					hooks?.onAccessDenied?.({
						sessionToken: token,
						code: CredatHttpErrorCodes.INSUFFICIENT_SCOPES,
						reason: `None of required scopes matched: ${opts.anyScope.join(", ")}`,
						agentDid: delegationResult.agent,
						requiredScopes: opts.anyScope,
						grantedScopes: delegationResult.scopes,
						timestamp: Date.now(),
					});
					return {
						ok: false,
						response: scopeErrorResponse(opts.anyScope, delegationResult.scopes),
					};
				}
			}

			if (opts.constraintContext) {
				const context =
					typeof opts.constraintContext === "function"
						? await opts.constraintContext(request)
						: opts.constraintContext;
				const violations = validateConstraints(delegationResult.constraints, context);
				if (violations.length > 0) {
					hooks?.onAccessDenied?.({
						sessionToken: token,
						code: CredatHttpErrorCodes.CONSTRAINT_VIOLATION,
						reason: violations.map((v) => v.message).join("; "),
						agentDid: delegationResult.agent,
						violations,
						timestamp: Date.now(),
					});
					return { ok: false, response: constraintErrorResponse(violations) };
				}
			}

			const auth: AuthContext = {
				agentDid: delegationResult.agent,
				ownerDid: delegationResult.owner,
				scopes: delegationResult.scopes,
				constraints: delegationResult.constraints,
				sessionToken: token,
			};
			return { ok: true, auth };
		};
	};
}
