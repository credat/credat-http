import type { ConstraintViolation } from "./types.js";

export const CredatHttpErrorCodes = {
	NOT_AUTHENTICATED: "NOT_AUTHENTICATED",
	SESSION_EXPIRED: "SESSION_EXPIRED",
	INSUFFICIENT_SCOPES: "INSUFFICIENT_SCOPES",
	CONSTRAINT_VIOLATION: "CONSTRAINT_VIOLATION",
	HANDSHAKE_VERIFICATION_FAILED: "HANDSHAKE_VERIFICATION_FAILED",
	CHALLENGE_NOT_FOUND: "CHALLENGE_NOT_FOUND",
	CONFIGURATION_ERROR: "CONFIGURATION_ERROR",
	INVALID_REQUEST: "INVALID_REQUEST",
} as const;

export type CredatHttpErrorCode = (typeof CredatHttpErrorCodes)[keyof typeof CredatHttpErrorCodes];

export function authErrorResponse(
	error: string,
	code: CredatHttpErrorCode,
	details?: string[],
	status = 401,
): Response {
	return Response.json({ error, code, ...(details && { details }) }, { status });
}

export function scopeErrorResponse(required: string[], granted: string[]): Response {
	const missing = required.filter((s) => !granted.includes(s));
	return Response.json(
		{
			error: `Insufficient scopes. Missing: ${missing.join(", ")}`,
			code: CredatHttpErrorCodes.INSUFFICIENT_SCOPES,
			details: [`required: ${required.join(", ")}`, `granted: ${granted.join(", ")}`],
		},
		{ status: 403 },
	);
}

export function constraintErrorResponse(violations: ConstraintViolation[]): Response {
	return Response.json(
		{
			error: `Constraint violation: ${violations.map((v) => v.message).join("; ")}`,
			code: CredatHttpErrorCodes.CONSTRAINT_VIOLATION,
			details: violations.map((v) => `${v.constraint}: ${v.message}`),
		},
		{ status: 403 },
	);
}
