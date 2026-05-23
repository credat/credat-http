import type { ConstraintContext, ConstraintViolation, DelegationConstraints } from "./types.js";

/**
 * Validate a runtime context against the constraints attached to a delegation.
 *
 * Mirrors the logic in `@credat/mcp` so HTTP and MCP services enforce
 * identical rules. Returns an empty array if all constraints pass.
 */
export function validateConstraints(
	constraints: DelegationConstraints | undefined,
	context: ConstraintContext,
): ConstraintViolation[] {
	if (!constraints) return [];
	const violations: ConstraintViolation[] = [];

	if (typeof constraints.maxTransactionValue === "number") {
		if (
			typeof context.transactionValue === "number" &&
			context.transactionValue > constraints.maxTransactionValue
		) {
			violations.push({
				constraint: "maxTransactionValue",
				message: `Transaction value ${context.transactionValue} exceeds limit ${constraints.maxTransactionValue}`,
			});
		}
	}

	if (Array.isArray(constraints.allowedDomains)) {
		if (
			typeof context.domain === "string" &&
			!constraints.allowedDomains.includes(context.domain)
		) {
			violations.push({
				constraint: "allowedDomains",
				message: `Domain '${context.domain}' is not in the allowed list`,
			});
		}
	}

	if (typeof constraints.rateLimit === "number") {
		if (typeof context.rateLimit === "number" && context.rateLimit > constraints.rateLimit) {
			violations.push({
				constraint: "rateLimit",
				message: `Rate ${context.rateLimit} exceeds limit ${constraints.rateLimit}`,
			});
		}
	}

	return violations;
}
