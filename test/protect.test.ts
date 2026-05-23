import { describe, expect, it } from "vitest";
import { CredatHttpErrorCodes } from "../src/errors.js";
import { createTestSetup, performHandshake } from "./helpers.js";

describe("protect", () => {
	it("succeeds when bearer matches and required scope is granted", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });
		const token = await performHandshake(setup);
		const guard = setup.http.protect({ scopes: ["email:read"] });

		const req = new Request("http://test/emails", {
			headers: { authorization: `Bearer ${token}` },
		});
		const result = await guard(req);

		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.auth.scopes).toContain("email:read");
			expect(result.auth.sessionToken).toBe(token);
			expect(result.auth.agentDid).toBe(setup.agent.did);
		}
	});

	it("rejects a missing Authorization header", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });
		const guard = setup.http.protect({ scopes: ["email:read"] });

		const result = await guard(new Request("http://test/emails"));

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.response.status).toBe(401);
			const data = (await result.response.json()) as { code: string };
			expect(data.code).toBe(CredatHttpErrorCodes.NOT_AUTHENTICATED);
		}
	});

	it("rejects an unknown bearer token", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });
		const guard = setup.http.protect({ scopes: ["email:read"] });

		const req = new Request("http://test/emails", {
			headers: { authorization: "Bearer no-such-session" },
		});
		const result = await guard(req);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.response.status).toBe(401);
			const data = (await result.response.json()) as { code: string };
			expect(data.code).toBe(CredatHttpErrorCodes.SESSION_EXPIRED);
		}
	});

	it("rejects when a required scope is missing", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });
		const token = await performHandshake(setup);
		const guard = setup.http.protect({ scopes: ["email:send"] });

		const req = new Request("http://test/emails", {
			headers: { authorization: `Bearer ${token}` },
		});
		const result = await guard(req);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.response.status).toBe(403);
			const data = (await result.response.json()) as { code: string };
			expect(data.code).toBe(CredatHttpErrorCodes.INSUFFICIENT_SCOPES);
		}
	});

	it("anyScope passes when at least one is granted", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });
		const token = await performHandshake(setup);
		const guard = setup.http.protect({ anyScope: ["email:send", "email:read"] });

		const req = new Request("http://test/emails", {
			headers: { authorization: `Bearer ${token}` },
		});
		const result = await guard(req);

		expect(result.ok).toBe(true);
	});

	it("constraintContext rejects values that exceed delegation limits", async () => {
		const setup = await createTestSetup({
			scopes: ["payment:create"],
			constraints: { maxTransactionValue: 100 },
		});
		const token = await performHandshake(setup);
		const guard = setup.http.protect({
			scopes: ["payment:create"],
			constraintContext: { transactionValue: 500 },
		});

		const req = new Request("http://test/pay", {
			headers: { authorization: `Bearer ${token}` },
		});
		const result = await guard(req);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.response.status).toBe(403);
			const data = (await result.response.json()) as { code: string };
			expect(data.code).toBe(CredatHttpErrorCodes.CONSTRAINT_VIOLATION);
		}
	});

	it("constraintContext function form computes context from the request", async () => {
		const setup = await createTestSetup({
			scopes: ["payment:create"],
			constraints: { maxTransactionValue: 100 },
		});
		const token = await performHandshake(setup);
		const guard = setup.http.protect({
			scopes: ["payment:create"],
			constraintContext: async (req) => {
				const url = new URL(req.url);
				const amount = Number(url.searchParams.get("amount") ?? "0");
				return { transactionValue: amount };
			},
		});

		const okReq = new Request("http://test/pay?amount=50", {
			headers: { authorization: `Bearer ${token}` },
		});
		expect((await guard(okReq)).ok).toBe(true);

		const denyReq = new Request("http://test/pay?amount=200", {
			headers: { authorization: `Bearer ${token}` },
		});
		expect((await guard(denyReq)).ok).toBe(false);
	});
});
