import { presentCredentials } from "@credat/sdk";
import { describe, expect, it } from "vitest";
import { CredatHttpErrorCodes } from "../src/errors.js";
import { createTestSetup, performHandshake } from "./helpers.js";

describe("challenge handler", () => {
	it("returns a fresh challenge message", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });
		const req = new Request("http://test/credat/challenge", { method: "POST" });
		const res = await setup.http.handlers().challenge(req);

		expect(res.status).toBe(200);
		const data = (await res.json()) as { from: string; nonce: string };
		expect(data.from).toBe("did:web:api.example.com");
		expect(typeof data.nonce).toBe("string");
		expect(data.nonce.length).toBeGreaterThan(0);
	});
});

describe("authenticate handler", () => {
	it("issues a session token on a valid presentation", async () => {
		const setup = await createTestSetup({ scopes: ["email:read", "email:send"] });
		const token = await performHandshake(setup);

		expect(typeof token).toBe("string");
		expect(token.length).toBe(64); // 32 bytes hex
	});

	it("rejects an unknown nonce", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });

		// Get a valid challenge, then tamper the nonce before signing
		const challengeReq = new Request("http://test/credat/challenge", { method: "POST" });
		const challengeRes = await setup.http.handlers().challenge(challengeReq);
		const challenge = (await challengeRes.json()) as { from: string; nonce: string };
		const presentation = await presentCredentials({
			challenge: { ...challenge, nonce: "this-nonce-was-never-issued" },
			delegation: setup.delegation,
			agent: setup.agent,
		});

		const authReq = new Request("http://test/credat/authenticate", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ presentation }),
		});
		const authRes = await setup.http.handlers().authenticate(authReq);

		expect(authRes.status).toBe(401);
		const data = (await authRes.json()) as { code: string };
		expect(data.code).toBe(CredatHttpErrorCodes.CHALLENGE_NOT_FOUND);
	});

	it("rejects a body without 'presentation'", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });
		const authReq = new Request("http://test/credat/authenticate", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({}),
		});
		const authRes = await setup.http.handlers().authenticate(authReq);

		expect(authRes.status).toBe(400);
		const data = (await authRes.json()) as { code: string };
		expect(data.code).toBe(CredatHttpErrorCodes.INVALID_REQUEST);
	});

	it("rejects malformed JSON", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });
		const authReq = new Request("http://test/credat/authenticate", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: "not json",
		});
		const authRes = await setup.http.handlers().authenticate(authReq);

		expect(authRes.status).toBe(400);
	});

	it("a consumed nonce cannot be replayed", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });

		const challengeReq = new Request("http://test/credat/challenge", { method: "POST" });
		const challengeRes = await setup.http.handlers().challenge(challengeReq);
		const challenge = (await challengeRes.json()) as { from: string; nonce: string };
		const presentation = await presentCredentials({
			challenge,
			delegation: setup.delegation,
			agent: setup.agent,
		});
		const body = JSON.stringify({ presentation });

		// First authenticate — succeeds.
		const first = await setup.http
			.handlers()
			.authenticate(
				new Request("http://test/credat/authenticate", {
					method: "POST",
					headers: { "content-type": "application/json" },
					body,
				}),
			);
		expect(first.status).toBe(200);

		// Replay the same presentation — the nonce has been consumed.
		const replay = await setup.http
			.handlers()
			.authenticate(
				new Request("http://test/credat/authenticate", {
					method: "POST",
					headers: { "content-type": "application/json" },
					body,
				}),
			);
		expect(replay.status).toBe(401);
		const data = (await replay.json()) as { code: string };
		expect(data.code).toBe(CredatHttpErrorCodes.CHALLENGE_NOT_FOUND);
	});
});
