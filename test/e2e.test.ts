import { presentCredentials } from "@credat/sdk";
import express from "express";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { expressHandler, expressProtect } from "../src/express.js";
import { createTestSetup } from "./helpers.js";

async function listen(app: express.Express): Promise<{ url: string; close: () => Promise<void> }> {
	return new Promise((resolve) => {
		const server = app.listen(0, () => {
			const addr = server.address() as AddressInfo;
			resolve({
				url: `http://127.0.0.1:${addr.port}`,
				close: () =>
					new Promise<void>((res, rej) => server.close((err) => (err ? rej(err) : res()))),
			});
		});
	});
}

describe("Express end-to-end", () => {
	it("challenge → authenticate → protected route succeeds; denied without token", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });

		const app = express();
		app.use(express.json());
		app.post(setup.http.paths.challenge, expressHandler(setup.http.handlers().challenge));
		app.post(setup.http.paths.authenticate, expressHandler(setup.http.handlers().authenticate));
		app.get(
			"/emails",
			expressProtect(setup.http.protect({ scopes: ["email:read"] })),
			(req, res) => {
				res.json({ agent: req.credatAuth?.agentDid, inbox: ["one", "two"] });
			},
		);

		const { url, close } = await listen(app);
		try {
			// 1. Challenge
			const challengeRes = await fetch(`${url}${setup.http.paths.challenge}`, { method: "POST" });
			expect(challengeRes.status).toBe(200);
			const challenge = (await challengeRes.json()) as { from: string; nonce: string };

			// 2. Sign with the delegation
			const presentation = await presentCredentials({
				challenge,
				delegation: setup.delegation,
				agent: setup.agent,
			});

			// 3. Authenticate
			const authRes = await fetch(`${url}${setup.http.paths.authenticate}`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ presentation }),
			});
			expect(authRes.status).toBe(200);
			const auth = (await authRes.json()) as {
				authenticated: boolean;
				sessionToken: string;
				scopes: string[];
			};
			expect(auth.authenticated).toBe(true);
			expect(auth.scopes).toEqual(["email:read"]);

			// 4. Protected call with bearer succeeds
			const ok = await fetch(`${url}/emails`, {
				headers: { authorization: `Bearer ${auth.sessionToken}` },
			});
			expect(ok.status).toBe(200);
			const result = (await ok.json()) as { agent: string; inbox: string[] };
			expect(result.agent).toBe(setup.agent.did);
			expect(result.inbox).toEqual(["one", "two"]);

			// 5. Same call without the header → 401
			const denied = await fetch(`${url}/emails`);
			expect(denied.status).toBe(401);
		} finally {
			await close();
		}
	});

	it("a protected route rejects with 403 when the delegated scope is missing", async () => {
		const setup = await createTestSetup({ scopes: ["email:read"] });

		const app = express();
		app.use(express.json());
		app.post(setup.http.paths.challenge, expressHandler(setup.http.handlers().challenge));
		app.post(setup.http.paths.authenticate, expressHandler(setup.http.handlers().authenticate));
		app.post(
			"/send",
			expressProtect(setup.http.protect({ scopes: ["email:send"] })),
			(_req, res) => {
				res.json({ ok: true });
			},
		);

		const { url, close } = await listen(app);
		try {
			const challengeRes = await fetch(`${url}${setup.http.paths.challenge}`, { method: "POST" });
			const challenge = (await challengeRes.json()) as { from: string; nonce: string };
			const presentation = await presentCredentials({
				challenge,
				delegation: setup.delegation,
				agent: setup.agent,
			});
			const authRes = await fetch(`${url}${setup.http.paths.authenticate}`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ presentation }),
			});
			const auth = (await authRes.json()) as { sessionToken: string };

			const denied = await fetch(`${url}/send`, {
				method: "POST",
				headers: {
					authorization: `Bearer ${auth.sessionToken}`,
					"content-type": "application/json",
				},
				body: JSON.stringify({ to: "alice@example.com" }),
			});
			expect(denied.status).toBe(403);
		} finally {
			await close();
		}
	});
});
