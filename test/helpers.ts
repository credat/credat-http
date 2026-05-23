import {
	createAgent,
	createDidWeb,
	delegate,
	generateKeyPair,
	presentCredentials,
} from "@credat/sdk";
import type { AgentIdentity, DelegationConstraints, KeyPair } from "@credat/sdk";
import { CredatHttp } from "../src/http.js";

export interface TestSetup {
	ownerKeyPair: KeyPair;
	ownerDid: string;
	agent: AgentIdentity;
	delegation: string;
	http: CredatHttp;
}

export async function createTestSetup(opts: {
	scopes: string[];
	constraints?: DelegationConstraints;
}): Promise<TestSetup> {
	const ownerKeyPair = generateKeyPair("ES256");
	const ownerDid = createDidWeb("acme.example");
	const agent = await createAgent({ domain: "agents.acme.example" });

	const delegation = await delegate({
		agent: agent.did,
		owner: ownerDid,
		ownerKeyPair,
		scopes: opts.scopes,
		constraints: opts.constraints,
		validUntil: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
	});

	const http = new CredatHttp({
		serverDid: "did:web:api.example.com",
		ownerPublicKey: ownerKeyPair.publicKey,
		agentPublicKey: agent.keyPair.publicKey,
	});

	return { ownerKeyPair, ownerDid, agent, delegation: delegation.token, http };
}

/** Run a full challenge → authenticate handshake and return the session token. */
export async function performHandshake(setup: TestSetup): Promise<string> {
	const challengeReq = new Request("http://test/credat/challenge", { method: "POST" });
	const challengeRes = await setup.http.handlers().challenge(challengeReq);
	const challenge = await challengeRes.json();

	const presentation = await presentCredentials({
		challenge,
		delegation: setup.delegation,
		agent: setup.agent,
	});

	const authReq = new Request("http://test/credat/authenticate", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ presentation }),
	});
	const authRes = await setup.http.handlers().authenticate(authReq);
	const data = (await authRes.json()) as { authenticated: boolean; sessionToken?: string };
	if (!data.authenticated || !data.sessionToken) {
		throw new Error(`Handshake failed: ${JSON.stringify(data)}`);
	}
	return data.sessionToken;
}
