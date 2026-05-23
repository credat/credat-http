<p align="center">
  <a href="https://credat.io">
    <img alt="Credat" src="https://raw.githubusercontent.com/credat/credat/main/logo.png" width="120" />
  </a>
</p>

<h1 align="center">@credat/http</h1>

<p align="center">
  <strong>Drop-in Credat protection for HTTP APIs.</strong>
  <br />
  Verify agent identity, delegated permissions, and scopes — before any handler runs.
</p>

<div align="center">

[![npm](https://img.shields.io/npm/v/@credat/http?color=cb3837&logo=npm)](https://www.npmjs.com/package/@credat/http)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-yellow.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-22+-green?logo=node.js)](https://nodejs.org/)

</div>

---

> Your HTTP API is trusted by every AI agent on the planet. Should it be?

Most of what AI agents will talk to isn't an MCP server — it's a plain HTTP API. `@credat/http` is the drop-in middleware that puts Credat in front of any HTTP service: an agent runs the handshake against two endpoints, gets a session token, and your existing routes get a typed `req.credatAuth` with the agent's identity and granted scopes.

Built on Web Standard `Request`/`Response` — works natively in **Hono, Cloudflare Workers, Next.js Route Handlers, Bun, Deno**, with a thin adapter for **Express**.

## Install

```bash
npm install @credat/http @credat/sdk
```

## Quick start — Express

```typescript
import express from "express";
import { CredatHttp } from "@credat/http";
import { expressHandler, expressProtect } from "@credat/http/express";

const http = new CredatHttp({
  serverDid: "did:web:api.example.com",
  ownerPublicKey,
  agentPublicKey,
});

const app = express();
app.use(express.json());

// Two handshake endpoints — agents call these to establish a session.
app.post("/credat/challenge",    expressHandler(http.handlers().challenge));
app.post("/credat/authenticate", expressHandler(http.handlers().authenticate));

// Protect a route — agent must have the required scope.
app.get("/emails",
  expressProtect(http.protect({ scopes: ["email:read"] })),
  (req, res) => {
    res.json({ agent: req.credatAuth!.agentDid, inbox: [...] });
  }
);

// Enforce delegation constraints (e.g. spend caps) from request context.
app.post("/payments",
  expressProtect(http.protect({
    scopes: ["payment:create"],
    constraintContext: (req) => ({ transactionValue: Number(req.body.amount) }),
  })),
  (req, res) => { /* ... */ }
);
```

## Quick start — Hono / Workers / Next.js (Web Standard, no adapter)

```typescript
import { Hono } from "hono";
import { CredatHttp } from "@credat/http";

const http = new CredatHttp({ serverDid: "...", ownerPublicKey, agentPublicKey });
const app = new Hono();

app.post("/credat/challenge",    (c) => http.handlers().challenge(c.req.raw));
app.post("/credat/authenticate", (c) => http.handlers().authenticate(c.req.raw));

app.get("/emails", async (c) => {
  const result = await http.protect({ scopes: ["email:read"] })(c.req.raw);
  if (!result.ok) return result.response;
  return c.json({ agent: result.auth.agentDid });
});
```

## How it works

```
Agent                                Your HTTP API
  │                                        │
  │  1. POST /credat/challenge             │
  │ ─────────────────────────────────────► │
  │  ← { nonce, from, timestamp, ... }     │
  │                                        │
  │  [sign nonce with delegation]          │
  │                                        │
  │  2. POST /credat/authenticate          │
  │     { presentation }                   │
  │ ─────────────────────────────────────► │
  │  ← { authenticated, sessionToken,      │
  │       scopes, expiresAt }              │
  │                                        │
  │  3. GET /emails                        │
  │     Authorization: Bearer <token>      │
  │ ─────────────────────────────────────► │  protect() checks session + scopes
  │  ← 200 { ... }     OR     403 ...      │
```

The handshake reuses the protocol implemented in `@credat/sdk` and pairs with the `HttpTransport` shipped by [`@credat/langchain`](https://www.npmjs.com/package/@credat/langchain). Default paths (`/credat/challenge`, `/credat/authenticate`) match `HttpTransport`'s defaults.

## Configuration

| Option | Default | Notes |
|---|---|---|
| `serverDid` | required | DID the server identifies itself as |
| `ownerPublicKey` | required | `Uint8Array` of the owner key that signed delegations |
| `agentPublicKey` | — | Static agent public key (single-agent scenarios) |
| `resolveAgentKey` | — | `(did) => Promise<Uint8Array>` for multi-agent scenarios |
| `challengeMaxAgeMs` | `5 * 60_000` | Challenge nonce validity window |
| `sessionMaxAgeMs` | `60 * 60_000` | Bearer session TTL |
| `challengeStore` | in-memory | Implement `IChallengeStore` for persistence |
| `sessionStore` | in-memory | Implement `ISessionStore` for persistence |
| `hooks` | — | `onChallengeIssued`, `onAuthenticated`, `onAuthFailed`, `onAccessDenied` |
| `paths` | `/credat/{challenge,authenticate}` | Override the endpoint paths |

## Error responses

All error responses are JSON with `{ error, code, details? }`. Codes mirror `@credat/mcp`:

| Code | HTTP status | Meaning |
|---|---|---|
| `NOT_AUTHENTICATED` | 401 | Missing or invalid `Authorization: Bearer ...` |
| `SESSION_EXPIRED` | 401 | Bearer token unknown or expired — re-authenticate |
| `CHALLENGE_NOT_FOUND` | 401 | Nonce was never issued or already consumed |
| `INSUFFICIENT_SCOPES` | 403 | Agent doesn't have the required scope(s) |
| `CONSTRAINT_VIOLATION` | 403 | Request violates a delegation constraint |
| `HANDSHAKE_VERIFICATION_FAILED` | 401 | Presentation signature/structure invalid |
| `INVALID_REQUEST` | 400 | Malformed body |

## License

Apache-2.0
