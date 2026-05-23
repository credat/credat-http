# @credat/http — Development Guidelines

## What This Package Does

Drop-in Credat protection for HTTP APIs. Exposes the challenge/authenticate handshake as HTTP endpoints, and protects routes by verifying delegated agent credentials and scopes.

Companion to `@credat/mcp` (MCP servers) and `@credat/langchain` (agent side).

## Architecture

```
CredatHttp (main entry)
├── handlers().challenge    →  POST /credat/challenge      → ChallengeMessage
├── handlers().authenticate →  POST /credat/authenticate   → { authenticated, sessionToken, scopes, ... }
├── protect({ scopes? })    →  (Request) => Promise<AuthContext>  — used in route guards
└── getAuth(req)            →  AuthContext | undefined
```

Core uses Web Standard `Request`/`Response`. Express adapter under `@credat/http/express`.

## Conventions

- Follow the same patterns as `@credat/mcp`
- Named exports only (no default exports)
- Web Standard `Request`/`Response` everywhere internally
- Bearer-token sessions (opaque 256-bit random); pluggable `ISessionStore` (in-memory default)
- Scope/constraint checking via `@credat/sdk`'s `hasAllScopes` / `hasAnyScope` / `validateConstraints` (matching `@credat/mcp`)
- Biome for linting/formatting (tabs, 100 width)
- Vitest for testing

## Endpoints

| Path (default) | Method | Body | Response |
|---|---|---|---|
| `/credat/challenge` | POST | (empty) | `ChallengeMessage` from `@credat/sdk` |
| `/credat/authenticate` | POST | `{ presentation }` | `{ authenticated, sessionToken, scopes, expiresAt }` or 401 |
| protected routes | any | — | header `Authorization: Bearer <sessionToken>` required |

Paths configurable via `paths: { challenge?, authenticate? }` constructor option.

## Don'ts

- Don't add cookie session mode in v0 — bearer only (cookies are a follow-up)
- Don't add a SQLite session store in v0 — in-memory only (follow `@credat/mcp/sqlite` pattern later)
- Don't add Fastify or Hono adapters — they use Web Standard natively; the core just works
- Don't import from `@credat/sdk` internal paths — only from the package root
- Don't use non-null assertions (`!`)
