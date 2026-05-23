import type {
	Request as ExpressRequest,
	Response as ExpressResponse,
	NextFunction,
	RequestHandler,
} from "express";
import type { ProtectResult } from "./protect.js";
import type { AuthContext } from "./types.js";

declare module "express-serve-static-core" {
	interface Request {
		credatAuth?: AuthContext;
	}
}

type WebHandler = (request: Request) => Promise<Response>;
type ProtectHandler = (request: Request) => Promise<ProtectResult>;

async function toWebRequest(req: ExpressRequest): Promise<Request> {
	const protocol =
		(req.headers["x-forwarded-proto"] as string | undefined) ?? req.protocol ?? "http";
	const host = req.headers.host ?? "localhost";
	const url = `${protocol}://${host}${req.originalUrl ?? req.url}`;

	const headers = new Headers();
	for (const [k, v] of Object.entries(req.headers)) {
		if (Array.isArray(v)) {
			for (const vv of v) headers.append(k, vv);
		} else if (typeof v === "string") {
			headers.set(k, v);
		}
	}

	const method = (req.method ?? "GET").toUpperCase();
	let body: string | undefined;
	if (method !== "GET" && method !== "HEAD" && req.body !== undefined) {
		if (typeof req.body === "string") {
			body = req.body;
		} else if (typeof req.body === "object") {
			body = JSON.stringify(req.body);
			if (!headers.has("content-type")) {
				headers.set("content-type", "application/json");
			}
		}
	}

	return new Request(url, { method, headers, body });
}

async function sendWebResponse(res: ExpressResponse, response: Response): Promise<void> {
	res.status(response.status);
	response.headers.forEach((v, k) => {
		res.setHeader(k, v);
	});
	const text = await response.text();
	res.send(text);
}

/**
 * Adapt a Web Standard handler to Express middleware.
 *
 * Use it to mount the challenge/authenticate handlers:
 *   app.post('/credat/challenge', expressHandler(http.handlers().challenge));
 */
export function expressHandler(handler: WebHandler): RequestHandler {
	return async (req, res, next) => {
		try {
			const webReq = await toWebRequest(req);
			const webRes = await handler(webReq);
			await sendWebResponse(res, webRes);
		} catch (err) {
			next(err);
		}
	};
}

/**
 * Adapt a `protect()` guard to Express middleware. On success it attaches
 * `req.credatAuth` and calls `next()`. On rejection it sends the error response.
 *
 *   app.get('/emails', expressProtect(http.protect({ scopes: ['email:read'] })), handler);
 */
export function expressProtect(protect: ProtectHandler): RequestHandler {
	return async (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => {
		try {
			const webReq = await toWebRequest(req);
			const result = await protect(webReq);
			if (result.ok) {
				req.credatAuth = result.auth;
				next();
			} else {
				await sendWebResponse(res, result.response);
			}
		} catch (err) {
			next(err);
		}
	};
}
