// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { routeAgentRequest } from "agents";
import { type Context, Hono } from "hono";
import { createRequestHandler } from "react-router";
import { app as apiApp, forwardCopy, receiveEmail } from "./index";
import { canAccessMailbox, homePathFor, resolveSession, safeDecode, safeStringEqual } from "./lib/auth";
import type { MailboxContext } from "./lib/mailbox";
import { EmailMCP } from "./mcp";
import type { Env } from "./types";

export { MailboxDO } from "./durableObject";
export { EmailAgent } from "./agent";
export { EmailMCP } from "./mcp";

declare module "react-router" {
	export interface AppLoadContext {
		cloudflare: {
			env: Env;
			ctx: ExecutionContext;
		};
	}
}

const requestHandler = createRequestHandler(
	() => import("virtual:react-router/server-build"),
	import.meta.env.MODE,
);

// Main app that wraps the API and adds React Router fallback
const app = new Hono<MailboxContext>();

// Work out who is signed in (session cookie, or Cloudflare Access JWT for admins).
app.use("*", async (c, next) => {
	c.set("session", await resolveSession(c));
	return next();
});

function sameOrigin(c: Context<MailboxContext>): boolean {
	const origin = c.req.header("origin");
	if (!origin) return true;
	try {
		return new URL(origin).host === new URL(c.req.url).host;
	} catch {
		return false;
	}
}

// MCP server endpoint — used by AI coding tools (ProtoAgent, Claude Code, Cursor, etc.)
// Admins only, or clients sending "Authorization: Bearer <MCP_TOKEN>".
// Must be before API routes and React Router catch-all
const mcpHandler = EmailMCP.serve("/mcp", { binding: "EMAIL_MCP" });
async function mcpAllowed(c: Context<MailboxContext>): Promise<boolean> {
	if (c.get("session")?.role === "admin") return true;
	const token = c.env.MCP_TOKEN;
	const header = c.req.header("authorization") || "";
	if (!token || !header.startsWith("Bearer ")) return false;
	return safeStringEqual(header.slice(7).trim(), token);
}
app.all("/mcp", async (c) => {
	if (!(await mcpAllowed(c))) return c.json({ error: "Unauthorized" }, 401);
	return mcpHandler.fetch(c.req.raw, c.env, c.executionCtx as ExecutionContext);
});
app.all("/mcp/*", async (c) => {
	if (!(await mcpAllowed(c))) return c.json({ error: "Unauthorized" }, 401);
	return mcpHandler.fetch(c.req.raw, c.env, c.executionCtx as ExecutionContext);
});

// Mount the API routes
app.route("/", apiApp);

// Agent WebSocket routing - must be before React Router catch-all.
// Only the email agent is reachable, and only for a mailbox the user may open.
app.all("/agents/*", async (c) => {
	const session = c.get("session");
	if (!session) return c.text("Not signed in", 401);
	if (!sameOrigin(c)) return c.text("Forbidden", 403);
	const parts = new URL(c.req.url).pathname.split("/").filter(Boolean);
	if (parts[1] !== "email-agent" || !parts[2]) return c.text("Agent not found", 404);
	if (!canAccessMailbox(session, safeDecode(parts[2]))) return c.text("Forbidden", 403);
	const response = await routeAgentRequest(c.req.raw, c.env);
	if (response) return response;
	return c.text("Agent not found", 404);
});

// React Router catch-all: serves the SPA for all non-API routes.
// Signed-out visitors go to /login; mailbox users stay inside their own mailbox.
app.all("*", (c) => {
	const url = new URL(c.req.url);
	const path = url.pathname;
	const session = c.get("session");
	const isPublic = path === "/login" || path.startsWith("/__manifest");

	if (!session && !isPublic) {
		const next = path === "/" ? "" : `?next=${encodeURIComponent(path + url.search)}`;
		return c.redirect(`/login${next}`, 302);
	}
	if (session && path === "/login") return c.redirect(homePathFor(session), 302);
	if (session?.role === "mailbox") {
		if (path === "/") return c.redirect(homePathFor(session), 302);
		const match = path.match(/^\/mailbox\/([^/]+)/);
		if (match && !canAccessMailbox(session, safeDecode(match[1]))) {
			return c.redirect(homePathFor(session), 302);
		}
	}

	return requestHandler(c.req.raw, {
		cloudflare: { env: c.env, ctx: c.executionCtx as ExecutionContext },
	});
});

// Export the Hono app as the default export with an email handler
export default {
	fetch: app.fetch,
	async email(
		message: ForwardableEmailMessage,
		env: Env,
		ctx: ExecutionContext,
	) {
		let mailboxId: string | undefined;
		try {
			mailboxId = await receiveEmail(message, env, ctx);
		} catch (e) {
			console.error("Failed to process incoming email:", (e as Error).message, (e as Error).stack);
			// Re-throw so Cloudflare's email routing can retry delivery or bounce the message.
			// Swallowing the error would silently drop the email.
			throw e;
		}
		if (mailboxId) await forwardCopy(message, env, mailboxId);
	},
};
