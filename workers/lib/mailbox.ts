// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Hono middleware to handle repetitive Mailbox Durable Object instantiation.
 * Checks the signed-in user may open the mailbox, checks it exists in R2,
 * then instantiates the DO stub and attaches it to the Hono context
 * (`c.var.mailboxStub`).
 */
import { createMiddleware } from "hono/factory";
import type { MailboxDO } from "../durableObject";
import type { Env } from "../types";
import { canAccessMailbox, safeDecode, type Session } from "./auth";

export type MailboxContext = {
	Bindings: Env;
	Variables: {
		mailboxStub: DurableObjectStub<MailboxDO>;
		session: Session | null;
	};
};

/** Rejects requests for a mailbox the signed-in user may not open. */
export const requireMailboxAccess = createMiddleware<MailboxContext>(async (c, next) => {
	const rawId = c.req.param("mailboxId");
	if (!rawId) return c.json({ error: "Mailbox ID required" }, 400);
	if (!canAccessMailbox(c.get("session"), rawId)) {
		return c.json({ error: "You don't have access to this mailbox" }, 403);
	}
	await next();
});

export const requireAdmin = createMiddleware<MailboxContext>(async (c, next) => {
	if (c.get("session")?.role !== "admin") {
		return c.json({ error: "Admin only" }, 403);
	}
	await next();
});

export const requireMailbox = createMiddleware<MailboxContext>(async (c, next) => {
	const rawId = c.req.param("mailboxId");
	if (!rawId) return c.json({ error: "Mailbox ID required" }, 400);
	const mailboxId = safeDecode(rawId);
	if (!canAccessMailbox(c.get("session"), mailboxId)) {
		return c.json({ error: "You don't have access to this mailbox" }, 403);
	}

	// Verify mailbox exists
	const key = `mailboxes/${mailboxId}.json`;
	const obj = await c.env.BUCKET.head(key);
	if (!obj) {
		return c.json({ error: "Not found" }, 404);
	}

	// Instantiate DO stub
	const ns = c.env.MAILBOX;
	const id = ns.idFromName(mailboxId);
	const stub = ns.get(id);

	c.set("mailboxStub", stub);

	await next();
});
