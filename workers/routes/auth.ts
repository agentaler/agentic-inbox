/**
 * Sign-in API: login / logout / current session / change password,
 * plus the admin endpoint that sets a mailbox's password.
 */
import { Hono } from "hono";
import { z } from "zod";
import {
	adminLoginEnabled,
	allowLoginAttempt,
	clearSessionCookie,
	MAX_PASSWORD_LENGTH,
	normalizeAddress,
	setMailboxPassword,
	startAdminSession,
	startMailboxSession,
	validatePasswordStrength,
	verifyAdminPassword,
	verifyMailboxPassword,
} from "../lib/auth";
import { type MailboxContext, requireAdmin } from "../lib/mailbox";

const LoginBody = z.object({
	email: z.string().trim().min(1).max(254),
	password: z.string().min(1).max(MAX_PASSWORD_LENGTH),
});

const ChangePasswordBody = z.object({
	currentPassword: z.string().min(1).max(MAX_PASSWORD_LENGTH),
	newPassword: z.string().max(MAX_PASSWORD_LENGTH),
});

const SetPasswordBody = z.object({
	password: z.string().max(MAX_PASSWORD_LENGTH),
});

const WRONG_LOGIN = "Wrong email or password.";

const auth = new Hono<MailboxContext>();

auth.post("/api/v1/auth/login", async (c) => {
	const parsed = LoginBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: "Enter your email and password." }, 400);
	const login = normalizeAddress(parsed.data.email);
	const ip = c.req.header("cf-connecting-ip") || "unknown";
	if (!(await allowLoginAttempt(c.env, ip, login))) {
		return c.json({ error: "Too many attempts. Wait a minute and try again." }, 429);
	}

	if (login === "admin") {
		if (!(await verifyAdminPassword(c.env, parsed.data.password))) return c.json({ error: WRONG_LOGIN }, 401);
		await startAdminSession(c);
		return c.json({ role: "admin" });
	}

	const rec = await verifyMailboxPassword(c.env, login, parsed.data.password);
	if (!rec || !(await c.env.BUCKET.head(`mailboxes/${login}.json`))) {
		return c.json({ error: WRONG_LOGIN }, 401);
	}
	await startMailboxSession(c, login, rec);
	return c.json({ role: "mailbox", mailbox: login });
});

auth.post("/api/v1/auth/logout", (c) => {
	const session = c.get("session");
	clearSessionCookie(c);
	// Admins who came in through Cloudflare Access also need to end that session.
	return c.json({ ok: true, accessLogout: session?.role === "admin" && session.via === "access" });
});

auth.get("/api/v1/auth/me", (c) => {
	const session = c.get("session");
	if (!session) return c.json({ error: "Not signed in" }, 401);
	if (session.role === "admin") {
		return c.json({ role: "admin", via: session.via, adminLogin: adminLoginEnabled(c.env) });
	}
	return c.json({ role: "mailbox", mailbox: session.mailbox });
});

auth.put("/api/v1/auth/password", async (c) => {
	const session = c.get("session");
	if (session?.role !== "mailbox") return c.json({ error: "Sign in to a mailbox to change its password." }, 403);
	const parsed = ChangePasswordBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: "Enter your current and new password." }, 400);
	const weak = validatePasswordStrength(parsed.data.newPassword);
	if (weak) return c.json({ error: weak }, 400);
	const ip = c.req.header("cf-connecting-ip") || "unknown";
	if (!(await allowLoginAttempt(c.env, ip, session.mailbox))) {
		return c.json({ error: "Too many attempts. Wait a minute and try again." }, 429);
	}
	if (!(await verifyMailboxPassword(c.env, session.mailbox, parsed.data.currentPassword))) {
		return c.json({ error: "Current password is wrong." }, 400);
	}
	const rec = await setMailboxPassword(c.env, session.mailbox, parsed.data.newPassword);
	// Changing the password signs out other sessions; keep this one signed in.
	await startMailboxSession(c, session.mailbox, rec);
	return c.json({ ok: true });
});

auth.put("/api/v1/admin/mailboxes/:mailboxId/password", requireAdmin, async (c) => {
	const mailboxId = normalizeAddress(c.req.param("mailboxId"));
	if (!(await c.env.BUCKET.head(`mailboxes/${mailboxId}.json`))) return c.json({ error: "Mailbox not found" }, 404);
	const parsed = SetPasswordBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: "Enter a password." }, 400);
	const weak = validatePasswordStrength(parsed.data.password);
	if (weak) return c.json({ error: weak }, 400);
	await setMailboxPassword(c.env, mailboxId, parsed.data.password);
	return c.json({ ok: true });
});

export default auth;
