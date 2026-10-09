/**
 * Sign-in API: login (with optional two-step verification), logout, current
 * session, change password, two-step setup, plus admin endpoints to set a
 * mailbox's password or reset its two-step verification.
 */
import { type Context, Hono } from "hono";
import { z } from "zod";
import {
	adminLoginEnabled,
	allowLoginAttempt,
	checkNewPassword,
	clearFailedLogins,
	clearSessionCookie,
	lockedForMinutes,
	MAX_PASSWORD_LENGTH,
	normalizeAddress,
	recordFailedLogin,
	type Session,
	setMailboxPassword,
	startAdminSession,
	startMailboxSession,
	verifyAdminPassword,
	verifyMailboxPassword,
} from "../lib/auth";
import { type MailboxContext, requireAdmin } from "../lib/mailbox";
import { deleteTotp, getTotp, newTotpSecret, otpauthUrl, saveTotp, verifyTotpCode } from "../lib/totp";

const LoginBody = z.object({
	email: z.string().trim().min(1).max(254),
	password: z.string().min(1).max(MAX_PASSWORD_LENGTH),
	code: z.string().max(16).optional(),
});

const ChangePasswordBody = z.object({
	currentPassword: z.string().min(1).max(MAX_PASSWORD_LENGTH),
	newPassword: z.string().max(MAX_PASSWORD_LENGTH),
});

const SetPasswordBody = z.object({
	password: z.string().max(MAX_PASSWORD_LENGTH),
	resetTwoFactor: z.boolean().optional(),
});

const CodeBody = z.object({ code: z.string().min(1).max(16) });

const WRONG_LOGIN = "Wrong email or password.";

/** The login id two-step verification is attached to, or null (Access admins use Cloudflare's own sign-in). */
function loginIdFor(session: Session | null): string | null {
	if (!session) return null;
	if (session.role === "mailbox") return session.mailbox;
	return session.via === "password" ? "admin" : null;
}

function issuerFor(c: Context<MailboxContext>): string {
	const domain = (c.env.DOMAINS || "").split(",")[0]?.trim();
	return domain ? `${domain} Mail` : "Agentic Inbox";
}

function lockedMessage(minutes: number): string {
	return `Too many failed attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`;
}

const auth = new Hono<MailboxContext>();

auth.post("/api/v1/auth/login", async (c) => {
	const parsed = LoginBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: "Enter your email and password." }, 400);
	const login = normalizeAddress(parsed.data.email);
	const ip = c.req.header("cf-connecting-ip") || "unknown";
	if (!(await allowLoginAttempt(c.env, ip, login))) {
		return c.json({ error: "Too many attempts. Wait a minute and try again." }, 429);
	}
	const locked = await lockedForMinutes(c.env, login);
	if (locked) return c.json({ error: lockedMessage(locked) }, 429);

	// 1. Password
	let mailboxRecord: Awaited<ReturnType<typeof verifyMailboxPassword>> = null;
	if (login === "admin") {
		if (!(await verifyAdminPassword(c.env, parsed.data.password))) {
			await recordFailedLogin(c.env, login);
			return c.json({ error: WRONG_LOGIN }, 401);
		}
	} else {
		mailboxRecord = await verifyMailboxPassword(c.env, login, parsed.data.password);
		if (!mailboxRecord || !(await c.env.BUCKET.head(`mailboxes/${login}.json`))) {
			await recordFailedLogin(c.env, login);
			return c.json({ error: WRONG_LOGIN }, 401);
		}
	}

	// 2. Two-step verification, if turned on for this login
	const totp = await getTotp(c.env, login);
	if (totp?.enabled) {
		if (!parsed.data.code) {
			return c.json({ error: "Enter the 6-digit code from your authenticator app.", twoFactorRequired: true }, 401);
		}
		const step = await verifyTotpCode(totp.secret, parsed.data.code, totp.lastStep);
		if (step === null) {
			await recordFailedLogin(c.env, login);
			return c.json({ error: "That code didn't work. Enter the current code from your app.", twoFactorRequired: true }, 401);
		}
		await saveTotp(c.env, login, { ...totp, lastStep: step });
	}

	await clearFailedLogins(c.env, login);
	if (login === "admin") {
		await startAdminSession(c);
		return c.json({ role: "admin" });
	}
	await startMailboxSession(c, login, mailboxRecord!);
	return c.json({ role: "mailbox", mailbox: login });
});

auth.post("/api/v1/auth/logout", (c) => {
	const session = c.get("session");
	clearSessionCookie(c);
	// Admins who came in through Cloudflare Access also need to end that session.
	return c.json({ ok: true, accessLogout: session?.role === "admin" && session.via === "access" });
});

auth.get("/api/v1/auth/me", async (c) => {
	const session = c.get("session");
	if (!session) return c.json({ error: "Not signed in" }, 401);
	const loginId = loginIdFor(session);
	const twoFactor = loginId ? (await getTotp(c.env, loginId))?.enabled === true : false;
	if (session.role === "admin") {
		return c.json({ role: "admin", via: session.via, adminLogin: adminLoginEnabled(c.env), twoFactor });
	}
	return c.json({ role: "mailbox", mailbox: session.mailbox, twoFactor });
});

auth.put("/api/v1/auth/password", async (c) => {
	const session = c.get("session");
	if (session?.role !== "mailbox") return c.json({ error: "Sign in to a mailbox to change its password." }, 403);
	const parsed = ChangePasswordBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: "Enter your current and new password." }, 400);
	const ip = c.req.header("cf-connecting-ip") || "unknown";
	if (!(await allowLoginAttempt(c.env, ip, session.mailbox))) {
		return c.json({ error: "Too many attempts. Wait a minute and try again." }, 429);
	}
	const locked = await lockedForMinutes(c.env, session.mailbox);
	if (locked) return c.json({ error: lockedMessage(locked) }, 429);
	if (!(await verifyMailboxPassword(c.env, session.mailbox, parsed.data.currentPassword))) {
		await recordFailedLogin(c.env, session.mailbox);
		return c.json({ error: "Current password is wrong." }, 400);
	}
	const problem = await checkNewPassword(parsed.data.newPassword, session.mailbox);
	if (problem) return c.json({ error: problem }, 400);
	const rec = await setMailboxPassword(c.env, session.mailbox, parsed.data.newPassword);
	// Changing the password signs out other sessions; keep this one signed in.
	await startMailboxSession(c, session.mailbox, rec);
	return c.json({ ok: true });
});

// ── Two-step verification (authenticator app) ──────────────────────

auth.post("/api/v1/auth/2fa/setup", async (c) => {
	const loginId = loginIdFor(c.get("session"));
	if (!loginId) return c.json({ error: "Two-step verification is managed by Cloudflare for this sign-in." }, 400);
	const existing = await getTotp(c.env, loginId);
	if (existing?.enabled) return c.json({ error: "Two-step verification is already on." }, 409);
	const secret = newTotpSecret();
	await saveTotp(c.env, loginId, { secret, enabled: false, createdAt: new Date().toISOString() });
	return c.json({ secret, otpauthUrl: otpauthUrl(issuerFor(c), loginId, secret) });
});

auth.post("/api/v1/auth/2fa/enable", async (c) => {
	const loginId = loginIdFor(c.get("session"));
	if (!loginId) return c.json({ error: "Not available for this sign-in." }, 400);
	const parsed = CodeBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: "Enter the 6-digit code." }, 400);
	const rec = await getTotp(c.env, loginId);
	if (!rec) return c.json({ error: "Start the setup again." }, 400);
	if (rec.enabled) return c.json({ ok: true });
	const step = await verifyTotpCode(rec.secret, parsed.data.code);
	if (step === null) return c.json({ error: "That code didn't work. Check the app and try the current code." }, 400);
	await saveTotp(c.env, loginId, { ...rec, enabled: true, lastStep: step });
	return c.json({ ok: true });
});

auth.post("/api/v1/auth/2fa/disable", async (c) => {
	const loginId = loginIdFor(c.get("session"));
	if (!loginId) return c.json({ error: "Not available for this sign-in." }, 400);
	const parsed = CodeBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: "Enter the 6-digit code." }, 400);
	const rec = await getTotp(c.env, loginId);
	if (!rec?.enabled) {
		await deleteTotp(c.env, loginId);
		return c.json({ ok: true });
	}
	const step = await verifyTotpCode(rec.secret, parsed.data.code, rec.lastStep);
	if (step === null) {
		await recordFailedLogin(c.env, loginId);
		return c.json({ error: "That code didn't work." }, 400);
	}
	await deleteTotp(c.env, loginId);
	return c.json({ ok: true });
});

// ── Admin ──────────────────────────────────────────────────────────

auth.put("/api/v1/admin/mailboxes/:mailboxId/password", requireAdmin, async (c) => {
	const mailboxId = normalizeAddress(c.req.param("mailboxId"));
	if (!(await c.env.BUCKET.head(`mailboxes/${mailboxId}.json`))) return c.json({ error: "Mailbox not found" }, 404);
	const parsed = SetPasswordBody.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: "Enter a password." }, 400);
	const problem = await checkNewPassword(parsed.data.password, mailboxId);
	if (problem) return c.json({ error: problem }, 400);
	await setMailboxPassword(c.env, mailboxId, parsed.data.password);
	if (parsed.data.resetTwoFactor) await deleteTotp(c.env, mailboxId);
	await clearFailedLogins(c.env, mailboxId);
	return c.json({ ok: true });
});

auth.delete("/api/v1/admin/mailboxes/:mailboxId/2fa", requireAdmin, async (c) => {
	const mailboxId = normalizeAddress(c.req.param("mailboxId"));
	await deleteTotp(c.env, mailboxId);
	return c.json({ ok: true });
});

export default auth;
