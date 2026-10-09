/**
 * Sign-in for Agentic Inbox.
 *
 * Each mailbox has its own password. People sign in on /login with their
 * mailbox address and password and can only open that mailbox. The special
 * login "admin" (password from the ADMIN_PASSWORD secret) can open every
 * mailbox, create mailboxes and set passwords. A request that carries a valid
 * Cloudflare Access JWT (POLICY_AUD + TEAM_DOMAIN) is also treated as admin.
 *
 * Passwords are hashed with PBKDF2-SHA256 and stored in R2 under
 * auth/mailboxes/<address>.json. Sessions are HMAC-signed cookies; the signing
 * key comes from SESSION_SECRET or is generated once and kept in R2.
 */
import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createRemoteJWKSet, jwtVerify } from "jose";
import type { Env } from "../types";

export type Session =
	| { role: "admin"; via: "access" | "password" }
	| { role: "mailbox"; mailbox: string };

export const SESSION_COOKIE = "inbox_session";
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
export const MIN_PASSWORD_LENGTH = 10;
export const MAX_PASSWORD_LENGTH = 512;

// Workers caps PBKDF2 at 100,000 iterations.
const PBKDF2_ITERATIONS = 100_000;
const AUTH_PREFIX = "auth/mailboxes/";
const SESSION_KEY_OBJECT = "auth/session-key";
const RECORD_CACHE_MS = 30_000;
const LOCK_PREFIX = "auth/lock/";
/** Failed sign-ins allowed per login within LOCK_WINDOW_MS before it is locked. */
const MAX_FAILED_LOGINS = 8;
const LOCK_WINDOW_MS = 15 * 60_000;
const LOCK_DURATION_MS = 15 * 60_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ── Encoding helpers ───────────────────────────────────────────────

export function toB64url(input: ArrayBuffer | Uint8Array): string {
	const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
	let bin = "";
	for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(value: string): Uint8Array<ArrayBuffer> {
	const b64 = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
	const bin = atob(b64);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

export function safeDecode(value: string): string {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

export function normalizeAddress(value: string): string {
	return safeDecode(value).trim().toLowerCase();
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.byteLength !== b.byteLength) return false;
	const subtle = crypto.subtle as SubtleCrypto & {
		timingSafeEqual?: (x: ArrayBufferView, y: ArrayBufferView) => boolean;
	};
	if (typeof subtle.timingSafeEqual === "function") return subtle.timingSafeEqual(a, b);
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
	return diff === 0;
}

async function sha256(value: string): Promise<Uint8Array<ArrayBuffer>> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

/** Constant-time string comparison (compares SHA-256 digests). */
export async function safeStringEqual(a: string, b: string): Promise<boolean> {
	return timingSafeEqual(await sha256(a), await sha256(b));
}

// ── Session signing key ────────────────────────────────────────────

let sessionKeyPromise: Promise<CryptoKey> | null = null;

function getSessionKey(env: Env): Promise<CryptoKey> {
	if (!sessionKeyPromise) {
		sessionKeyPromise = loadSessionKey(env).catch((err) => {
			sessionKeyPromise = null;
			throw err;
		});
	}
	return sessionKeyPromise;
}

async function loadSessionKey(env: Env): Promise<CryptoKey> {
	let raw: Uint8Array<ArrayBuffer>;
	if (env.SESSION_SECRET && env.SESSION_SECRET.length >= 32) {
		raw = encoder.encode(env.SESSION_SECRET);
	} else {
		let obj = await env.BUCKET.get(SESSION_KEY_OBJECT);
		if (!obj) {
			// Create it only if nobody else has (If-None-Match: *), then read back what is stored.
			const fresh = crypto.getRandomValues(new Uint8Array(32));
			try {
				await env.BUCKET.put(SESSION_KEY_OBJECT, fresh, { onlyIf: new Headers({ "If-None-Match": "*" }) });
			} catch {
				/* conditional put unsupported: fall through */
			}
			obj = await env.BUCKET.get(SESSION_KEY_OBJECT);
			if (!obj) {
				await env.BUCKET.put(SESSION_KEY_OBJECT, fresh);
				obj = await env.BUCKET.get(SESSION_KEY_OBJECT);
			}
		}
		if (!obj) throw new Error("Session key unavailable");
		raw = new Uint8Array(await obj.arrayBuffer());
	}
	return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

// ── Signed session tokens ──────────────────────────────────────────

interface TokenPayload {
	/** "a" = admin, "m" = mailbox */
	r: "a" | "m";
	/** mailbox address (mailbox sessions) */
	m?: string;
	/** password version: invalidates sessions when a password changes */
	v?: number | string;
	/** expiry, seconds since epoch */
	exp: number;
}

async function signToken(env: Env, payload: TokenPayload): Promise<string> {
	const body = toB64url(encoder.encode(JSON.stringify(payload)));
	const sig = await crypto.subtle.sign("HMAC", await getSessionKey(env), encoder.encode(body));
	return `${body}.${toB64url(sig)}`;
}

async function verifyToken(env: Env, token: string): Promise<TokenPayload | null> {
	const dot = token.indexOf(".");
	if (dot <= 0 || dot === token.length - 1) return null;
	const body = token.slice(0, dot);
	const sig = token.slice(dot + 1);
	try {
		const ok = await crypto.subtle.verify("HMAC", await getSessionKey(env), fromB64url(sig), encoder.encode(body));
		if (!ok) return null;
		const payload = JSON.parse(decoder.decode(fromB64url(body))) as TokenPayload;
		if (typeof payload.exp !== "number" || payload.exp * 1000 <= Date.now()) return null;
		return payload;
	} catch {
		return null;
	}
}

// ── Mailbox passwords ──────────────────────────────────────────────

interface PasswordRecord {
	salt: string;
	hash: string;
	iterations: number;
	v: number;
	updatedAt: string;
}

const recordCache = new Map<string, { rec: PasswordRecord | null; at: number }>();

function passwordKey(mailbox: string): string {
	return `${AUTH_PREFIX}${mailbox.toLowerCase()}.json`;
}

async function readPasswordRecord(env: Env, mailbox: string): Promise<PasswordRecord | null> {
	const obj = await env.BUCKET.get(passwordKey(mailbox));
	if (!obj) return null;
	try {
		return (await obj.json()) as PasswordRecord;
	} catch {
		return null;
	}
}

async function cachedPasswordRecord(env: Env, mailbox: string): Promise<PasswordRecord | null> {
	const key = mailbox.toLowerCase();
	const hit = recordCache.get(key);
	if (hit && Date.now() - hit.at < RECORD_CACHE_MS) return hit.rec;
	const rec = await readPasswordRecord(env, key);
	recordCache.set(key, { rec, at: Date.now() });
	return rec;
}

async function pbkdf2(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<Uint8Array<ArrayBuffer>> {
	const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
	const bits = await crypto.subtle.deriveBits(
		{ name: "PBKDF2", hash: "SHA-256", salt, iterations },
		material,
		256,
	);
	return new Uint8Array(bits);
}

export function validatePasswordStrength(password: string): string | null {
	if (password.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
	if (password.length > MAX_PASSWORD_LENGTH) return "Password is too long.";
	return null;
}

/**
 * Has this password appeared in a known data breach? Uses the Have I Been Pwned
 * range API (k-anonymity: only the first 5 characters of the SHA-1 hash leave
 * the Worker). Returns false if the check can't be completed.
 */
async function isBreachedPassword(password: string): Promise<boolean> {
	try {
		const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", encoder.encode(password)));
		const hex = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
		const res = await fetch(`https://api.pwnedpasswords.com/range/${hex.slice(0, 5)}`, {
			headers: { "Add-Padding": "true", "User-Agent": "agentic-inbox" },
			signal: AbortSignal.timeout(3000),
		});
		if (!res.ok) return false;
		const suffix = hex.slice(5);
		for (const line of (await res.text()).split("\n")) {
			const [hash, count] = line.trim().split(":");
			if (hash === suffix && Number(count) > 0) return true;
		}
		return false;
	} catch {
		return false;
	}
}

/** Full check for a new password: length, not the address itself, not breached. */
export async function checkNewPassword(password: string, login: string): Promise<string | null> {
	const weak = validatePasswordStrength(password);
	if (weak) return weak;
	const lower = password.toLowerCase();
	const local = login.split("@")[0];
	if (lower === login.toLowerCase() || (local.length >= 4 && lower.includes(local))) {
		return "Don't use the email address in the password.";
	}
	if (await isBreachedPassword(password)) {
		return "This password has appeared in a data breach. Please choose a different one.";
	}
	return null;
}

// ── Lockout after repeated failures ────────────────────────────────

interface LockRecord {
	fails: number;
	first: number;
	lockedUntil?: number;
}

function lockKey(login: string): string {
	return `${LOCK_PREFIX}${login.toLowerCase()}.json`;
}

/** Minutes until this login unlocks, or 0 if it isn't locked. */
export async function lockedForMinutes(env: Env, login: string): Promise<number> {
	const obj = await env.BUCKET.get(lockKey(login));
	if (!obj) return 0;
	try {
		const rec = (await obj.json()) as LockRecord;
		if (rec.lockedUntil && rec.lockedUntil > Date.now()) return Math.ceil((rec.lockedUntil - Date.now()) / 60_000);
	} catch {
		/* treat as unlocked */
	}
	return 0;
}

export async function recordFailedLogin(env: Env, login: string): Promise<void> {
	const now = Date.now();
	let rec: LockRecord = { fails: 0, first: now };
	const obj = await env.BUCKET.get(lockKey(login));
	if (obj) {
		try {
			rec = (await obj.json()) as LockRecord;
		} catch {
			/* start over */
		}
	}
	if (now - rec.first > LOCK_WINDOW_MS || (rec.lockedUntil && rec.lockedUntil <= now)) {
		rec = { fails: 0, first: now };
	}
	rec.fails += 1;
	if (rec.fails >= MAX_FAILED_LOGINS) rec.lockedUntil = now + LOCK_DURATION_MS;
	await env.BUCKET.put(lockKey(login), JSON.stringify(rec));
}

export async function clearFailedLogins(env: Env, login: string): Promise<void> {
	await env.BUCKET.delete(lockKey(login));
}

export async function hasMailboxPassword(env: Env, mailbox: string): Promise<boolean> {
	return (await env.BUCKET.head(passwordKey(mailbox))) !== null;
}

export async function setMailboxPassword(env: Env, mailbox: string, password: string): Promise<PasswordRecord> {
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
	const previous = await readPasswordRecord(env, mailbox);
	const rec: PasswordRecord = {
		salt: toB64url(salt),
		hash: toB64url(hash),
		iterations: PBKDF2_ITERATIONS,
		v: (previous?.v ?? 0) + 1,
		updatedAt: new Date().toISOString(),
	};
	await env.BUCKET.put(passwordKey(mailbox), JSON.stringify(rec), {
		httpMetadata: { contentType: "application/json" },
	});
	recordCache.set(mailbox.toLowerCase(), { rec, at: Date.now() });
	return rec;
}

export async function deleteMailboxPassword(env: Env, mailbox: string): Promise<void> {
	await env.BUCKET.delete(passwordKey(mailbox));
	recordCache.delete(mailbox.toLowerCase());
}

const DUMMY_SALT = new Uint8Array(16);

export async function verifyMailboxPassword(env: Env, mailbox: string, password: string): Promise<PasswordRecord | null> {
	const rec = await readPasswordRecord(env, mailbox);
	if (!rec) {
		// Spend the same time as a real check so unknown addresses are not obvious.
		await pbkdf2(password, DUMMY_SALT, PBKDF2_ITERATIONS);
		return null;
	}
	const hash = await pbkdf2(password, fromB64url(rec.salt), rec.iterations);
	return timingSafeEqual(hash, fromB64url(rec.hash)) ? rec : null;
}

// ── Admin ──────────────────────────────────────────────────────────

export function adminLoginEnabled(env: Env): boolean {
	return typeof env.ADMIN_PASSWORD === "string" && env.ADMIN_PASSWORD.length > 0;
}

export async function verifyAdminPassword(env: Env, password: string): Promise<boolean> {
	if (!adminLoginEnabled(env)) return false;
	return safeStringEqual(password, env.ADMIN_PASSWORD!);
}

/** Short fingerprint of the admin password so changing it signs admins out. */
async function adminVersion(env: Env): Promise<string> {
	return toB64url((await sha256(`admin:${env.ADMIN_PASSWORD ?? ""}`)).slice(0, 9));
}

// ── Cloudflare Access (optional admin path) ────────────────────────

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getAccessUrls(teamDomain: string) {
	const certsPath = "/cdn-cgi/access/certs";
	const teamUrl = new URL(teamDomain);
	const issuer = teamUrl.origin;
	const certsUrl = teamUrl.pathname.endsWith(certsPath) ? teamUrl : new URL(certsPath, issuer);
	return { issuer, certsUrl };
}

export async function verifyAccessJwt(env: Env, token: string | undefined): Promise<boolean> {
	if (!token || !env.POLICY_AUD || !env.TEAM_DOMAIN) return false;
	try {
		const { issuer, certsUrl } = getAccessUrls(env.TEAM_DOMAIN);
		let jwks = jwksCache.get(certsUrl.href);
		if (!jwks) {
			jwks = createRemoteJWKSet(certsUrl);
			jwksCache.set(certsUrl.href, jwks);
		}
		await jwtVerify(token, jwks, { issuer, audience: env.POLICY_AUD });
		return true;
	} catch {
		return false;
	}
}

// ── Sessions ───────────────────────────────────────────────────────

// biome-ignore lint/suspicious/noExplicitAny: works with any Hono context that has our bindings
type AnyContext = Context<{ Bindings: Env; Variables: any }>;

function setSessionCookie(c: AnyContext, token: string) {
	setCookie(c, SESSION_COOKIE, token, {
		httpOnly: true,
		secure: true,
		sameSite: "Lax",
		path: "/",
		maxAge: SESSION_TTL_SECONDS,
	});
}

export function clearSessionCookie(c: AnyContext) {
	deleteCookie(c, SESSION_COOKIE, { path: "/", secure: true });
}

function expiry(): number {
	return Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
}

export async function startMailboxSession(c: AnyContext, mailbox: string, rec: PasswordRecord) {
	setSessionCookie(c, await signToken(c.env, { r: "m", m: mailbox.toLowerCase(), v: rec.v, exp: expiry() }));
}

export async function startAdminSession(c: AnyContext) {
	setSessionCookie(c, await signToken(c.env, { r: "a", v: await adminVersion(c.env), exp: expiry() }));
}

export async function resolveSession(c: AnyContext): Promise<Session | null> {
	const env = c.env;
	if (await verifyAccessJwt(env, c.req.header("cf-access-jwt-assertion"))) {
		return { role: "admin", via: "access" };
	}
	const token = getCookie(c, SESSION_COOKIE);
	if (!token) return null;
	const payload = await verifyToken(env, token);
	if (!payload) return null;
	if (payload.r === "a") {
		if (!adminLoginEnabled(env) || payload.v !== (await adminVersion(env))) return null;
		return { role: "admin", via: "password" };
	}
	if (payload.r === "m" && typeof payload.m === "string") {
		const rec = await cachedPasswordRecord(env, payload.m);
		if (!rec || rec.v !== payload.v) return null;
		return { role: "mailbox", mailbox: payload.m };
	}
	return null;
}

export function canAccessMailbox(session: Session | null | undefined, mailboxId: string): boolean {
	if (!session) return false;
	if (session.role === "admin") return true;
	return session.mailbox === normalizeAddress(mailboxId);
}

export function homePathFor(session: Session): string {
	return session.role === "mailbox" ? `/mailbox/${session.mailbox}/emails/inbox` : "/";
}

/** Login rate limit (per IP and per login). No-op if the LOGIN_LIMITER binding is missing. */
export async function allowLoginAttempt(env: Env, ip: string, login: string): Promise<boolean> {
	type Limiter = { limit(options: { key: string }): Promise<{ success: boolean }> };
	const limiter = (env as unknown as { LOGIN_LIMITER?: Limiter }).LOGIN_LIMITER;
	if (!limiter) return true;
	try {
		const [byIp, byLogin] = await Promise.all([
			limiter.limit({ key: `ip:${ip}` }),
			limiter.limit({ key: `login:${login}` }),
		]);
		return byIp.success && byLogin.success;
	} catch {
		return true;
	}
}
