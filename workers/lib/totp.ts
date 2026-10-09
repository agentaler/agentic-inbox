/**
 * Time-based one-time passwords (RFC 6238, the 6-digit codes from apps like
 * Google Authenticator, 1Password or Authy). Records live in R2 under
 * auth/totp/<login>.json, where <login> is a mailbox address or "admin".
 */
import type { Env } from "../types";

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_SECONDS = 30;
const TOTP_PREFIX = "auth/totp/";

export interface TotpRecord {
	secret: string; // base32
	enabled: boolean;
	/** Last time step accepted, so a code can't be used twice. */
	lastStep?: number;
	createdAt: string;
}

export function base32Encode(bytes: Uint8Array): string {
	let bits = 0;
	let value = 0;
	let out = "";
	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			out += B32[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
		value &= (1 << bits) - 1;
	}
	if (bits > 0) out += B32[(value << (5 - bits)) & 31];
	return out;
}

export function base32Decode(input: string): Uint8Array<ArrayBuffer> {
	const clean = input.toUpperCase().replace(/[\s=]/g, "");
	let bits = 0;
	let value = 0;
	const out: number[] = [];
	for (const ch of clean) {
		const idx = B32.indexOf(ch);
		if (idx < 0) throw new Error("Invalid base32");
		value = (value << 5) | idx;
		bits += 5;
		if (bits >= 8) {
			out.push((value >>> (bits - 8)) & 255);
			bits -= 8;
		}
		value &= (1 << bits) - 1;
	}
	return new Uint8Array(out);
}

export async function hotp(secret: Uint8Array<ArrayBuffer>, counter: number): Promise<string> {
	const buf = new ArrayBuffer(8);
	const view = new DataView(buf);
	view.setUint32(0, Math.floor(counter / 2 ** 32));
	view.setUint32(4, counter >>> 0);
	const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
	const offset = mac[mac.length - 1] & 0x0f;
	const bin =
		((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
	return String(bin % 1_000_000).padStart(6, "0");
}

/**
 * Check a 6-digit code (allowing one step of clock drift either way).
 * Returns the matched time step, or null. Steps at or before lastStep are
 * rejected so a code can't be replayed.
 */
export async function verifyTotpCode(secretB32: string, code: string, lastStep?: number): Promise<number | null> {
	const clean = (code || "").replace(/\s/g, "");
	if (!/^\d{6}$/.test(clean)) return null;
	let secret: Uint8Array<ArrayBuffer>;
	try {
		secret = base32Decode(secretB32);
	} catch {
		return null;
	}
	const now = Math.floor(Date.now() / 1000 / STEP_SECONDS);
	let match: number | null = null;
	for (const step of [now - 1, now, now + 1]) {
		const expected = await hotp(secret, step);
		// Compare every candidate so timing doesn't reveal which step matched.
		let diff = 0;
		for (let i = 0; i < 6; i++) diff |= expected.charCodeAt(i) ^ clean.charCodeAt(i);
		if (diff === 0 && (lastStep === undefined || step > lastStep) && match === null) match = step;
	}
	return match;
}

export function newTotpSecret(): string {
	return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

export function otpauthUrl(issuer: string, login: string, secret: string): string {
	const label = encodeURIComponent(`${issuer}:${login}`);
	const params = new URLSearchParams({ secret, issuer, algorithm: "SHA1", digits: "6", period: String(STEP_SECONDS) });
	return `otpauth://totp/${label}?${params.toString()}`;
}

function totpKey(login: string): string {
	return `${TOTP_PREFIX}${login.toLowerCase()}.json`;
}

export async function getTotp(env: Env, login: string): Promise<TotpRecord | null> {
	const obj = await env.BUCKET.get(totpKey(login));
	if (!obj) return null;
	try {
		return (await obj.json()) as TotpRecord;
	} catch {
		return null;
	}
}

export async function saveTotp(env: Env, login: string, rec: TotpRecord): Promise<void> {
	await env.BUCKET.put(totpKey(login), JSON.stringify(rec), { httpMetadata: { contentType: "application/json" } });
}

export async function deleteTotp(env: Env, login: string): Promise<void> {
	await env.BUCKET.delete(totpKey(login));
}

export async function totpEnabled(env: Env, login: string): Promise<boolean> {
	return (await getTotp(env, login))?.enabled === true;
}
