import { Button, Input, Text } from "@cloudflare/kumo";
import { EnvelopeSimpleIcon } from "@phosphor-icons/react";
import { type FormEvent, useState } from "react";
import { useSearchParams } from "react-router";
import api, { ApiError } from "~/services/api";

export function meta() {
	return [{ title: "Sign in · Agentic Inbox" }];
}

/** Only allow redirects to paths on this site. */
function safeNext(value: string | null): string | null {
	if (!value || !value.startsWith("/") || value.startsWith("/login")) return null;
	// Reject "//host", "/\host" and control characters, which browsers may treat as another site.
	if (/^\/[\\/]/.test(value) || /[\\\u0000-\u001f]/.test(value)) return null;
	return value;
}

export default function LoginRoute() {
	const [searchParams] = useSearchParams();
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [needCode, setNeedCode] = useState(false);
	const [code, setCode] = useState("");

	const handleSubmit = async (e: FormEvent) => {
		e.preventDefault();
		setError(null);
		if (!email.trim() || !password) {
			setError("Enter your email and password.");
			return;
		}
		if (needCode && code.trim().length < 6) {
			setError("Enter the 6-digit code from your authenticator app.");
			return;
		}
		setIsSubmitting(true);
		try {
			const res = await api.login(email.trim(), password, needCode ? code.trim() : undefined);
			const home = res.role === "mailbox" && res.mailbox ? `/mailbox/${res.mailbox}/emails/inbox` : "/";
			window.location.assign(safeNext(searchParams.get("next")) ?? home);
		} catch (err) {
			if (err instanceof ApiError && err.body.twoFactorRequired) {
				// Password was right; now ask for the authenticator code.
				setError(needCode ? err.message : null);
				setNeedCode(true);
				setCode("");
			} else {
				setError(
					err instanceof ApiError && err.status !== 500
						? err.message
						: "Couldn't sign in right now. Please try again.",
				);
			}
			setIsSubmitting(false);
		}
	};

	return (
		<div className="min-h-screen bg-kumo-recessed flex items-center justify-center px-4 py-12">
			<div className="w-full max-w-sm">
				<div className="flex flex-col items-center text-center mb-6">
					<div className="flex h-12 w-12 items-center justify-center rounded-full bg-kumo-fill text-kumo-default mb-4">
						<EnvelopeSimpleIcon size={24} weight="duotone" />
					</div>
					<h1 className="text-xl font-semibold text-kumo-default">Sign in to your mailbox</h1>
					<p className="text-sm text-kumo-subtle mt-1">Use your email address and the password you were given.</p>
				</div>

				<form
					onSubmit={handleSubmit}
					className="rounded-xl border border-kumo-line bg-kumo-base p-6 space-y-4"
					noValidate
				>
					{error && (
						<Text variant="error" size="sm">
							{error}
						</Text>
					)}
					<Input
						label="Email address"
						type="email"
						name="email"
						autoComplete="username"
						autoCapitalize="none"
						spellCheck={false}
						placeholder="you@company.com"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						autoFocus
						required
					/>
					<Input
						label="Password"
						type="password"
						name="password"
						autoComplete="current-password"
						value={password}
						onChange={(e) => setPassword(e.target.value)}
						required
					/>
					{needCode && (
						<Input
							label="6-digit code from your authenticator app"
							name="code"
							inputMode="numeric"
							autoComplete="one-time-code"
							placeholder="123456"
							value={code}
							onChange={(e) => setCode(e.target.value)}
							autoFocus
						/>
					)}
					<Button type="submit" variant="primary" className="w-full justify-center" loading={isSubmitting}>
						Sign in
					</Button>
				</form>

				<p className="text-xs text-kumo-subtle text-center mt-4">
					Forgot your password? Ask your administrator to reset it.
				</p>
			</div>
		</div>
	);
}
