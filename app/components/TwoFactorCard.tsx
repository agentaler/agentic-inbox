import { Badge, Button, Input, Text, useKumoToastManager } from "@cloudflare/kumo";
import { ShieldCheckIcon } from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import qrcode from "qrcode-generator";
import { useMemo, useState } from "react";
import { queryKeys } from "~/queries/keys";
import api from "~/services/api";

function qrDataUrl(text: string): string {
	const qr = qrcode(0, "M");
	qr.addData(text);
	qr.make();
	return qr.createDataURL(5, 2);
}

/** Turn two-step verification (authenticator app codes) on or off for the signed-in login. */
export default function TwoFactorCard({ enabled }: { enabled: boolean }) {
	const toastManager = useKumoToastManager();
	const queryClient = useQueryClient();
	const [setup, setSetup] = useState<{ secret: string; otpauthUrl: string } | null>(null);
	const [code, setCode] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [disabling, setDisabling] = useState(false);

	const qr = useMemo(() => (setup ? qrDataUrl(setup.otpauthUrl) : null), [setup]);

	const refresh = () => queryClient.invalidateQueries({ queryKey: queryKeys.session });

	const run = async (fn: () => Promise<void>) => {
		setError(null);
		setBusy(true);
		try {
			await fn();
		} catch (err) {
			setError((err instanceof Error && err.message) || "Something went wrong");
		} finally {
			setBusy(false);
		}
	};

	const startSetup = () =>
		run(async () => {
			setSetup(await api.twoFactorSetup());
			setCode("");
		});

	const confirmSetup = () =>
		run(async () => {
			await api.twoFactorEnable(code.trim());
			toastManager.add({ title: "Two-step verification is on" });
			setSetup(null);
			setCode("");
			await refresh();
		});

	const turnOff = () =>
		run(async () => {
			await api.twoFactorDisable(code.trim());
			toastManager.add({ title: "Two-step verification is off" });
			setDisabling(false);
			setCode("");
			await refresh();
		});

	return (
		<div className="rounded-lg border border-kumo-line bg-kumo-base p-5">
			<div className="flex items-center gap-2 mb-2">
				<ShieldCheckIcon size={16} weight="duotone" className="text-kumo-subtle" />
				<span className="text-sm font-medium text-kumo-default">Two-step verification</span>
				{enabled ? <Badge variant="primary">On</Badge> : <Badge variant="secondary">Off</Badge>}
			</div>
			<p className="text-xs text-kumo-subtle mb-3">
				After your password, sign-in also asks for a 6-digit code from an authenticator app
				(Google Authenticator, Microsoft Authenticator, 1Password…). A stolen password alone is then not enough.
			</p>
			{error && (
				<Text variant="error" size="sm">
					{error}
				</Text>
			)}

			{!enabled && !setup && (
				<Button variant="secondary" onClick={startSetup} loading={busy}>
					Set up two-step verification
				</Button>
			)}

			{!enabled && setup && (
				<div className="space-y-3">
					<p className="text-sm text-kumo-default">1. Scan this code with your authenticator app.</p>
					{qr && (
						<img
							src={qr}
							alt="QR code for your authenticator app"
							className="h-44 w-44 rounded-md border border-kumo-line bg-white p-1"
						/>
					)}
					<p className="text-xs text-kumo-subtle">
						Can't scan? Enter this key instead:{" "}
						<span className="font-mono text-kumo-default break-all">
							{setup.secret.match(/.{1,4}/g)?.join(" ")}
						</span>
					</p>
					<p className="text-sm text-kumo-default">2. Enter the 6-digit code the app shows.</p>
					<div className="flex items-end gap-2">
						<div className="w-40">
							<Input
								aria-label="6-digit code"
								inputMode="numeric"
								autoComplete="one-time-code"
								placeholder="123456"
								value={code}
								onChange={(e) => setCode(e.target.value)}
							/>
						</div>
						<Button variant="primary" onClick={confirmSetup} loading={busy} disabled={code.trim().length < 6}>
							Turn on
						</Button>
						<Button variant="ghost" onClick={() => setSetup(null)}>
							Cancel
						</Button>
					</div>
				</div>
			)}

			{enabled && !disabling && (
				<Button variant="secondary" onClick={() => setDisabling(true)}>
					Turn off
				</Button>
			)}

			{enabled && disabling && (
				<div className="flex items-end gap-2">
					<div className="w-40">
						<Input
							aria-label="Current 6-digit code"
							inputMode="numeric"
							autoComplete="one-time-code"
							placeholder="123456"
							value={code}
							onChange={(e) => setCode(e.target.value)}
						/>
					</div>
					<Button variant="destructive" onClick={turnOff} loading={busy} disabled={code.trim().length < 6}>
						Turn off
					</Button>
					<Button variant="ghost" onClick={() => setDisabling(false)}>
						Cancel
					</Button>
				</div>
			)}
		</div>
	);
}
