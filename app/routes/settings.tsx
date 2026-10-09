// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Badge, Button, Input, Loader, useKumoToastManager } from "@cloudflare/kumo";
import { RobotIcon, ArrowCounterClockwiseIcon, ArrowBendUpRightIcon, KeyIcon } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { useParams } from "react-router";
import { useMailbox, useUpdateMailbox } from "~/queries/mailboxes";
import { useSession } from "~/queries/session";
import api from "~/services/api";

// Placeholder shown in the textarea when no custom prompt is set.
// The authoritative default prompt lives in workers/agent/index.ts (DEFAULT_SYSTEM_PROMPT).
const PROMPT_PLACEHOLDER = `You are an email assistant that helps manage this inbox. You read emails, draft replies, and help organize conversations.\n\nWrite like a real person. Short, direct, flowing prose. Plain text only.\n\n(Leave empty to use the full built-in default prompt)`;

export default function SettingsRoute() {
	const { mailboxId } = useParams<{ mailboxId: string }>();
	const toastManager = useKumoToastManager();
	const { data: mailbox } = useMailbox(mailboxId);
	const updateMailboxMutation = useUpdateMailbox();

	const [displayName, setDisplayName] = useState("");
	const [agentPrompt, setAgentPrompt] = useState("");
	const [isSaving, setIsSaving] = useState(false);
	const [forwardEnabled, setForwardEnabled] = useState(false);
	const [forwardEmail, setForwardEmail] = useState("");
	const { data: session } = useSession();
	const [currentPassword, setCurrentPassword] = useState("");
	const [newPassword, setNewPassword] = useState("");
	const [confirmPassword, setConfirmPassword] = useState("");
	const [isChangingPassword, setIsChangingPassword] = useState(false);

	useEffect(() => {
		if (mailbox) {
			setDisplayName(mailbox.settings?.fromName || mailbox.name || "");
			setAgentPrompt(mailbox.settings?.agentSystemPrompt || "");
			setForwardEnabled(!!mailbox.settings?.forwarding?.enabled);
			setForwardEmail(mailbox.settings?.forwarding?.email || "");
		}
	}, [mailbox]);

	const handleChangePassword = async () => {
		if (newPassword.length < 8) {
			toastManager.add({ title: "New password must be at least 8 characters", variant: "error" });
			return;
		}
		if (newPassword !== confirmPassword) {
			toastManager.add({ title: "The new passwords don't match", variant: "error" });
			return;
		}
		setIsChangingPassword(true);
		try {
			await api.changePassword(currentPassword, newPassword);
			toastManager.add({ title: "Password changed" });
			setCurrentPassword("");
			setNewPassword("");
			setConfirmPassword("");
		} catch (err) {
			toastManager.add({
				title: (err instanceof Error && err.message) || "Couldn't change the password",
				variant: "error",
			});
		} finally {
			setIsChangingPassword(false);
		}
	};

	const handleSave = async () => {
		if (!mailbox || !mailboxId) return;
		const target = forwardEmail.trim().toLowerCase();
		if (forwardEnabled && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target)) {
			toastManager.add({ title: "Enter a valid forwarding address", variant: "error" });
			return;
		}
		setIsSaving(true);
		const settings = {
			...mailbox.settings,
			fromName: displayName,
			agentSystemPrompt: agentPrompt.trim() || undefined,
			forwarding: { enabled: forwardEnabled && !!target, email: target },
		};
		try {
			await updateMailboxMutation.mutateAsync({ mailboxId, settings });
			toastManager.add({ title: "Settings saved!" });
		} catch {
			toastManager.add({
				title: "Failed to save settings",
				variant: "error",
			});
		} finally {
			setIsSaving(false);
		}
	};

	const handleResetPrompt = () => {
		setAgentPrompt("");
	};

	if (!mailbox) {
		return (
			<div className="flex justify-center py-20">
				<Loader size="lg" />
			</div>
		);
	}

	const isCustomPrompt = agentPrompt.trim().length > 0;

	return (
		<div className="max-w-2xl px-4 py-4 md:px-8 md:py-6 h-full overflow-y-auto">
			<h1 className="text-lg font-semibold text-kumo-default mb-6">Settings</h1>

			<div className="space-y-6">
				{/* Account */}
				<div className="rounded-lg border border-kumo-line bg-kumo-base p-5">
					<div className="text-sm font-medium text-kumo-default mb-4">
						Account
					</div>
					<div className="space-y-3">
						<Input
							label="Display Name"
							value={displayName}
							onChange={(e) => setDisplayName(e.target.value)}
						/>
						<Input label="Email" type="email" value={mailbox.email} disabled />
					</div>
				</div>

				{/* Forwarding */}
				<div className="rounded-lg border border-kumo-line bg-kumo-base p-5">
					<div className="flex items-center gap-2 mb-2">
						<ArrowBendUpRightIcon size={16} weight="duotone" className="text-kumo-subtle" />
						<span className="text-sm font-medium text-kumo-default">Forward a copy</span>
					</div>
					<p className="text-xs text-kumo-subtle mb-3">
						New mail still arrives here, and a copy is also sent to this address. The address must be
						verified under Cloudflare Email Routing &rarr; Destination addresses.
					</p>
					<label className="flex items-center gap-2 text-sm text-kumo-default mb-3 cursor-pointer">
						<input
							type="checkbox"
							checked={forwardEnabled}
							onChange={(e) => setForwardEnabled(e.target.checked)}
							className="h-4 w-4"
						/>
						Forward new mail
					</label>
					<Input
						label="Forward to"
						type="email"
						placeholder="name@gmail.com"
						value={forwardEmail}
						onChange={(e) => setForwardEmail(e.target.value)}
						disabled={!forwardEnabled}
					/>
				</div>

				{session?.role === "mailbox" && (
					<div className="rounded-lg border border-kumo-line bg-kumo-base p-5">
						<div className="flex items-center gap-2 mb-4">
							<KeyIcon size={16} weight="duotone" className="text-kumo-subtle" />
							<span className="text-sm font-medium text-kumo-default">Change password</span>
						</div>
						<div className="space-y-3">
							<Input
								label="Current password"
								type="password"
								autoComplete="current-password"
								value={currentPassword}
								onChange={(e) => setCurrentPassword(e.target.value)}
							/>
							<Input
								label="New password (8+ characters)"
								type="password"
								autoComplete="new-password"
								value={newPassword}
								onChange={(e) => setNewPassword(e.target.value)}
							/>
							<Input
								label="Repeat new password"
								type="password"
								autoComplete="new-password"
								value={confirmPassword}
								onChange={(e) => setConfirmPassword(e.target.value)}
							/>
							<div className="flex justify-end">
								<Button
									variant="secondary"
									onClick={handleChangePassword}
									loading={isChangingPassword}
									disabled={!currentPassword || !newPassword}
								>
									Change password
								</Button>
							</div>
						</div>
					</div>
				)}

				{/* Agent System Prompt */}
				<div className="rounded-lg border border-kumo-line bg-kumo-base p-5">
					<div className="flex items-center justify-between mb-4">
						<div className="flex items-center gap-2">
							<RobotIcon size={16} weight="duotone" className="text-kumo-subtle" />
							<span className="text-sm font-medium text-kumo-default">
								AI Agent Prompt
							</span>
							{isCustomPrompt ? (
								<Badge variant="primary">Custom</Badge>
							) : (
								<Badge variant="secondary">Default</Badge>
							)}
						</div>
						{isCustomPrompt && (
							<Button
								variant="ghost"
								size="xs"
								icon={<ArrowCounterClockwiseIcon size={14} />}
								onClick={handleResetPrompt}
							>
								Reset to default
							</Button>
						)}
					</div>
					<p className="text-xs text-kumo-subtle mb-3">
						Customize how the AI agent behaves for this mailbox.
						Leave empty to use the built-in default prompt.
					</p>
					<textarea
						value={agentPrompt}
						onChange={(e) => setAgentPrompt(e.target.value)}
						placeholder={PROMPT_PLACEHOLDER}
						rows={12}
						className="w-full resize-y rounded-lg border border-kumo-line bg-kumo-recessed px-3 py-2 text-xs text-kumo-default placeholder:text-kumo-subtle focus:outline-none focus:ring-1 focus:ring-kumo-ring font-mono leading-relaxed"
					/>
					<p className="text-xs text-kumo-subtle mt-2">
						The prompt is sent as the system message to the AI model.
						It controls the agent's personality, writing style, and behavior rules.
					</p>
				</div>

				{/* Save */}
				<div className="flex justify-end">
					<Button variant="primary" onClick={handleSave} loading={isSaving}>
						Save Changes
					</Button>
				</div>
			</div>
		</div>
	);
}
