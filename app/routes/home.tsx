// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import {
	Button,
	Dialog,
	Empty,
	Input,
	Loader,
	Select,
	Text,
	useKumoToastManager,
} from "@cloudflare/kumo";
import { EnvelopeIcon, KeyIcon, PlusIcon, SignOutIcon, TrashIcon } from "@phosphor-icons/react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { Link as RouterLink, Navigate } from "react-router";
import api from "~/services/api";
import {
	useCreateMailbox,
	useDeleteMailbox,
	useMailboxes,
} from "~/queries/mailboxes";
import { queryKeys } from "~/queries/keys";
import { signOut, useSession } from "~/queries/session";
import TwoFactorCard from "~/components/TwoFactorCard";

export function meta() {
	return [{ title: "Agentic Inbox" }];
}

export default function HomeRoute() {
	const { data: session, isLoading: sessionLoading } = useSession();
	if (sessionLoading || !session) {
		return (
			<div className="flex justify-center items-center min-h-screen">
				<Loader size="lg" />
			</div>
		);
	}
	if (session.role === "mailbox") {
		return <Navigate to={`/mailbox/${session.mailbox}/emails/inbox`} replace />;
	}
	return (
		<AdminHome
			showAdminTip={session.via === "access" && !session.adminLogin}
			adminTwoFactor={session.via === "password" ? session.twoFactor : null}
		/>
	);
}

function AdminHome({ showAdminTip, adminTwoFactor }: { showAdminTip: boolean; adminTwoFactor: boolean | null }) {
	const toastManager = useKumoToastManager();
	const queryClient = useQueryClient();
	const { data: mailboxes = [], refetch: refetchMailboxes, isFetched: mailboxesFetched } = useMailboxes();
	const createMailbox = useCreateMailbox();
	const deleteMailbox = useDeleteMailbox();

	const { data: configData } = useQuery({
		queryKey: queryKeys.config,
		queryFn: () => api.getConfig(),
		staleTime: Infinity, // config rarely changes
	});

	const domains = configData?.domains ?? [];
	const emailAddresses = configData?.emailAddresses ?? [];

	const [isCreateOpen, setIsCreateOpen] = useState(false);
	const [newPrefix, setNewPrefix] = useState("");
	const [selectedDomain, setSelectedDomain] = useState("");
	const [newName, setNewName] = useState("");
	const [isCreating, setIsCreating] = useState(false);
	const [createError, setCreateError] = useState<string | null>(null);
	const [isDeleteOpen, setIsDeleteOpen] = useState(false);
	const [mailboxToDelete, setMailboxToDelete] = useState<{
		id: string;
		email: string;
	} | null>(null);
	const [isDeleting, setIsDeleting] = useState(false);
	const [newPassword, setNewPassword] = useState("");
	const [passwordTarget, setPasswordTarget] = useState<string | null>(null);
	const [passwordValue, setPasswordValue] = useState("");
	const [passwordConfirm, setPasswordConfirm] = useState("");
	const [passwordError, setPasswordError] = useState<string | null>(null);
	const [isSavingPassword, setIsSavingPassword] = useState(false);
	const [resetTwoFactor, setResetTwoFactor] = useState(false);

	// Set default domain when config loads
	useEffect(() => {
		if (domains.length > 0 && !selectedDomain) {
			setSelectedDomain(domains[0]);
		}
	}, [domains, selectedDomain]);

	// Auto-create mailboxes from config (run once when both data sources are ready)
	const autoCreateDone = useRef(false);
	useEffect(() => {
		if (autoCreateDone.current) return;
		if (emailAddresses.length === 0 || !mailboxesFetched) return;
		const existingEmails = new Set(
			mailboxes.map((m) => m.email.toLowerCase()),
		);
		const toCreate = emailAddresses.filter(
			(addr) => !existingEmails.has(addr.toLowerCase()),
		);
		if (toCreate.length === 0) {
			autoCreateDone.current = true;
			return;
		}
		autoCreateDone.current = true;
		let cancelled = false;
		Promise.all(
			toCreate.map((addr) => {
				const localPart = addr.split("@")[0] || addr;
				return api.createMailbox(addr, localPart).catch(() => {});
			}),
		).then(() => { if (!cancelled) refetchMailboxes(); });
		return () => { cancelled = true; };
	}, [emailAddresses, mailboxes, refetchMailboxes]);

	const handleCreate = async (e: FormEvent) => {
		e.preventDefault();
		setCreateError(null);
		if (!newPrefix || !selectedDomain) {
			setCreateError("Please fill in all fields");
			return;
		}
		if (newPassword && newPassword.length < 10) {
			setCreateError("Password must be at least 10 characters.");
			return;
		}
		const email = `${newPrefix}@${selectedDomain}`;
		const name = newName || newPrefix;
		setIsCreating(true);
		try {
			await createMailbox.mutateAsync({ email, name, password: newPassword || undefined });
			toastManager.add({ title: "Mailbox created successfully!" });
			setIsCreateOpen(false);
			setNewPrefix("");
			setNewName("");
			setNewPassword("");
		} catch (err: unknown) {
			const message = (err instanceof Error ? err.message : null) || "Failed to create mailbox";
			setCreateError(message);
		} finally {
			setIsCreating(false);
		}
	};

	const handleDelete = async () => {
		if (!mailboxToDelete) return;
		setIsDeleting(true);
		try {
			await deleteMailbox.mutateAsync(mailboxToDelete.id);
			toastManager.add({ title: "Mailbox deleted" });
			setIsDeleteOpen(false);
			setMailboxToDelete(null);
		} catch {
			toastManager.add({ title: "Failed to delete mailbox", variant: "error" });
		} finally {
			setIsDeleting(false);
		}
	};


	const openPasswordDialog = (mailboxId: string) => {
		setPasswordTarget(mailboxId);
		setPasswordValue("");
		setPasswordConfirm("");
		setPasswordError(null);
		setResetTwoFactor(false);
	};

	const handleSetPassword = async (e: FormEvent) => {
		e.preventDefault();
		if (!passwordTarget) return;
		setPasswordError(null);
		if (passwordValue.length < 10) {
			setPasswordError("Password must be at least 10 characters.");
			return;
		}
		if (passwordValue !== passwordConfirm) {
			setPasswordError("The two passwords don't match.");
			return;
		}
		setIsSavingPassword(true);
		try {
			await api.setMailboxPassword(passwordTarget, passwordValue, resetTwoFactor);
			toastManager.add({ title: `Password set for ${passwordTarget}` });
			setPasswordTarget(null);
			queryClient.invalidateQueries({ queryKey: queryKeys.mailboxes.all });
		} catch (err: unknown) {
			setPasswordError((err instanceof Error ? err.message : null) || "Failed to set password");
		} finally {
			setIsSavingPassword(false);
		}
	};

	const isConfigured = emailAddresses.length > 0;
	const accounts = isConfigured
		? emailAddresses.map((addr) => ({
				id: addr,
				email: addr,
				name: addr.split("@")[0] || addr,
				hasPassword: mailboxes.find((m) => m.email.toLowerCase() === addr.toLowerCase())?.hasPassword,
				hasTwoFactor: mailboxes.find((m) => m.email.toLowerCase() === addr.toLowerCase())?.hasTwoFactor,
			}))
		: mailboxes;

	const isLoading = !configData;

	return (
		<div className="min-h-screen bg-kumo-recessed">
			<div className="mx-auto max-w-2xl px-4 py-8 md:px-6 md:py-16">
				<div className="mb-8">
					<div className="flex items-center justify-between gap-2">
						<h1 className="text-2xl font-bold text-kumo-default">Mailboxes</h1>
						<div className="flex items-center gap-2">
							{!isConfigured && (
								<Button
									variant="primary"
									icon={<PlusIcon size={16} />}
									onClick={() => setIsCreateOpen(true)}
								>
									New Mailbox
								</Button>
							)}
							<Button variant="ghost" icon={<SignOutIcon size={16} />} onClick={() => signOut()}>
								Sign out
							</Button>
						</div>
					</div>
					{domains.length > 0 && (
						<p className="text-sm text-kumo-subtle mt-1">
							{domains.join(", ")}
						</p>
					)}
					<p className="text-sm text-kumo-subtle mt-3">
						Give each colleague their mailbox address and a password (key icon). They sign in at{" "}
						<span className="font-medium text-kumo-default">/login</span> and only see their own mailbox.
					</p>
					{showAdminTip && (
						<p className="text-xs text-kumo-subtle mt-2">
							Tip: add an ADMIN_PASSWORD secret to this Worker so you can also sign in as{" "}
							<span className="font-medium">admin</span> without Cloudflare.
						</p>
					)}
				</div>

				{adminTwoFactor !== null && (
					<div className="mb-6">
						<TwoFactorCard enabled={adminTwoFactor} />
					</div>
				)}

				{isLoading ? (
					<div className="flex justify-center py-20">
						<Loader size="lg" />
					</div>
				) : accounts.length > 0 ? (
					<div className="rounded-xl border border-kumo-line bg-kumo-base overflow-hidden">
						{accounts.map((account, idx) => (
							<RouterLink
								key={account.id}
								to={`/mailbox/${account.id}`}
								className={`group flex items-center gap-4 px-5 py-4 no-underline transition-colors hover:bg-kumo-tint ${
									idx > 0 ? "border-t border-kumo-line" : ""
								}`}
							>
								<div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-kumo-fill text-sm font-bold text-kumo-default">
									{account.name.charAt(0).toUpperCase()}
								</div>
								<div className="min-w-0 flex-1">
									<div className="text-sm font-medium text-kumo-default truncate">
										{account.name}
									</div>
									<div className="text-sm text-kumo-subtle truncate">
										{account.email}
									</div>
								</div>
								{account.hasTwoFactor && (
									<span className="shrink-0 rounded-full bg-kumo-fill px-2 py-0.5 text-xs text-kumo-subtle">
										2-step on
									</span>
								)}
								{account.hasPassword === false && (
									<span className="shrink-0 rounded-full bg-kumo-fill px-2 py-0.5 text-xs text-kumo-subtle">
										No password
									</span>
								)}
								<Button
									variant="ghost"
									size="sm"
									shape="square"
									icon={<KeyIcon size={16} />}
									aria-label={`Set password for ${account.email}`}
									onClick={(e) => {
										e.preventDefault();
										e.stopPropagation();
										openPasswordDialog(account.id);
									}}
								/>
								{!isConfigured && (
									<Button
										variant="ghost"
										size="sm"
										shape="square"
										icon={<TrashIcon size={16} />}
										aria-label={`Delete mailbox ${account.email}`}
										onClick={(e) => {
											e.preventDefault();
											e.stopPropagation();
											setMailboxToDelete({
												id: account.id,
												email: account.email,
											});
											setIsDeleteOpen(true);
										}}
									/>
								)}
							</RouterLink>
						))}
					</div>
				) : (
					<div className="rounded-xl border border-kumo-line bg-kumo-base py-16 px-6">
						<div className="flex flex-col items-center text-center">
							<div className="mb-4">
								<EnvelopeIcon
									size={48}
									weight="thin"
									className="text-kumo-subtle"
								/>
							</div>
							<h3 className="text-base font-semibold text-kumo-default mb-1.5">
								No mailboxes yet
							</h3>
							<p className="text-sm text-kumo-subtle max-w-sm mb-5">
								{isConfigured
									? "Your email routing is configured but no mailboxes have been created yet. They will appear here automatically."
									: "Create a mailbox to start sending and receiving emails with your domain."}
							</p>
							{!isConfigured && (
								<Button
									variant="primary"
									icon={<PlusIcon size={16} />}
									onClick={() => setIsCreateOpen(true)}
								>
									Create Mailbox
								</Button>
							)}
						</div>
					</div>
				)}
			</div>

			{/* Create Dialog */}
			<Dialog.Root open={isCreateOpen} onOpenChange={setIsCreateOpen}>
				<Dialog size="sm" className="p-6">
					<Dialog.Title className="text-base font-semibold mb-5">
						Create New Mailbox
					</Dialog.Title>
					<form onSubmit={handleCreate} className="space-y-4">
						{createError && (
							<Text variant="error" size="sm">
								{createError}
							</Text>
						)}
						<div>
							<span className="text-sm font-medium text-kumo-default mb-1.5 block">
								Email Address
							</span>
							<div className="flex items-center gap-2">
								<div className="flex-1">
									<Input
										aria-label="Address prefix"
										placeholder="info"
										size="sm"
										value={newPrefix}
										onChange={(e) => setNewPrefix(e.target.value)}
										required
									/>
								</div>
								<span className="text-sm text-kumo-subtle">@</span>
								{domains.length > 1 ? (
									<div className="flex-1">
										<Select
											aria-label="Domain"
											value={selectedDomain}
											onValueChange={(value) => {
												if (value) setSelectedDomain(value);
											}}
										>
											{domains.map((d) => (
												<Select.Option key={d} value={d}>
													{d}
												</Select.Option>
											))}
										</Select>
									</div>
								) : (
									<span className="text-sm text-kumo-subtle">
										{selectedDomain || "no domain"}
									</span>
								)}
							</div>
						</div>
						<Input
							label="Display Name (optional)"
							placeholder="Info"
							size="sm"
							value={newName}
							onChange={(e) => setNewName(e.target.value)}
						/>
						<Input
							label="Sign-in password (optional, 10+ characters)"
							type="password"
							autoComplete="new-password"
							size="sm"
							value={newPassword}
							onChange={(e) => setNewPassword(e.target.value)}
						/>
						<div className="flex justify-end gap-2 pt-2">
							<Dialog.Close
								render={(props) => (
									<Button {...props} variant="secondary" size="sm">
										Cancel
									</Button>
								)}
							/>
							<Button
								type="submit"
								variant="primary"
								size="sm"
								loading={isCreating}
								disabled={!selectedDomain}
							>
								Create
							</Button>
						</div>
					</form>
				</Dialog>
			</Dialog.Root>

			{/* Set Password Dialog */}
			<Dialog.Root
				open={passwordTarget !== null}
				onOpenChange={(open) => {
					if (!open) setPasswordTarget(null);
				}}
			>
				<Dialog size="sm" className="p-6">
					<Dialog.Title className="text-base font-semibold mb-1">
						Set sign-in password
					</Dialog.Title>
					<Dialog.Description className="text-kumo-subtle text-sm mb-5">
						For <strong className="text-kumo-default">{passwordTarget}</strong>. This replaces any old
						password and signs the mailbox out everywhere.
					</Dialog.Description>
					<form onSubmit={handleSetPassword} className="space-y-4">
						{passwordError && (
							<Text variant="error" size="sm">
								{passwordError}
							</Text>
						)}
						<Input
							label="New password"
							type="password"
							autoComplete="new-password"
							size="sm"
							value={passwordValue}
							onChange={(e) => setPasswordValue(e.target.value)}
							required
						/>
						<Input
							label="Repeat password"
							type="password"
							autoComplete="new-password"
							size="sm"
							value={passwordConfirm}
							onChange={(e) => setPasswordConfirm(e.target.value)}
							required
						/>
						{accounts.find((a) => a.id === passwordTarget)?.hasTwoFactor && (
							<label className="flex items-center gap-2 text-sm text-kumo-default cursor-pointer">
								<input
									type="checkbox"
									checked={resetTwoFactor}
									onChange={(e) => setResetTwoFactor(e.target.checked)}
									className="h-4 w-4"
								/>
								Also turn off two-step verification (lost phone)
							</label>
						)}
						<div className="flex justify-end gap-2 pt-2">
							<Dialog.Close
								render={(props) => (
									<Button {...props} variant="secondary" size="sm">
										Cancel
									</Button>
								)}
							/>
							<Button type="submit" variant="primary" size="sm" loading={isSavingPassword}>
								Save password
							</Button>
						</div>
					</form>
				</Dialog>
			</Dialog.Root>

			{/* Delete Dialog */}
			<Dialog.Root
				open={isDeleteOpen}
				onOpenChange={(open) => {
					setIsDeleteOpen(open);
					if (!open) setMailboxToDelete(null);
				}}
			>
				<Dialog size="sm" className="p-6">
					<Dialog.Title className="text-base font-semibold mb-2">
						Delete Mailbox
					</Dialog.Title>
					<Dialog.Description className="text-kumo-subtle text-sm mb-5">
						Are you sure you want to delete{" "}
						<strong className="text-kumo-default">
							{mailboxToDelete?.email}
						</strong>
						? This action cannot be undone.
					</Dialog.Description>
					<div className="flex justify-end gap-2">
						<Dialog.Close
							render={(props) => (
								<Button {...props} variant="secondary" size="sm">
									Cancel
								</Button>
							)}
						/>
						<Button
							variant="destructive"
							size="sm"
							loading={isDeleting}
							onClick={handleDelete}
						>
							Delete
						</Button>
					</div>
				</Dialog>
			</Dialog.Root>
		</div>
	);
}
