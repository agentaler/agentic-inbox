import { useQuery } from "@tanstack/react-query";
import api, { type SessionInfo } from "~/services/api";
import { queryKeys } from "./keys";

/** The signed-in user (admin, or a single mailbox). */
export function useSession() {
	return useQuery<SessionInfo>({
		queryKey: queryKeys.session,
		queryFn: () => api.me(),
		staleTime: 5 * 60_000,
		retry: false,
	});
}

/** Sign out, then go to the sign-in page (or end the Cloudflare Access session). */
export async function signOut() {
	try {
		const res = await api.logout();
		if (res?.accessLogout) {
			window.location.assign("/cdn-cgi/access/logout");
			return;
		}
	} catch {
		/* ignore: we're leaving anyway */
	}
	window.location.assign("/login");
}
