// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

export interface Env extends Cloudflare.Env {
	/** Cloudflare Access (optional): a valid Access JWT for this audience signs the request in as admin. */
	POLICY_AUD?: string;
	TEAM_DOMAIN?: string;
	/** Secret. Password for the "admin" login on the sign-in page. Admin login is disabled when unset. */
	ADMIN_PASSWORD?: string;
	/** Secret (optional, 32+ chars). Session signing key; a random key is generated and kept in R2 when unset. */
	SESSION_SECRET?: string;
	/** Secret (optional). Bearer token that lets external MCP clients use /mcp. MCP is admin-only when unset. */
	MCP_TOKEN?: string;
}
