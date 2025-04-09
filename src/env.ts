/**
 * @description
 * Defines the TypeScript interface for the Cloudflare Worker environment bindings and secrets
 * for the MCP Resource Server (`mcp-worker`).
 *
 * @dependencies
 * - None
 *
 * @notes
 * - This interface should mirror the bindings and secrets configured in `wrangler.toml`.
 * - AUTH_SERVER_URL is critical for fetching the JWKS from the auth-worker.
 */

import type { KVNamespace } from '@cloudflare/workers-types';

export interface Env {
	// --- Secrets (set via `wrangler secret put`) ---

	/**
	 * The base URL of the Authentication Server worker (`auth-worker`).
	 * Used to fetch the JWKS endpoint (/.well-known/jwks.json) for token validation.
	 */
	AUTH_SERVER_URL: string;

	/**
	 * KV Namespace for storing Vault-related data like secrets.
	 * Bound in `wrangler.toml`.
	 */
	MCP_VAULT_KV?: KVNamespace;

	/**
	 * The Hanko API URL for initializing the Hanko web component.
	 */
	HANKO_API_URL: string;

	// --- Variables (set via wrangler.toml [vars]) ---

	/**
	 * The expected origin of the auth-worker iframe host page.
	 * Used as the targetOrigin for postMessage calls.
	 */
	AUTH_WORKER_ORIGIN: string;

	// Add any other secrets or KV/DO bindings needed by the resource server here.
	// EXAMPLE_KV: KVNamespace;
}
