/**
 * @description
 * Cloudflare Worker entry point for the MCP Resource Server.
 * Provides protected API endpoints that require valid OAuth access tokens.
 * Uses Hono for routing and jose for JWT validation via middleware.
 *
 * Responsibilities:
 * - Define API routes (e.g., /api/data).
 * - Implement middleware for validating access tokens using JWKS from the Auth Server.
 * - Handle API requests after successful token validation.
 *
 * @dependencies
 * - hono: Web framework for Cloudflare Workers.
 * - jose: For JWT validation.
 * - ./env: Type definition for environment bindings.
 * - ./auth-middleware: JWT validation middleware.
 *
 * @notes
 * - Requires AUTH_SERVER_URL binding/secret in wrangler.toml.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors'; // Import CORS middleware
import type { Env } from './env';
import type { ExecutionContext } from '@cloudflare/workers-types';
import { jwtAuthMiddleware } from './auth-middleware'; // Import the middleware
import type { JWTPayload } from 'jose'; // Import JWTPayload type
import { html, raw } from 'hono/html'; // Import html AND raw helpers
import type { Next, Context } from 'hono'; // Or your framework's equivalent

// --- Inlined Script Content ---
// Follows Hanko Vanilla JS Guide pattern
const hankoScriptContent = `
console.log('[Hanko Iframe] Script start');
// Import register directly from the esm.run CDN
import { register } from 'https://esm.run/@teamhanko/hanko-elements';

document.addEventListener('DOMContentLoaded', async () => { // Make callback async
    console.log('[Hanko Iframe] DOMContentLoaded event fired.');

    const hankoAuthEl = document.getElementById('hankoAuthEl');
    const statusEl = document.getElementById('status');
    console.log('[Hanko Iframe] Found elements:', { hankoAuthEl, statusEl });

    if (!hankoAuthEl || !statusEl) {
        console.error('[Hanko Iframe] Could not find Hanko DOM elements!');
        return;
    }

    console.log('[Hanko Iframe] Reading attributes...');
    const authWorkerTargetOrigin = hankoAuthEl.dataset.authOrigin;
    const hankoApi = hankoAuthEl.dataset.hankoApi; // Read API URL from data attribute
    console.log('[Hanko Iframe] Config:', { hankoApi, authWorkerTargetOrigin });

    if (!hankoApi) {
        console.error('[Hanko Iframe] Hanko API URL is missing from data-hanko-api attribute.');
        if(statusEl) statusEl.textContent = 'Error: Hanko API URL not configured.';
        return;
    }
    if (!authWorkerTargetOrigin) {
         console.error('[Hanko Iframe] Auth Worker Origin is missing from data attribute.');
         if(statusEl) statusEl.textContent = 'Error: Auth Worker Origin not configured.';
         return;
    }

    try {
        console.log('[Hanko Iframe] Calling register from esm.run...');
        // Register returns the hanko instance
        const { hanko } = await register(hankoApi);
        console.log('[Hanko Iframe] register() successful, Hanko instance obtained.');
        if(statusEl) statusEl.textContent = 'Authenticator loading...';

        // --- Event Handling using Hanko instance --- 

        console.log('[Hanko Iframe] Adding onSessionCreated listener...');
        hanko.onSessionCreated(async () => { // Make the callback async
            console.log('[Hanko Iframe] onSessionCreated event fired. Attempting to get current user...');
            try {
                 const currentUser = await hanko.user.getCurrent();
                 const userID = currentUser?.id;
                 console.log('[Hanko Iframe] getCurrent() result:', currentUser);

                 if (userID) {
                     if(statusEl) statusEl.textContent = 'Authentication successful! Processing...';
                     console.log('[Hanko Iframe] Sending HANKO_AUTH_SUCCESS to parent with targetOrigin *');
                     window.parent.postMessage({ type: 'HANKO_AUTH_SUCCESS', payload: { hankoUserId: userID } }, '*');
                 } else {
                     console.error('[Hanko Iframe] Got user from getCurrent(), but ID was missing.', currentUser);
                     if(statusEl) statusEl.textContent = 'Error: Missing user ID after login.';
                     console.log('[Hanko Iframe] Sending HANKO_AUTH_ERROR (missing ID) to parent with targetOrigin *');
                     window.parent.postMessage({ type: 'HANKO_AUTH_ERROR', payload: { message: 'Session created but user ID missing.' } }, '*');
                 }
            } catch (error) {
                 console.error('[Hanko Iframe] Error calling hanko.user.getCurrent() after session creation:', error);
                 if(statusEl) statusEl.textContent = 'Error retrieving user details after login.';
                 console.log('[Hanko Iframe] Sending HANKO_AUTH_ERROR (getCurrent failed) to parent with targetOrigin *');
                 window.parent.postMessage({ type: 'HANKO_AUTH_ERROR', payload: { message: 'Failed to retrieve user details after login.' } }, '*');
            }
        });

        // Completion/Error: Use onAuthFlowCompleted (covers success/fail/abort)
        // console.log('[Hanko Iframe] Adding onAuthFlowCompleted listener...');
        // hanko.onAuthFlowCompleted(({ detail }) => { ... }); // REMOVED - This method doesn't seem to exist on the instance from register()

        console.log('[Hanko Iframe] Instance listeners added. Waiting for UI interaction...');
        if(statusEl) statusEl.textContent = 'Please authenticate using the passkey.';

    } catch (error) {
         console.error('[Hanko Iframe] Error during Hanko register/listener setup:', error);
         if(statusEl) statusEl.textContent = 'Error initializing authenticator.';
    }
});
`;

// Define context including validated JWT payload added by middleware
// Removed ApiContext type alias, defining structure directly in Hono generic
// type ApiContext = Hono<{ Bindings: Env, Variables: { jwtPayload?: JWTPayload } }>;

const app = new Hono<{
  Bindings: Env;
  Variables: {
    // jwtPayload?: JWTPayload; // We might remove this later if jwtAuthMiddleware is fully gone
    tokenProps?: IntrospectionSuccessResponse; // Added by introspection middleware
    userId?: string; // Added by introspection middleware
    clientId?: string; // Added by introspection middleware
    tokenScopes?: string[]; // Added by introspection middleware
  };
}>(); // Correctly define generic

// --- CORS Middleware ---
// Apply CORS globally BEFORE other middleware/routes
app.use('*', cors({
    origin: ['http://localhost:3000'], // Allow your frontend origin
    allowHeaders: ['Authorization', 'Content-Type'], // Allow necessary headers
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Allow common methods + OPTIONS for preflight
    credentials: true, // Allow credentials (cookies, authorization headers)
}));
console.log("CORS Middleware registered for origin http://localhost:3000");

// --- JWT Middleware ---
// Apply JWT validation middleware to all API routes
app.use('/api/*', tokenIntrospectionMiddleware);
console.log("Token Introspection Middleware registered for /api/* routes.");

// --- HTML Template for Hanko UI (used in iframe) ---
const hankoUiHtml = (hankoApiUrl: string, authWorkerOrigin: string) => html`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hanko Authentication</title>
    <!-- REMOVED script tags from here - handled by import in inline script -->
    <style>
        body { margin: 0; padding: 20px; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 90vh; font-family: sans-serif; background-color: #f7f7f7; }
        hanko-auth { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 400px; /* Example width */ }
        hanko-auth::part(container) { border: none; box-shadow: none; padding: 0; }
        #status { margin-top: 15px; font-size: 0.9em; color: #666; text-align: center; min-height: 1.2em; }
    </style>
</head>
<body>
    <hanko-auth
        id="hankoAuthEl"
        lang="en"
        data-hanko-api="${hankoApiUrl}" 
        data-auth-origin="${authWorkerOrigin}"
        <!-- REMOVED api attribute - register() handles config -->
    ></hanko-auth>
    <div id="status">Initializing authenticator...</div>

    <!-- Inject script content using raw helper -->
    <script type="module">${raw(hankoScriptContent)}</script> 
</body>
</html>`;

// --- API Routes ---

// Example protected API route
app.get('/api/data', async (c) => { // Make handler async
	console.log("MCP Worker: /api/data accessed.");

	// Access validated introspection data from context set by middleware
	const tokenProps = c.get('tokenProps') as IntrospectionSuccessResponse | undefined; // Get the whole props object
	
	if (!tokenProps || !tokenProps.active) { // Check if props exist and token is active
		console.error("MCP Worker: Reached /api/data but tokenProps are missing or inactive!");
		return c.json({ error: 'internal_server_error', message: 'Authentication context missing or token inactive.' }, 500);
	}

    const userId = tokenProps.sub; // Use 'sub' from introspection response
    const scope = tokenProps.scope; // Use 'scope' from introspection response
    const issuedAt = tokenProps.iat;
    const expiresAt = tokenProps.exp;

    // --- Fetch User Metadata from Vault KV ---
    let userVaultData = {}; // Default to empty object
    if (userId && c.env.MCP_VAULT_KV) { // Check if userId exists and MCP_VAULT_KV is bound
        try {
            const vaultKey = `user_profile:${userId}`; // Example key structure
            console.log(`[MCP Worker /api/data] Attempting to fetch vault data for key: ${vaultKey}`);
            const data = await c.env.MCP_VAULT_KV.get(vaultKey, { type: 'json' });
            if (data) {
                userVaultData = data;
                console.log(`[MCP Worker /api/data] Found vault data for user ${userId}.`);
            } else {
                console.log(`[MCP Worker /api/data] No vault data found for user ${userId} at key ${vaultKey}.`);
                // Decide if missing vault data is an error or acceptable
            }
        } catch (kvError: any) {
            console.error(`[MCP Worker /api/data] Error fetching vault data for user ${userId}:`, kvError);
            // Decide how to handle KV errors (e.g., return 500 or continue without vault data)
            // Returning 500 for now, adjust as needed
            return c.json({ error: 'server_error', message: 'Failed to retrieve user metadata.' }, 500);
        }
    } else {
        if (!userId) console.warn("[MCP Worker /api/data] No userId in tokenProps, cannot fetch vault data.");
        if (!c.env.MCP_VAULT_KV) console.warn("[MCP Worker /api/data] MCP_VAULT_KV binding not configured, cannot fetch vault data.");
        // Continue without vault data if userId or binding is missing
    }
    // --- End Fetch User Metadata ---

	return c.json({
		message: "Success! You have accessed protected data via Token Introspection.", 
        userId: userId || 'Unknown',
        issuedAt: issuedAt ? new Date(issuedAt * 1000).toISOString() : 'N/A',
        expiresAt: expiresAt ? new Date(expiresAt * 1000).toISOString() : 'N/A',
        scope: scope || 'N/A', 
        vaultData: userVaultData, // Include fetched vault data
		timestamp: new Date().toISOString(),
	});
});

// Root route (unprotected) - Serves the Hanko UI HTML
app.get('/', (c) => {
    console.log("MCP Worker: Root route '/' accessed, serving Hanko UI HTML.");
    const hankoApiUrl = c.env.HANKO_API_URL;
    const authWorkerOrigin = c.env.AUTH_WORKER_ORIGIN;

    if (!hankoApiUrl || !authWorkerOrigin) {
        console.error("MCP Worker: Missing HANKO_API_URL or AUTH_WORKER_ORIGIN in environment.");
        return c.text('Internal Server Error: Worker configuration missing.', 500);
    }

    return c.html(hankoUiHtml(hankoApiUrl, authWorkerOrigin));
});

// Default 404 (unprotected)
app.notFound((c) => {
	return c.json({ error: 'not_found', message: 'Endpoint not found.' }, 404);
});

// Error handler (unprotected)
app.onError((err, c) => {
	console.error(`MCP Worker Error: ${err.message}`, err.stack);
	return c.json({ error: 'server_error', message: 'An internal error occurred.' }, 500);
});

// --- Add POST /api/vault Endpoint ---
app.post('/api/vault', async (c) => {
    console.log("[MCP Worker /api/vault] POST request received.");

    // UserID should be available from tokenIntrospectionMiddleware applied via app.use('/api/*', ...)
    const userId = c.get('userId');
    if (!userId) {
        console.error("[MCP Worker /api/vault] No userId found in context. Middleware issue?");
        return c.json({ error: 'unauthorized', message: 'Authentication context missing.' }, 401);
    }

    // Ensure MCP_VAULT_KV is configured
    if (!c.env.MCP_VAULT_KV) {
        console.error("[MCP Worker /api/vault] MCP_VAULT_KV binding not configured.");
        return c.json({ error: 'server_error', message: 'Vault storage is not configured.' }, 500);
    }

    // Parse the request body as JSON
    let vaultDataToSave;
    try {
        vaultDataToSave = await c.req.json();
        // Basic validation: Ensure it's an object (or handle specific expected structures)
        if (typeof vaultDataToSave !== 'object' || vaultDataToSave === null) {
            throw new Error("Invalid data format: Expected a JSON object.");
        }
        console.log(`[MCP Worker /api/vault] Parsed request body for user ${userId}:`, vaultDataToSave);
    } catch (error: any) {
        console.error(`[MCP Worker /api/vault] Error parsing JSON body for user ${userId}:`, error);
        return c.json({ error: 'invalid_request', message: `Invalid JSON data: ${error.message}` }, 400);
    }

    // Save data to KV
    try {
        const vaultKey = `user_profile:${userId}`; // Consistent key structure
        await c.env.MCP_VAULT_KV.put(vaultKey, JSON.stringify(vaultDataToSave));
        console.log(`[MCP Worker /api/vault] Successfully saved vault data for user ${userId} at key ${vaultKey}.`);
        return c.json({ success: true, message: "Vault data saved successfully." }, 200);
    } catch (kvError: any) {
        console.error(`[MCP Worker /api/vault] Error saving vault data for user ${userId}:`, kvError);
        return c.json({ error: 'server_error', message: 'Failed to save vault data.' }, 500);
    }
});
// --- End POST /api/vault Endpoint ---

// Define the expected structure of the successful introspection response
interface IntrospectionSuccessResponse {
  active: true;
  scope: string;
  client_id: string;
  sub: string; // User ID
  exp: number;
  iat: number;
  token_type: 'bearer';
  [key: string]: any; // Include any decrypted props
}

interface IntrospectionFailureResponse {
  active: false;
  [key: string]: any; // May include reason, error, etc.
}

type IntrospectionResponse = IntrospectionSuccessResponse | IntrospectionFailureResponse;

// --- Middleware Function ---
export async function tokenIntrospectionMiddleware(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'invalid_token', error_description: 'Missing or invalid Authorization header.' }, 401);
  }

  const token = authHeader.substring(7);

  // URL of your auth-worker's introspection endpoint
  const introspectionUrl = 'http://localhost:8788/introspect'; // Adjust port/host as needed

  try {
    const formData = new FormData();
    formData.append('token', token);
    // Optional: formData.append('token_type_hint', 'access_token');

    console.log(`[mcp-worker] Calling introspection endpoint: ${introspectionUrl} for token: ${token.substring(0,10)}...`); // Log partial token

    const response = await fetch(introspectionUrl, {
      method: 'POST',
      body: formData,
      // Consider adding headers like Accept: application/json if needed
    });

    if (!response.ok) {
       const errorBody = await response.text();
       console.error(`[mcp-worker] Introspection request failed with status ${response.status}: ${errorBody}`);
       return c.json({ error: 'introspection_failed', error_description: `Token introspection failed (${response.status}).` }, 401);
    }

    const introspectionResult: IntrospectionResponse = await response.json();

    console.log('[mcp-worker] Introspection response received:', introspectionResult);

    if (!introspectionResult.active) {
      console.log('[mcp-worker] Token introspection result: inactive.');
      return c.json({ error: 'invalid_token', error_description: 'Token is invalid, expired, or revoked.' }, 401);
    }

    // --- Token is Active ---
    console.log(`[mcp-worker] Token active for user: ${introspectionResult.sub}, client: ${introspectionResult.client_id}, scope: ${introspectionResult.scope}`);

    // Optional: Check token expiration just in case (though auth server should handle this)
    const now = Math.floor(Date.now() / 1000);
    if (introspectionResult.exp < now) {
       console.warn('[mcp-worker] Introspection returned active token, but exp is in the past.');
       return c.json({ error: 'invalid_token', error_description: 'Token is expired (client-side check).' }, 401);
    }

    // --- Attach relevant info to context for downstream handlers ---
    // Adjust context variable names as needed by your application
    c.set('userId', introspectionResult.sub);
    c.set('clientId', introspectionResult.client_id);
    c.set('tokenScopes', introspectionResult.scope.split(' '));
    // You can attach the whole introspection result or specific props
    c.set('tokenProps', introspectionResult); // Contains user info, etc. from decrypted props

    await next(); // Proceed to the actual API handler

  } catch (error: any) {
    console.error('[mcp-worker] Error in tokenIntrospectionMiddleware:', error);
    return c.json({ error: 'server_error', error_description: 'Internal server error during token validation.' }, 500);
  }
}

export default {
    // Hono requires the fetch signature to include ExecutionContext
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        console.log(`MCP Worker received request: ${request.method} ${request.url}`);
        return app.fetch(request, env, ctx);
    }
};
