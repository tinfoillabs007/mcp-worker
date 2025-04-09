/**
 * @description
 * Hono middleware for validating JWT access tokens issued by the auth-worker.
 * Fetches the JWKS from the auth-worker's /.well-known/jwks.json endpoint
 * to verify the token signature. Also checks issuer and potentially audience.
 *
 * @dependencies
 * - hono: Provides MiddlewareHandler type.
 * - jose: For JWT validation (jwtVerify) and JWKS fetching (createRemoteJWKSet).
 * - ./env: Type definition for environment bindings (AUTH_SERVER_URL).
 *
 * @notes
 * - Includes a simple in-memory cache for JWKS to reduce fetching.
 * - Issuer validation is crucial.
 * - Audience validation is commented out but highly recommended for production
 *   (requires the auth-worker to include an 'aud' claim in the token).
 * - Error handling returns appropriate 401 or 500 responses.
 */

import type { MiddlewareHandler } from 'hono';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import type { JWTPayload, KeyLike, JWSHeaderParameters } from 'jose';
import type { Env } from './env'; // Environment bindings for this worker

// --- Utility Function ---

/**
 * Escapes special HTML characters in a string to prevent XSS.
 * @param unsafe The potentially unsafe string.
 * @returns The escaped string, or an empty string if input is null/undefined.
 */
const escapeHtml = (unsafe: string | undefined | null): string => {
	if (!unsafe) return '';
	return unsafe
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#039;');
};


// --- Middleware Types ---

// Define the expected shape of the environment after middleware runs
type ApiContextEnv = {
    Bindings: Env,
    Variables: {
        jwtPayload?: JWTPayload; // To store the validated payload
    }
};

// --- JWKS Caching ---
let jwksCache: ReturnType<typeof createRemoteJWKSet> | null = null;
let jwksUrlCache: string | null = null;

/**
 * Hono middleware to authenticate requests using JWT Bearer tokens
 * and validate them against the JWKS endpoint of the Authorization Server.
 */
export const jwtAuthMiddleware: MiddlewareHandler<ApiContextEnv> = async (c, next) => {
	console.log('[jwtAuthMiddleware] Running...');

	// 1. Extract token from Authorization header
	const authHeader = c.req.header('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		console.log('[jwtAuthMiddleware] Error: Missing or malformed Authorization header.');
		return c.json({ error: 'invalid_token', error_description: 'Missing or invalid Authorization header.' }, 401, {
			'WWW-Authenticate': 'Bearer realm="mcp-api", error="invalid_request", error_description="Authorization header required"',
		});
	}
	const token = authHeader.substring(7); // Remove "Bearer " prefix

	// 2. Get Auth Server URL from environment
	const authServerUrl = c.env.AUTH_SERVER_URL;
	if (!authServerUrl) {
		console.error('[jwtAuthMiddleware] Error: AUTH_SERVER_URL is not configured in the environment.');
		return c.json({ error: 'server_error', error_description: 'Authentication server URL not configured.' }, 500);
	}

	try {
		// 3. Construct JWKS URL and get/cache JWKS set
		const jwksUrl = new URL('/.well-known/jwks.json', authServerUrl).toString();
        console.log(`[jwtAuthMiddleware] JWKS URL: ${jwksUrl}`);

        // Use cache if URL hasn't changed
        if (!jwksCache || jwksUrlCache !== jwksUrl) {
             console.log(`[jwtAuthMiddleware] Fetching or refetching JWKS from ${jwksUrl}`);
             // Consider adding options like cacheMaxAge if library supports it directly
             // or implement more robust caching using Workers Cache API.
             jwksCache = createRemoteJWKSet(new URL(jwksUrl));
             jwksUrlCache = jwksUrl;
        } else {
             console.log(`[jwtAuthMiddleware] Using cached JWKS for ${jwksUrl}`);
        }


		// 4. Verify the JWT
		console.log('[jwtAuthMiddleware] Verifying token...');
		const { payload /*, protectedHeader */ } = await jwtVerify(
			token,
			jwksCache,
			{
				issuer: authServerUrl, // Verify the issuer matches the auth server URL
                // audience: 'urn:mcp-resource-server', // IMPORTANT: Add audience validation in production!
                // algorithms: ['RS256'] // Optional: Specify expected algorithms if known
			}
		);
        console.log('[jwtAuthMiddleware] Token verified successfully. Payload:', payload);


		// 5. Attach payload to context and proceed
		c.set('jwtPayload', payload);
		await next();

	} catch (error: any) {
		console.error('[jwtAuthMiddleware] Token validation failed:', error.message);

        let errorType = 'invalid_token';
        let errorDescription = 'Access token is invalid or expired.';

        // Provide more specific feedback based on JOSE error codes if possible
        if (error.code === 'ERR_JWT_EXPIRED') {
            errorDescription = 'Access token has expired.';
        } else if (error.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
            errorDescription = 'Access token signature verification failed.';
        } else if (error.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
            errorDescription = `Access token claim validation failed (${error.message})`; // e.g., invalid issuer
        } else if (error.code === 'ERR_JWKS_NO_MATCHING_KEY') {
             errorDescription = 'No matching key found to verify token signature.';
             // Invalidate cache in case keys rotated
             jwksCache = null;
             jwksUrlCache = null;
        } else if (error.code === 'ERR_JWKS_TIMEOUT' || error.code === 'ERR_JWKS_FETCH_FAILED') {
            errorType = 'server_error';
            errorDescription = 'Failed to fetch validation keys from authentication server.';
        }

		return c.json({ error: errorType, error_description: errorDescription }, 401, {
			'WWW-Authenticate': `Bearer realm="mcp-api", error="${errorType}", error_description="${escapeHtml(errorDescription)}"`,
		});
	}
};
