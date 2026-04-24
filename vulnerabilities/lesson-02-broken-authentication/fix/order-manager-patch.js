/**
 * order-manager-patch.js
 * DVSA Lesson 02 — Broken Authentication Fix
 *
 * Change: Replaced unauthenticated JWT payload decoding with full Cognito JWT
 * signature verification using node-jose and the Cognito JWKS endpoint.
 *
 * Vulnerability: The original code decoded the JWT payload with
 * jose.util.base64url.decode() and trusted the claims directly, with no
 * signature verification. Any attacker could forge a token with any user's
 * UUID and gain access to that user's data.
 *
 * Fix: Added getCognitoKeystore() and verifyCognitoJwt() which:
 *   1. Fetch the Cognito User Pool public JWKS (cached 6 hours)
 *   2. Verify the JWT signature against those public keys
 *   3. Validate the issuer matches the expected Cognito pool URL
 *   4. Only then extract username/sub claims from the verified payload
 */

'use strict';

const jose = require('node-jose');
const https = require('https');

// JWKS cache: avoids re-fetching public keys on every Lambda invocation
let _jwksCache = { keystore: null, fetchedAt: 0 };

/**
 * Simple HTTPS JSON fetch helper.
 */
function fetchJson(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            let data = '';
            res.on('data', (c) => data += c);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
                } else {
                    reject(new Error('HTTP ' + res.statusCode));
                }
            });
        }).on('error', reject);
    });
}

/**
 * Fetches and caches the Cognito User Pool JWKS keystore.
 * Cache TTL: 6 hours. Subsequent calls within TTL return the cached keystore.
 */
async function getCognitoKeystore() {
    const now = Date.now();
    if (_jwksCache.keystore && (now - _jwksCache.fetchedAt) < 6 * 60 * 60 * 1000) {
        return _jwksCache.keystore;
    }
    const region = process.env.AWS_REGION;
    const userPoolId = process.env.userpoolid;
    const jwks = await fetchJson(
        `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`
    );
    const keystore = await jose.JWK.asKeyStore(jwks);
    _jwksCache = { keystore, fetchedAt: now };
    return keystore;
}

/**
 * Verifies a Cognito-issued JWT.
 * Checks: signature (via JWKS), issuer, expiry.
 * Returns the verified payload object on success, throws on failure.
 *
 * @param {string} jwt - Raw JWT string from Authorization header
 * @returns {object} Verified token payload
 */
async function verifyCognitoJwt(jwt) {
    const region = process.env.AWS_REGION;
    const userPoolId = process.env.userpoolid;
    const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
    const keystore = await getCognitoKeystore();

    // node-jose verifies signature and returns the payload
    const result = await jose.JWS.createVerify(keystore).verify(jwt);
    const payload = JSON.parse(result.payload.toString());

    // Validate issuer claim
    if (payload.iss !== issuer) {
        throw new Error(`Invalid issuer: expected ${issuer}, got ${payload.iss}`);
    }

    // Validate expiry
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
        throw new Error('Token has expired');
    }

    return payload;
}

// ---------------------------------------------------------------------------
// Lambda handler — FIXED version
// ---------------------------------------------------------------------------
exports.handler = async (event, context, callback) => {
    const headers = event.headers || {};
    const auth_header = headers.Authorization || headers.authorization || '';

    if (!auth_header) {
        return callback(null, { status: 'err', msg: 'missing authorization header' });
    }

    let verifiedToken;
    try {
        // FIXED: Verify signature before trusting any payload claims
        verifiedToken = await verifyCognitoJwt(auth_header);
    } catch (err) {
        return callback(null, { status: 'err', msg: 'invalid token' });
    }

    // Safe to use claims only after successful verification
    const user = verifiedToken.username || verifiedToken.sub;
    const isAdmin = false;

    // ... rest of order manager logic continues here using verified `user`
};

/*
 * ─────────────────────────────────────────────────────────────────────────────
 * DIFF SUMMARY
 * ─────────────────────────────────────────────────────────────────────────────
 * REMOVED (vulnerable):
 *   var token_sections = auth_header.split('.');
 *   var auth_data = jose.util.base64url.decode(token_sections[1]);
 *   var token = JSON.parse(auth_data);
 *   var user = token.username;
 *
 * ADDED (secure):
 *   fetchJson()          — HTTPS helper for JWKS endpoint
 *   getCognitoKeystore() — Cached JWKS fetcher (6-hour TTL)
 *   verifyCognitoJwt()   — Full signature + issuer + expiry verification
 *   handler now calls verifyCognitoJwt() and rejects on any failure
 * ─────────────────────────────────────────────────────────────────────────────
 */
