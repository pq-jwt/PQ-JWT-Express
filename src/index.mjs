/**
 * @package     @pq-jwt/express
 * @author      Sachin Ruhil <sachinruhil11@gmail.com>
 * @version     0.0.1
 * @license     MIT
 * @description Express.js middleware for @pq-jwt/core post-quantum JWT authentication.
 *              Turns 15 lines of boilerplate into a single pqAuth() call.
 * @copyright   2025 Sachin Ruhil. All rights reserved.
 * @see         https://github.com/pq-jwt/PQ-JWT-Express
 * @see         NIST FIPS 204 https://doi.org/10.6028/NIST.FIPS.204
 */

import {
  verify,
  importKey,
  TokenExpiredError,
  SignatureError,
  InvalidTokenError,
  PQJWTError,
  SUPPORTED_ALGORITHMS,
} from '@pq-jwt/core';

// ── Error classes ────────────────────────────────────────────

export class PQExpressError extends Error {
  constructor(message, statusCode, code) {
    super(message);
    this.name     = 'PQExpressError';
    this.statusCode = statusCode;
    this.code     = code;
  }
}

export class MissingTokenError extends PQExpressError {
  constructor() {
    super('Missing authentication token', 401, 'MISSING_TOKEN');
    this.name = 'MissingTokenError';
  }
}

export class InvalidAlgorithmError extends PQExpressError {
  constructor(alg) {
    super(`Unsupported algorithm: ${alg}`, 401, 'INVALID_ALGORITHM');
    this.name = 'InvalidAlgorithmError';
  }
}

// ── Default token extractor ────────────────────────────────

/**
 * Default extractor — reads Authorization: Bearer <token>
 * Express always lowercases header names, so req.headers.authorization is correct.
 */
export function defaultExtractor(req) {
  const auth = req.headers?.authorization;
  if (typeof auth === 'string' && auth.startsWith('Bearer '))
    return auth.slice(7).trim() || null;
  return null;
}

/**
 * Cookie extractor — reads a named cookie (requires cookie-parser middleware)
 */
export function cookieExtractor(cookieName = 'pq_token') {
  return (req) => req.cookies?.[cookieName] ?? null;
}

/**
 * Header extractor — reads a custom header (e.g. X-Auth-Token)
 */
export function headerExtractor(headerName) {
  const lower = headerName.toLowerCase();
  return (req) => {
    const val = req.headers?.[lower];
    return typeof val === 'string' ? val.trim() || null : null;
  };
}

/**
 * Multi-source extractor — tries each extractor in order, returns first match
 */
export function fromExtractors(extractors) {
  return (req) => {
    for (const extractor of extractors) {
      const token = extractor(req);
      if (token) return token;
    }
    return null;
  };
}

// ── Default error handler ─────────────────────────────────

function defaultErrorHandler(err, req, res) {
  const statusCode = err.statusCode ?? 500;

  if (err instanceof TokenExpiredError)
    return res.status(401).json({
      error:   'Token expired',
      code:    'TOKEN_EXPIRED',
      expired: new Date(err.expiredAt * 1000).toISOString(),
    });

  if (err instanceof SignatureError)
    return res.status(403).json({
      error: 'Invalid token signature',
      code:  'SIGNATURE_INVALID',
    });

  if (err instanceof MissingTokenError)
    return res.status(401).json({
      error: 'Missing authentication token',
      code:  'MISSING_TOKEN',
    });

  if (err instanceof InvalidAlgorithmError)
    return res.status(401).json({
      error: err.message,
      code:  'INVALID_ALGORITHM',
    });

  if (err instanceof InvalidTokenError || err instanceof PQJWTError)
    return res.status(401).json({
      error: err.message || 'Invalid token',
      code:  err.code ?? 'INVALID_TOKEN',
    });

  // Fallback
  return res.status(statusCode).json({
    error: err.message || 'Authentication error',
    code:  err.code ?? 'AUTH_ERROR',
  });
}

// ── pqAuth() ──────────────────────────────────────────────

/**
 * Express middleware factory for @pq-jwt/core post-quantum JWT auth.
 *
 * @param {object} options
 * @param {Uint8Array|string} options.publicKey         PQ public key — hex string or Uint8Array
 * @param {string|string[]}  [options.issuer]           Expected iss claim
 * @param {string|string[]}  [options.audience]         Expected aud claim
 * @param {string}           [options.subject]          Expected sub claim
 * @param {string|string[]}  [options.algorithms]       Allowed alg values (default: all supported)
 * @param {number}           [options.clockTolerance=0] Seconds of clock skew to tolerate
 * @param {boolean}          [options.ignoreExpiration] Skip exp check (default: false)
 * @param {boolean}          [options.ignoreNotBefore]  Skip nbf check (default: false)
 * @param {function}         [options.extractor]        Custom token extractor (default: Bearer)
 * @param {boolean}          [options.credentialsRequired=true]  Return 401 if no token
 * @param {boolean}          [options.passthrough=false]         Call next() even on error
 * @param {function}         [options.onError]          Custom error handler (err, req, res)
 * @param {string}           [options.userProperty='user'] Attach payload to req[userProperty]
 * @returns {function} Express middleware (req, res, next)
 *
 * @example
 * import { pqAuth } from '@pq-jwt/express';
 *
 * app.use(pqAuth({
 *   publicKey: process.env.PQ_PUBLIC_KEY,
 *   issuer:    'auth.myapp.com',
 *   audience:  'api.myapp.com',
 * }));
 *
 * app.get('/me', (req, res) => res.json(req.user));
 */
export function pqAuth(options = {}) {
  if (!options.publicKey)
    throw new PQExpressError(
      'pqAuth: publicKey is required', 500, 'CONFIG_ERROR'
    );

  // Resolve public key once at startup — not on every request
  const pk = typeof options.publicKey === 'string'
    ? importKey(options.publicKey)
    : options.publicKey;

  const extractor         = options.extractor         ?? defaultExtractor;
  const credentialsRequired = options.credentialsRequired !== false;
  const passthrough       = options.passthrough        === true;
  const userProperty      = typeof options.userProperty === 'string'
    ? options.userProperty
    : 'user';
  const onError           = typeof options.onError === 'function'
    ? options.onError
    : defaultErrorHandler;

  // Build verify options once
  const verifyOpts = {
    clockTolerance: options.clockTolerance ?? 0,
    ignoreExpiry:   options.ignoreExpiration === true,
  };
  if (options.issuer)    verifyOpts.issuer    = options.issuer;
  if (options.audience)  verifyOpts.audience  = options.audience;
  if (options.subject)   verifyOpts.subject   = options.subject;
  if (options.algorithms) {
    const allowed = Array.isArray(options.algorithms)
      ? options.algorithms
      : [options.algorithms];
    verifyOpts.algorithms = allowed;
  }

  // Return the actual middleware
  return function pqAuthMiddleware(req, res, next) {
    const token = extractor(req);

    // No token
    if (!token) {
      if (!credentialsRequired) {
        req[userProperty] = null;
        return next();
      }
      const err = new MissingTokenError();
      if (passthrough) { req.authError = err; return next(); }
      return onError(err, req, res);
    }

    // Verify
    try {
      const { payload } = verify(token, pk, verifyOpts);
      req[userProperty] = payload;
      return next();
    } catch (err) {
      if (passthrough) { req.authError = err; return next(); }
      return onError(err, req, res);
    }
  };
}

// ── Helper: requireRole() ─────────────────────────────────

/**
 * Role-based authorization middleware.
 * Must be used AFTER pqAuth().
 *
 * @param {...string} roles  One or more allowed roles
 * @returns {function} Express middleware
 *
 * @example
 * app.get('/admin', pqAuth({ publicKey }), requireRole('admin'), handler);
 */
export function requireRole(...roles) {
  return function roleMiddleware(req, res, next) {
    const user = req.user;
    if (!user)
      return res.status(401).json({ error: 'Not authenticated', code: 'NOT_AUTHENTICATED' });
    if (roles.length > 0 && !roles.includes(user.role))
      return res.status(403).json({
        error:    `Requires role: ${roles.join(' or ')}`,
        code:     'INSUFFICIENT_ROLE',
        required: roles,
        actual:   user.role ?? null,
      });
    next();
  };
}

/**
 * requireClaim(claim, value?) — verify a specific claim exists (and optionally equals a value)
 *
 * @example
 * app.get('/verified', pqAuth({ publicKey }), requireClaim('emailVerified', true), handler);
 */
export function requireClaim(claim, value) {
  return function claimMiddleware(req, res, next) {
    const user = req.user;
    if (!user)
      return res.status(401).json({ error: 'Not authenticated', code: 'NOT_AUTHENTICATED' });
    if (!(claim in user))
      return res.status(403).json({
        error: `Missing required claim: ${claim}`,
        code:  'MISSING_CLAIM',
        claim,
      });
    if (value !== undefined && user[claim] !== value)
      return res.status(403).json({
        error:    `Claim ${claim} has unexpected value`,
        code:     'CLAIM_MISMATCH',
        claim,
        expected: value,
        actual:   user[claim],
      });
    next();
  };
}

// ── Named extractors re-exported ──────────────────────────
export const extractors = {
  fromBearer:     defaultExtractor,
  fromCookie:     cookieExtractor,
  fromHeader:     headerExtractor,
  fromMultiple:   fromExtractors,
};

// ── Version ──────────────────────────────────────────────
export const VERSION = '0.0.1';
