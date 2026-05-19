/**
 * @package     @pq-jwt/express
 * @author      Sachin Ruhil <sachinruhil11@gmail.com>
 * @version     0.0.1
 * @license     MIT
 * @description Express.js middleware for @pq-jwt/core post-quantum JWT authentication.
 * @copyright   2026 Sachin Ruhil. All rights reserved.
 * @see         https://github.com/pq-jwt/PQ-JWT-Express
 *
 * This version implements post-quantum JWT verification middleware for Express.
 */

import type { Request, Response, NextFunction } from 'express';

// ── Augment Express Request ───────────────────────────────

declare global {
  namespace Express {
    interface Request {
      /** Decoded JWT payload, set by pqAuth() middleware */
      user?: JWTPayload | null;
      /** Auth error when passthrough: true is set */
      authError?: Error;
    }
  }
}

// ── Payload type ──────────────────────────────────────────

export interface JWTPayload {
  sub?:  string;
  iss?:  string;
  aud?:  string | string[];
  exp?:  number;
  iat?:  number;
  nbf?:  number;
  jti?:  string;
  role?: string;
  [key: string]: unknown;
}

// ── Error classes ─────────────────────────────────────────

export class PQExpressError extends Error {
  statusCode: number;
  code:       string;
  constructor(message: string, statusCode: number, code: string);
}

export class MissingTokenError extends PQExpressError {
  constructor();
}

export class InvalidAlgorithmError extends PQExpressError {
  constructor(alg: string);
}

// ── Options ───────────────────────────────────────────────

export type TokenExtractor = (req: Request) => string | null;

export interface PqAuthOptions {
  /** PQ public key — hex string from exportKey() or raw Uint8Array. Required. */
  publicKey: string | Uint8Array;

  /** Expected issuer (iss claim). Single string or array of allowed issuers. */
  issuer?: string | string[];

  /** Expected audience (aud claim). Single string or array of allowed audiences. */
  audience?: string | string[];

  /** Expected subject (sub claim). */
  subject?: string;

  /** Allowed algorithm identifiers. Default: all algorithms supported by @pq-jwt/core. */
  algorithms?: string | string[];

  /** Seconds of clock skew to tolerate for exp/nbf checks. Default: 0 (strict). */
  clockTolerance?: number;

  /** Skip expiration (exp) check. Default: false. */
  ignoreExpiration?: boolean;

  /** Skip not-before (nbf) check. Default: false. */
  ignoreNotBefore?: boolean;

  /**
   * Token extractor function. Default: reads Authorization: Bearer <token>.
   * Use extractors.fromCookie(), extractors.fromHeader(), or extractors.fromMultiple().
   */
  extractor?: TokenExtractor;

  /**
   * Return 401 if no token is found. Default: true.
   * Set to false to allow unauthenticated requests (req.user will be null).
   */
  credentialsRequired?: boolean;

  /**
   * Call next() even on auth errors. The error is attached to req.authError.
   * Default: false.
   */
  passthrough?: boolean;

  /**
   * Custom error handler. Called instead of the default JSON error response.
   * @param err   The authentication error
   * @param req   Express request
   * @param res   Express response
   */
  onError?: (err: Error, req: Request, res: Response) => void;

  /**
   * Property name to attach the decoded payload to on req.
   * Default: 'user' (attaches to req.user).
   */
  userProperty?: string;
}

// ── Main exports ──────────────────────────────────────────

/**
 * Express middleware factory for @pq-jwt/core post-quantum JWT authentication.
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
export function pqAuth(options: PqAuthOptions): (
  req:  Request,
  res:  Response,
  next: NextFunction
) => void;

/**
 * Role-based authorization middleware. Must follow pqAuth().
 *
 * @example
 * app.get('/admin', pqAuth({ publicKey }), requireRole('admin'), handler);
 */
export function requireRole(
  ...roles: string[]
): (req: Request, res: Response, next: NextFunction) => void;

/**
 * Claim-based authorization middleware. Verifies a specific claim.
 *
 * @example
 * app.get('/verified', pqAuth({ publicKey }), requireClaim('emailVerified', true), handler);
 */
export function requireClaim(
  claim: string,
  value?: unknown
): (req: Request, res: Response, next: NextFunction) => void;

// ── Extractors ────────────────────────────────────────────

/** Default extractor — reads Authorization: Bearer <token> */
export function defaultExtractor(req: Request): string | null;

/** Cookie extractor — reads a named cookie (requires cookie-parser) */
export function cookieExtractor(cookieName?: string): TokenExtractor;

/** Header extractor — reads a named HTTP header */
export function headerExtractor(headerName: string): TokenExtractor;

/** Multi-source extractor — tries each extractor in order */
export function fromExtractors(extractors: TokenExtractor[]): TokenExtractor;

/** Extractor helpers object */
export const extractors: {
  fromBearer:   typeof defaultExtractor;
  fromCookie:   typeof cookieExtractor;
  fromHeader:   typeof headerExtractor;
  fromMultiple: typeof fromExtractors;
};

export const VERSION: string;
