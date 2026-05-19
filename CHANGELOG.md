# Changelog

## 1.0.0 — 2026-05-19

### Initial Release

- Production-ready Express.js middleware for `@pq-jwt/core` post-quantum JSON Web Token verification.
- `pqAuth()` middleware factory with seamless support for:
  - Custom token extractors (Bearer authorization headers, custom cookies, custom headers, and multi-source fallbacks).
  - Robust clock skew tolerance (`clockTolerance`) and expiration bypassing (`ignoreExpiration`).
  - Pre-resolved and runtime-resolved post-quantum public keys (both raw `Uint8Array` keys and hex strings).
  - Custom error handling capabilities via `onError` options.
  - Flexible target property mapping (defaults to `req.user`).
- Role-based authorization middleware via `requireRole()`.
- Generic claim-based validation middleware via `requireClaim()`.
- Built-in type definitions for TypeScript support (`src/index.d.ts`).
- Full compatibility with all four NIST ML-DSA and SLH-DSA draft standard algorithms (ML-DSA-44, ML-DSA-65, ML-DSA-87, SLH-DSA-SHA2-128s).
- Full 53/53 test coverage verifying all features, options, errors, and custom handlers.
