# @pq-jwt/express

**Express.js middleware for post-quantum JWT authentication.**
Wraps `@pq-jwt/core` into a single `pqAuth()` call.

Part of the [pq-jwt ecosystem](https://pq-jwt.github.io) by **Sachin Ruhil**.

```bash
npm install @pq-jwt/express @pq-jwt/core
```

---

## Before vs After

**Before** — 15 lines of boilerplate per route:

```javascript
app.get('/api/me', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  try {
    const { payload } = verify(auth.slice(7), publicKey, { issuer: 'myapp' });
    req.user = payload;
    res.json(req.user);
  } catch (e) {
    if (e instanceof TokenExpiredError) return res.status(401).json({ error: 'Expired' });
    if (e instanceof SignatureError) return res.status(403).json({ error: 'Invalid' });
    res.status(401).json({ error: e.message });
  }
});
```

**After** — one call protects everything:

```javascript
app.use(pqAuth({ publicKey: process.env.PQ_PUBLIC_KEY, issuer: 'myapp' }));
app.get('/api/me', (req, res) => res.json(req.user));
```

---

## Quick Start

```javascript
import express from 'express';
import { pqAuth } from '@pq-jwt/express';

const app = express();

app.use(pqAuth({
  publicKey: process.env.PQ_PUBLIC_KEY,  // hex from exportKey()
  issuer:    'auth.myapp.com',
  audience:  'api.myapp.com',
}));

// req.user is populated and verified on every request below this line
app.get('/me',     (req, res) => res.json({ user: req.user }));
app.get('/orders', (req, res) => res.json({ orders: [] }));

app.listen(3000);
```

---

## Options

```typescript
pqAuth({
  // Required
  publicKey: string | Uint8Array,  // PQ public key — exportKey() hex or raw Uint8Array

  // Claim validation
  issuer?:      string | string[],  // Expected iss
  audience?:    string | string[],  // Expected aud
  subject?:     string,             // Expected sub
  algorithms?:  string | string[],  // Allowed alg values

  // Time validation
  clockTolerance?:   number,   // Seconds of clock skew (default: 0)
  ignoreExpiration?: boolean,  // Skip exp check (default: false)

  // Token source
  extractor?: (req) => string | null,  // Default: Authorization: Bearer

  // Behaviour
  credentialsRequired?: boolean,  // 401 if no token (default: true)
  passthrough?:         boolean,  // next() even on error (default: false)

  // Response
  onError?:      (err, req, res) => void,  // Custom error handler
  userProperty?: string,                   // Default: 'user' (req.user)
})
```

---

## Role-based Access Control

```javascript
import { pqAuth, requireRole, requireClaim } from '@pq-jwt/express';

const auth = pqAuth({ publicKey, issuer: 'myapp' });

// Require specific role
app.get('/admin', auth, requireRole('admin'), handler);

// Allow multiple roles
app.get('/content', auth, requireRole('admin', 'editor'), handler);

// Require a specific claim value
app.get('/premium', auth, requireClaim('plan', 'premium'), handler);

// Require claim exists (any value)
app.get('/verified', auth, requireClaim('emailVerified'), handler);
```

---

## Custom Token Sources

```javascript
import { pqAuth, extractors } from '@pq-jwt/express';

// From a cookie (use with cookie-parser)
app.use(pqAuth({
  publicKey,
  extractor: extractors.fromCookie('pq_token'),
}));

// From a custom header
app.use(pqAuth({
  publicKey,
  extractor: extractors.fromHeader('X-Auth-Token'),
}));

// Try multiple sources — first match wins
app.use(pqAuth({
  publicKey,
  extractor: extractors.fromMultiple([
    extractors.fromBearer,
    extractors.fromCookie('pq_token'),
    extractors.fromHeader('X-Auth-Token'),
  ]),
}));
```

---

## Optional Authentication

```javascript
// Allow requests with or without a token
app.use(pqAuth({
  publicKey,
  credentialsRequired: false,
}));

app.get('/feed', (req, res) => {
  if (req.user) {
    res.json({ personalized: true, user: req.user });
  } else {
    res.json({ personalized: false });
  }
});
```

---

## Custom Error Handling

```javascript
app.use(pqAuth({
  publicKey,
  onError: (err, req, res) => {
    // Log to your observability system
    logger.warn({ ip: req.ip, error: err.code });

    if (err.name === 'TokenExpiredError')
      return res.status(401).json({ error: 'Expired', refresh: '/auth/refresh' });

    if (err.name === 'SignatureError')
      return res.status(403).json({ error: 'Token tampered' });

    res.status(401).json({ error: err.message });
  },
}));
```

---

## HTTP Status Mapping

| Situation | Status | Code |
|---|---|---|
| No token in request | 401 | `MISSING_TOKEN` |
| Token expired | 401 | `TOKEN_EXPIRED` |
| Signature invalid / tampered | 403 | `SIGNATURE_INVALID` |
| Malformed token | 401 | `INVALID_TOKEN` |
| Issuer/audience mismatch | 401 | `INVALID_TOKEN` |
| Disallowed algorithm | 401 | `INVALID_ALGORITHM` |
| Insufficient role | 403 | `INSUFFICIENT_ROLE` |
| Missing required claim | 403 | `MISSING_CLAIM` |
| Claim value mismatch | 403 | `CLAIM_MISMATCH` |

---

## TypeScript

No `@types/` package needed. `req.user` is typed automatically:

```typescript
import { pqAuth, requireRole } from '@pq-jwt/express';

app.use(pqAuth({ publicKey, issuer: 'myapp' }));

app.get('/me', (req, res) => {
  // req.user is typed as JWTPayload | null | undefined
  const userId = req.user?.sub;
  res.json({ userId });
});
```

---

## Ecosystem

| Package | Description |
|---|---|
| [`@pq-jwt/core`](https://npmjs.com/package/@pq-jwt/core) | PQ JWT sign/verify — ML-DSA, SLH-DSA |
| [`@pq-jwt/hybrid`](https://npmjs.com/package/@pq-jwt/hybrid) | ECDSA + ML-DSA migration bridge |
| [`@pq-jwt/express`](https://npmjs.com/package/@pq-jwt/express) | This package |

Website: [pq-jwt.github.io](https://pq-jwt.github.io)

---

**Sachin Ruhil** · MIT License
