/**
 * @pq-jwt/express — full test suite
 * Tests all middleware features without spinning up a real HTTP server.
 * We mock req/res/next objects to test the middleware in isolation.
 */

import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

import {
  pqAuth, requireRole, requireClaim,
  MissingTokenError, InvalidAlgorithmError, PQExpressError,
  defaultExtractor, cookieExtractor, headerExtractor, fromExtractors,
  extractors, VERSION,
} from '../src/index.mjs';

import {
  generateKeyPair, sign, verify, exportKey, importKey,
  TokenExpiredError, SignatureError, InvalidTokenError,
} from '@pq-jwt/core';

let pass = 0, fail = 0;

function test(name, fn) {
  try { fn(); console.log(`  ✓  ${name}`); pass++; }
  catch (e) { console.log(`  ✗  ${name} — ${e.message}`); fail++; }
}
function assert(c, m) { if (!c) throw new Error(m || 'assertion failed'); }

// ── Mock helpers ─────────────────────────────────────────
function mockReq(overrides = {}) {
  return {
    headers: {},
    cookies: {},
    query:   {},
    user:    undefined,
    ...overrides,
  };
}

function mockRes() {
  const res = {
    _status: null,
    _body:   null,
    status(code) { this._status = code; return this; },
    json(body)   { this._body   = body; return this; },
    send(body)   { this._body   = body; return this; },
  };
  return res;
}

function mockNext() {
  let called = false;
  const fn = () => { called = true; };
  fn.wasCalled = () => called;
  return fn;
}

// ── Key setup ─────────────────────────────────────────────
const kp    = generateKeyPair('ML-DSA-65');
const PK    = kp.publicKey;
const SK    = kp.secretKey;
const PKHEX = exportKey(PK);

function makeToken(payload = {}, opts = {}) {
  return sign(
    { sub: 'u1', role: 'admin', ...payload },
    SK,
    { algorithm: 'ML-DSA-65', expiresIn: '1h', issuer: 'test', audience: 'api', ...opts }
  );
}

const VALID_TOKEN   = makeToken();
const EXPIRED_TOKEN = makeToken({}, { expiresIn: -10 });

function bearerReq(token) {
  return mockReq({ headers: { authorization: `Bearer ${token}` } });
}

// ─────────────────────────────────────────────────────────
console.log('\n── pqAuth() factory ──────────────────────────────────────');

test('throws if publicKey missing', () => {
  let threw = false;
  try { pqAuth({}); } catch (e) { threw = true; assert(e.code === 'CONFIG_ERROR', 'code'); }
  assert(threw, 'should throw');
});
test('accepts Uint8Array publicKey', () => {
  const mw = pqAuth({ publicKey: PK });
  assert(typeof mw === 'function', 'returns function');
});
test('accepts hex string publicKey', () => {
  const mw = pqAuth({ publicKey: PKHEX });
  assert(typeof mw === 'function', 'returns function');
});
test('returns a 3-arg middleware function', () => {
  const mw = pqAuth({ publicKey: PK });
  assert(mw.length === 3, `expected 3 args, got ${mw.length}`);
});

// ─────────────────────────────────────────────────────────
console.log('\n── valid token ───────────────────────────────────────────');

test('calls next() on valid token', () => {
  const mw   = pqAuth({ publicKey: PK, issuer: 'test', audience: 'api' });
  const req  = bearerReq(VALID_TOKEN);
  const res  = mockRes();
  const next = mockNext();
  mw(req, res, next);
  assert(next.wasCalled(), 'next not called');
  assert(req.user?.sub === 'u1', `user.sub=${req.user?.sub}`);
  assert(req.user?.role === 'admin', 'role');
});
test('attaches payload to req.user', () => {
  const mw  = pqAuth({ publicKey: PK, issuer: 'test', audience: 'api' });
  const req = bearerReq(VALID_TOKEN);
  mw(req, mockRes(), mockNext());
  assert(req.user?.sub === 'u1', 'sub');
  assert(req.user?.iss === 'test', 'iss');
  assert(typeof req.user?.exp === 'number', 'exp');
});
test('userProperty option works (req.principal)', () => {
  const mw  = pqAuth({ publicKey: PK, issuer: 'test', audience: 'api', userProperty: 'principal' });
  const req = bearerReq(VALID_TOKEN);
  mw(req, mockRes(), mockNext());
  assert(req.principal?.sub === 'u1', 'principal.sub');
  assert(req.user === undefined, 'req.user not set');
});
test('accepts hex key string at runtime', () => {
  const mw  = pqAuth({ publicKey: PKHEX, issuer: 'test', audience: 'api' });
  const req = bearerReq(VALID_TOKEN);
  const next = mockNext();
  mw(req, mockRes(), next);
  assert(next.wasCalled(), 'next');
  assert(req.user?.sub === 'u1', 'user');
});

// ─────────────────────────────────────────────────────────
console.log('\n── missing token ─────────────────────────────────────────');

test('returns 401 when no Authorization header', () => {
  const mw  = pqAuth({ publicKey: PK });
  const req = mockReq();
  const res = mockRes();
  mw(req, res, mockNext());
  assert(res._status === 401, `status=${res._status}`);
  assert(res._body?.code === 'MISSING_TOKEN', `code=${res._body?.code}`);
});
test('credentialsRequired:false — calls next() with req.user=null', () => {
  const mw  = pqAuth({ publicKey: PK, credentialsRequired: false });
  const req = mockReq();
  const next = mockNext();
  mw(req, mockRes(), next);
  assert(next.wasCalled(), 'next');
  assert(req.user === null, `user=${req.user}`);
});
test('passthrough:true — calls next() with req.authError set', () => {
  const mw  = pqAuth({ publicKey: PK, passthrough: true });
  const req = mockReq();
  const next = mockNext();
  mw(req, mockRes(), next);
  assert(next.wasCalled(), 'next');
  assert(req.authError instanceof MissingTokenError, 'authError class');
});

// ─────────────────────────────────────────────────────────
console.log('\n── expired token ─────────────────────────────────────────');

test('returns 401 with TOKEN_EXPIRED on expired token', () => {
  const mw  = pqAuth({ publicKey: PK });
  const req = bearerReq(EXPIRED_TOKEN);
  const res = mockRes();
  mw(req, res, mockNext());
  assert(res._status === 401, `status=${res._status}`);
  assert(res._body?.code === 'TOKEN_EXPIRED', `code=${res._body?.code}`);
  assert(typeof res._body?.expired === 'string', 'expired timestamp');
});
test('ignoreExpiration bypasses exp check', () => {
  const mw   = pqAuth({ publicKey: PK, ignoreExpiration: true });
  const next = mockNext();
  mw(bearerReq(EXPIRED_TOKEN), mockRes(), next);
  assert(next.wasCalled(), 'next called');
});
test('clockTolerance accepts slightly expired token', () => {
  const tok  = makeToken({}, { expiresIn: -5 });
  const mw   = pqAuth({ publicKey: PK, clockTolerance: 10 });
  const next = mockNext();
  mw(bearerReq(tok), mockRes(), next);
  assert(next.wasCalled(), 'next called');
});
test('clockTolerance still rejects well-expired token', () => {
  const tok = makeToken({}, { expiresIn: -60 });
  const mw  = pqAuth({ publicKey: PK, clockTolerance: 10 });
  const res = mockRes();
  mw(bearerReq(tok), res, mockNext());
  assert(res._status === 401, 'should be 401');
  assert(res._body?.code === 'TOKEN_EXPIRED', 'code');
});

// ─────────────────────────────────────────────────────────
console.log('\n── signature / invalid token ─────────────────────────────');

test('returns 403 on tampered signature', () => {
  const parts = VALID_TOKEN.split('.');
  parts[2]    = parts[2].slice(0, -4) + 'XXXX';
  const mw    = pqAuth({ publicKey: PK });
  const res   = mockRes();
  mw(bearerReq(parts.join('.')), res, mockNext());
  assert(res._status === 403, `status=${res._status}`);
  assert(res._body?.code === 'SIGNATURE_INVALID', `code=${res._body?.code}`);
});
test('returns 401 on malformed token', () => {
  const mw  = pqAuth({ publicKey: PK });
  const res = mockRes();
  mw(bearerReq('not.a.valid.token.here'), res, mockNext());
  assert(res._status === 401, `status=${res._status}`);
});
test('returns 403 with wrong public key', () => {
  const otherKp = generateKeyPair('ML-DSA-65');
  const mw      = pqAuth({ publicKey: otherKp.publicKey });
  const res     = mockRes();
  mw(bearerReq(VALID_TOKEN), res, mockNext());
  assert(res._status === 403, `status=${res._status}`);
});

// ─────────────────────────────────────────────────────────
console.log('\n── claim validation ──────────────────────────────────────');

test('issuer validation passes', () => {
  const mw   = pqAuth({ publicKey: PK, issuer: 'test' });
  const next = mockNext();
  mw(bearerReq(VALID_TOKEN), mockRes(), next);
  assert(next.wasCalled(), 'next');
});
test('issuer validation fails on mismatch', () => {
  const mw  = pqAuth({ publicKey: PK, issuer: 'wrong' });
  const res = mockRes();
  mw(bearerReq(VALID_TOKEN), res, mockNext());
  assert(res._status === 401, `status=${res._status}`);
});
test('audience validation passes', () => {
  const mw   = pqAuth({ publicKey: PK, issuer: 'test', audience: 'api' });
  const next = mockNext();
  mw(bearerReq(VALID_TOKEN), mockRes(), next);
  assert(next.wasCalled(), 'next');
});
test('audience validation fails on mismatch', () => {
  const mw  = pqAuth({ publicKey: PK, issuer: 'test', audience: 'wrong' });
  const res = mockRes();
  mw(bearerReq(VALID_TOKEN), res, mockNext());
  assert(res._status === 401, `status=${res._status}`);
});
test('algorithm allowlist passes', () => {
  const mw   = pqAuth({ publicKey: PK, algorithms: ['ML-DSA-65', 'ML-DSA-87'] });
  const next = mockNext();
  mw(bearerReq(VALID_TOKEN), mockRes(), next);
  assert(next.wasCalled(), 'next');
});
test('algorithm allowlist rejects disallowed alg', () => {
  const mw  = pqAuth({ publicKey: PK, algorithms: ['ML-DSA-87'] });
  const res = mockRes();
  mw(bearerReq(VALID_TOKEN), res, mockNext());
  assert(res._status === 401, `status=${res._status}`);
});

// ─────────────────────────────────────────────────────────
console.log('\n── onError custom handler ────────────────────────────────');

test('onError called instead of default handler', () => {
  let caughtErr = null;
  const mw = pqAuth({
    publicKey: PK,
    onError: (err, req, res) => {
      caughtErr = err;
      res.status(418).json({ custom: true });
    }
  });
  const req = mockReq();
  const res = mockRes();
  mw(req, res, mockNext());
  assert(caughtErr instanceof MissingTokenError, 'got MissingTokenError');
  assert(res._status === 418, 'custom status');
  assert(res._body?.custom === true, 'custom body');
});
test('onError receives TokenExpiredError', () => {
  let errName = null;
  const mw = pqAuth({
    publicKey: PK,
    onError: (err, req, res) => { errName = err.constructor.name; res.status(401).json({}); }
  });
  mw(bearerReq(EXPIRED_TOKEN), mockRes(), mockNext());
  assert(errName === 'TokenExpiredError', `got ${errName}`);
});
test('onError receives SignatureError on tamper', () => {
  let errName = null;
  const mw = pqAuth({
    publicKey: PK,
    onError: (err, req, res) => { errName = err.constructor.name; res.status(403).json({}); }
  });
  const parts = VALID_TOKEN.split('.');
  parts[2]    = parts[2].slice(0,-4)+'XXXX';
  mw(bearerReq(parts.join('.')), mockRes(), mockNext());
  assert(errName === 'SignatureError', `got ${errName}`);
});

// ─────────────────────────────────────────────────────────
console.log('\n── extractors ────────────────────────────────────────────');

test('defaultExtractor reads Bearer header', () => {
  const req = mockReq({ headers: { authorization: `Bearer ${VALID_TOKEN}` } });
  assert(defaultExtractor(req) === VALID_TOKEN, 'token');
});
test('defaultExtractor returns null with no header', () => {
  assert(defaultExtractor(mockReq()) === null, 'null');
});
test('defaultExtractor returns null with non-Bearer header', () => {
  const req = mockReq({ headers: { authorization: 'Basic abc123' } });
  assert(defaultExtractor(req) === null, 'null for Basic');
});
test('cookieExtractor reads cookie by name', () => {
  const req = mockReq({ cookies: { pq_token: VALID_TOKEN } });
  assert(cookieExtractor('pq_token')(req) === VALID_TOKEN, 'token from cookie');
});
test('cookieExtractor returns null when cookie absent', () => {
  assert(cookieExtractor('pq_token')(mockReq()) === null, 'null');
});
test('headerExtractor reads custom header', () => {
  const req = mockReq({ headers: { 'x-auth-token': VALID_TOKEN } });
  assert(headerExtractor('X-Auth-Token')(req) === VALID_TOKEN, 'token from header');
});
test('fromExtractors returns first match', () => {
  const req = mockReq({
    cookies: { pq_token: VALID_TOKEN },
    headers: {},
  });
  const extractor = fromExtractors([defaultExtractor, cookieExtractor('pq_token')]);
  assert(extractor(req) === VALID_TOKEN, 'from cookie');
});
test('fromExtractors returns null when none match', () => {
  const extractor = fromExtractors([defaultExtractor, cookieExtractor('pq_token')]);
  assert(extractor(mockReq()) === null, 'null');
});
test('extractors object has all 4 methods', () => {
  assert(typeof extractors.fromBearer   === 'function', 'fromBearer');
  assert(typeof extractors.fromCookie   === 'function', 'fromCookie');
  assert(typeof extractors.fromHeader   === 'function', 'fromHeader');
  assert(typeof extractors.fromMultiple === 'function', 'fromMultiple');
});
test('cookie extractor works as pqAuth extractor option', () => {
  const mw  = pqAuth({
    publicKey:  PK,
    extractor:  cookieExtractor('pq_session'),
    issuer:     'test',
    audience:   'api',
  });
  const req  = mockReq({ cookies: { pq_session: VALID_TOKEN } });
  const next = mockNext();
  mw(req, mockRes(), next);
  assert(next.wasCalled(), 'next');
  assert(req.user?.sub === 'u1', 'user from cookie');
});

// ─────────────────────────────────────────────────────────
console.log('\n── requireRole() ─────────────────────────────────────────');

test('requireRole passes when role matches', () => {
  const req  = mockReq({ user: { sub: 'u1', role: 'admin' } });
  const next = mockNext();
  requireRole('admin')(req, mockRes(), next);
  assert(next.wasCalled(), 'next');
});
test('requireRole passes with multiple allowed roles', () => {
  const req  = mockReq({ user: { sub: 'u1', role: 'editor' } });
  const next = mockNext();
  requireRole('admin', 'editor')(req, mockRes(), next);
  assert(next.wasCalled(), 'next');
});
test('requireRole returns 403 on wrong role', () => {
  const req = mockReq({ user: { sub: 'u1', role: 'viewer' } });
  const res = mockRes();
  requireRole('admin')(req, res, mockNext());
  assert(res._status === 403, `status=${res._status}`);
  assert(res._body?.code === 'INSUFFICIENT_ROLE', 'code');
  assert(Array.isArray(res._body?.required), 'required is array');
});
test('requireRole returns 401 when no user', () => {
  const req = mockReq({});
  const res = mockRes();
  requireRole('admin')(req, res, mockNext());
  assert(res._status === 401, `status=${res._status}`);
});

// ─────────────────────────────────────────────────────────
console.log('\n── requireClaim() ────────────────────────────────────────');

test('requireClaim passes when claim exists', () => {
  const req  = mockReq({ user: { emailVerified: true } });
  const next = mockNext();
  requireClaim('emailVerified')(req, mockRes(), next);
  assert(next.wasCalled(), 'next');
});
test('requireClaim passes when claim matches value', () => {
  const req  = mockReq({ user: { plan: 'premium' } });
  const next = mockNext();
  requireClaim('plan', 'premium')(req, mockRes(), next);
  assert(next.wasCalled(), 'next');
});
test('requireClaim returns 403 when claim missing', () => {
  const req = mockReq({ user: { sub: 'u1' } });
  const res = mockRes();
  requireClaim('emailVerified')(req, res, mockNext());
  assert(res._status === 403, `status=${res._status}`);
  assert(res._body?.code === 'MISSING_CLAIM', 'code');
});
test('requireClaim returns 403 on value mismatch', () => {
  const req = mockReq({ user: { plan: 'free' } });
  const res = mockRes();
  requireClaim('plan', 'premium')(req, res, mockNext());
  assert(res._status === 403, `status=${res._status}`);
  assert(res._body?.code === 'CLAIM_MISMATCH', 'code');
  assert(res._body?.expected === 'premium', 'expected');
  assert(res._body?.actual === 'free', 'actual');
});
test('requireClaim returns 401 when no user', () => {
  const res = mockRes();
  requireClaim('role')(mockReq(), res, mockNext());
  assert(res._status === 401, 'status');
});

// ─────────────────────────────────────────────────────────
console.log('\n── full middleware chain ─────────────────────────────────');

test('pqAuth → requireRole — full chain passes', () => {
  const auth    = pqAuth({ publicKey: PK, issuer: 'test', audience: 'api' });
  const roleChk = requireRole('admin');

  // Simulate Express middleware chain
  const req  = bearerReq(VALID_TOKEN);
  const res  = mockRes();
  let nextCount = 0;

  auth(req, res, () => {
    nextCount++;
    roleChk(req, res, () => { nextCount++; });
  });

  assert(nextCount === 2, `chain ran ${nextCount}/2 steps`);
  assert(req.user?.role === 'admin', 'role');
});
test('pqAuth → requireRole — chain blocked on expired', () => {
  const auth    = pqAuth({ publicKey: PK });
  const roleChk = requireRole('admin');

  const req = bearerReq(EXPIRED_TOKEN);
  const res = mockRes();
  let nextCount = 0;

  auth(req, res, () => {
    nextCount++;
    roleChk(req, res, () => { nextCount++; });
  });

  assert(nextCount === 0, 'chain should not proceed');
  assert(res._status === 401, 'status');
});

// ─────────────────────────────────────────────────────────
console.log('\n── all 4 NIST algorithms ─────────────────────────────────');

import { SUPPORTED_ALGORITHMS } from '@pq-jwt/core';

for (const alg of SUPPORTED_ALGORITHMS) {
  test(`${alg}: sign + pqAuth verify`, () => {
    const kpA = generateKeyPair(alg);
    const tok = sign({ sub: 'u1', role: 'user' }, kpA.secretKey, {
      algorithm: alg, expiresIn: '1h', issuer: 'test',
    });
    const mw   = pqAuth({ publicKey: kpA.publicKey, issuer: 'test' });
    const req  = bearerReq(tok);
    const next = mockNext();
    mw(req, mockRes(), next);
    assert(next.wasCalled(), 'next');
    assert(req.user?.sub === 'u1', 'sub');
  });
}

// ─────────────────────────────────────────────────────────
console.log('\n── VERSION export ────────────────────────────────────────');

test('VERSION is a string', () => {
  assert(typeof VERSION === 'string', 'type');
  assert(VERSION === '0.0.1', `version=${VERSION}`);
});

// ─────────────────────────────────────────────────────────
console.log('\n── results ───────────────────────────────────────────────');
const total = pass + fail;
console.log(`\n  ${pass}/${total} passed ${fail > 0 ? `(${fail} FAILED)` : '— ALL PASS ✓'}\n`);
if (fail > 0) process.exit(1);
