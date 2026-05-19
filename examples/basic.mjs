import express from 'express';
import { generateKeyPair, sign, exportKey } from '@pq-jwt/core';
import { pqAuth, requireRole, requireClaim } from '../src/index.mjs';

// Node 18 polyfill for global crypto if not present
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

const app = express();
app.use(express.json());

// 1. Generate post-quantum key pair (ML-DSA-65) at startup
console.log('Generating ML-DSA-65 post-quantum key pair...');
const { publicKey, secretKey } = generateKeyPair('ML-DSA-65');
const publicKeyHex = exportKey(publicKey);

// 2. Generate a valid PQ-JWT for demonstration/testing purposes
const demoToken = sign(
  { sub: 'user_123', role: 'admin', emailVerified: true },
  secretKey,
  { algorithm: 'ML-DSA-65', expiresIn: '1h', issuer: 'auth-server', audience: 'api-service' }
);

console.log('\n--- DEMO POST-QUANTUM TOKEN ---');
console.log(demoToken);
console.log('-------------------------------\n');

// 3. Define the Post-Quantum JWT Auth Middleware
const auth = pqAuth({
  publicKey: publicKeyHex, // Accepts hex string or raw Uint8Array
  issuer: 'auth-server',
  audience: 'api-service',
});

// 4. Secure routes with pqAuth and role/claim guards
app.get('/public', (req, res) => {
  res.json({ message: 'This is a public endpoint.' });
});

app.get('/profile', auth, (req, res) => {
  res.json({
    message: 'Welcome! You have successfully authenticated using a Post-Quantum JWT.',
    user: req.user, // Attached by default by pqAuth()
  });
});

app.get('/admin', auth, requireRole('admin'), (req, res) => {
  res.json({
    message: 'Access granted to admin panel.',
    user: req.user,
  });
});

app.get('/premium-features', auth, requireClaim('emailVerified', true), (req, res) => {
  res.json({
    message: 'Access granted to premium features for verified emails.',
    user: req.user,
  });
});

// 5. Global Express error handler for custom typed errors
app.use((err, req, res, next) => {
  console.error('Error occurred:', err.message);
  res.status(err.statusCode || 500).json({
    error: err.message,
    code: err.code || 'INTERNAL_ERROR',
  });
});

const PORT = 3000;
console.log(`Starting demonstration Express server on http://localhost:${PORT}...`);
console.log(`- Try calling GET /profile with:`);
console.log(`  Headers: { "Authorization": "Bearer ${demoToken}" }`);

const server = app.listen(PORT, () => {
  console.log(`Server successfully started.`);
  // Close server automatically after startup for quick check
  setTimeout(() => {
    console.log('Closing example server.');
    server.close();
  }, 1000);
});
