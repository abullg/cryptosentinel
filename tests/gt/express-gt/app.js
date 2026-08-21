/**
 * CryptoSentinel Express GT — mini vulnerable app
 * Per Claude v9: "Express: IDOR + mass assignment + race на /transfer"
 *
 * Vulnerable endpoints (all intentionally vulnerable):
 *
 * 1. IDOR (BOLA) — GET /api/users/:id
 *    Any authenticated user can access any user by ID (no per-user authz)
 *
 * 2. Mass Assignment — PUT /api/users/:id
 *    User can PUT {role:"admin", balance:99999} → role/balance change
 *
 * 3. Race Condition — POST /api/transfer
 *    Double-spend: parallel requests can withdraw balance twice
 *    (TOCTOU: check balance → deduct, non-atomic)
 *
 * 4. JWT alg=none bypass — GET /api/profile
 *    Forged token with alg=none accepted → admin profile
 *
 * 5. BFLA (Broken Function Level Authorization) — POST /api/admin/users
 *    Regular user can call admin endpoint (no role check)
 *
 * Test credentials:
 *   user/user — regular user (ID=1)
 *   admin/admin — admin (ID=2)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3010;
const JWT_SECRET = 'cs-express-gt-secret-2026';

// ─── IN-MEMORY DB ───────────────────────────────────────────────────
const users = [
  { id: 1, username: 'user', password: 'user', role: 'user', balance: 1000, email: 'user@cs-gt.local', ssn: '123-45-6789' },
  { id: 2, username: 'admin', password: 'admin', role: 'admin', balance: 50000, email: 'admin@cs-gt.local', ssn: '987-65-4321' },
  { id: 3, username: 'alice', password: 'alice', role: 'user', balance: 500, email: 'alice@cs-gt.local', ssn: '111-22-3333' },
];

// ─── HEALTH ──────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    service: 'CryptoSentinel Express GT',
    version: '1.0',
    endpoints: [
      'POST /api/login',
      'GET /api/users/:id (IDOR)',
      'PUT /api/users/:id (mass assignment)',
      'POST /api/transfer (race)',
      'GET /api/profile (JWT bypass)',
      'POST /api/admin/users (BFLA)',
    ],
  });
});

// ─── LOGIN ───────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// Auth middleware
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    // INTENTIONALLY VULNERABLE: accept alg=none (JWT bypass)
    // Decode header to check alg
    const parts = token.split('.');
    if (parts.length >= 2) {
      const headerJson = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      if (headerJson.alg === 'none') {
        // BYPASS: accept forged token without signature verification
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        req.user = payload;
        return next();
      }
    }
    // Normal JWT verification
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── IDOR (BOLA) ────────────────────────────────────────────────────
// Any authenticated user can access ANY user by ID — no per-user authz
app.get('/api/users/:id', auth, (req, res) => {
  const userId = parseInt(req.params.id);
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // VULNERABLE: returns ALL user data including SSN, regardless of who's requesting
  // Should check: req.user.id === userId OR req.user.role === 'admin'
  res.json({
    id: user.id,
    username: user.username,
    role: user.role,
    balance: user.balance,
    email: user.email,
    ssn: user.ssn,  // ← sensitive data exposed to any user
  });
});

// ─── MASS ASSIGNMENT ────────────────────────────────────────────────
// User can PUT {role:"admin", balance:99999} → role/balance change
app.put('/api/users/:id', auth, (req, res) => {
  const userId = parseInt(req.params.id);
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // VULNERABLE: blindly merge all fields from request body
  // Should whitelist: only allow updating 'email' or 'username'
  Object.assign(user, req.body);

  res.json({
    id: user.id,
    username: user.username,
    role: user.role,
    balance: user.balance,
    email: user.email,
  });
});

// ─── RACE CONDITION (TOCTOU) ────────────────────────────────────────
// Double-spend: parallel requests can withdraw balance twice
app.post('/api/transfer', auth, (req, res) => {
  const { toUserId, amount } = req.body;
  const fromUser = users.find(u => u.id === req.user.id);
  const toUser = users.find(u => u.id === toUserId);

  if (!fromUser || !toUser) return res.status(404).json({ error: 'User not found' });
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });

  // VULNERABLE: check-then-act without atomic transaction
  // Race condition: two parallel requests both see balance=1000, both deduct 1000
  if (fromUser.balance < amount) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }

  // SIMULATE non-atomic delay (makes race exploitable)
  // In real app this would be DB query + network latency
  const start = Date.now();
  while (Date.now() - start < 50) { /* spin 50ms */ }

  fromUser.balance -= amount;
  toUser.balance += amount;

  res.json({
    status: 'transferred',
    from: fromUser.username,
    to: toUser.username,
    amount,
    newBalance: fromUser.balance,
  });
});

// ─── JWT alg=none BYPASS ────────────────────────────────────────────
// Forged token with alg=none accepted → admin profile
app.get('/api/profile', auth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // VULNERABLE: returns profile based on forged token's payload
  // If alg=none token has {role:"admin"}, returns admin data
  res.json({
    id: user.id,
    username: user.username,
    role: req.user.role || user.role,  // ← uses role from token (forgeable)
    balance: user.balance,
    email: user.email,
  });
});

// ─── BFLA (Broken Function Level Authorization) ───────────────────
// Regular user can call admin endpoint (no role check)
app.post('/api/admin/users', auth, (req, res) => {
  // VULNERABLE: no check that req.user.role === 'admin'
  // Should be: if (req.user.role !== 'admin') return 403
  const { username, password, role } = req.body;
  const newUser = {
    id: users.length + 1,
    username: username || `user${users.length + 1}`,
    password: password || 'default',
    role: role || 'user',  // ← regular user can create admin
    balance: 0,
    email: `${username || 'newuser'}@cs-gt.local`,
    ssn: '000-00-0000',
  };
  users.push(newUser);
  res.json({ status: 'created', user: { id: newUser.id, username: newUser.username, role: newUser.role } });
});

// ─── SERVER ─────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[express-gt] Listening on port ${PORT}`);
  console.log(`[express-gt] Vulnerable endpoints ready for oracle testing`);
});
