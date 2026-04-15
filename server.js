const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// INTENTIONAL WEAKNESS: JWT secret is hardcoded — easily discoverable in source control.
// Threat #3: Information Disclosure — Hardcoded JWT Secret
// Mitigation: load from environment variable (process.env.JWT_SECRET)
const JWT_SECRET = 'secret123';

app.use(express.json());
app.use(express.static('public'));

// ---------------------------------------------------------------------------
// In-memory data store (resets on server restart — fine for demo purposes)
// In production this would be a persistent database (e.g. PostgreSQL, SQLite).
// The threat model diagram reflects that production architecture.
// ---------------------------------------------------------------------------
let nextUserId = 1;
let nextNoteId = 1;

// Map<username, { id, username, passwordHash }>
const users = new Map();

// Map<noteId, { id, userId, body, createdAt }>
const notes = new Map();

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------
function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }
  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---------------------------------------------------------------------------
// POST /register
// ---------------------------------------------------------------------------
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }
  if (users.has(username)) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const user = { id: nextUserId++, username, passwordHash };
  users.set(username, user);
  res.status(201).json({ id: user.id, username });
});

// ---------------------------------------------------------------------------
// POST /login
// INTENTIONAL WEAKNESS: no rate limiting — allows unlimited password guesses.
// Threat #1: Spoofing — Brute Force on /login
// Threat #5: Denial of Service — Unrestricted Request Volume
// Mitigation: add express-rate-limit, account lockout after N failures
// ---------------------------------------------------------------------------
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const user = users.get(username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// ---------------------------------------------------------------------------
// GET /notes
// ---------------------------------------------------------------------------
app.get('/notes', requireAuth, (req, res) => {
  const userNotes = [...notes.values()]
    .filter(n => n.userId === req.userId)
    .sort((a, b) => b.id - a.id);
  res.json(userNotes);
});

// ---------------------------------------------------------------------------
// POST /notes
// INTENTIONAL WEAKNESS: note body is stored without sanitization.
// XSS surface — a note body of <script>alert(1)</script> would execute in
// a browser that renders the raw HTML without escaping.
// Mitigation: sanitize on input server-side; escape on render client-side
// ---------------------------------------------------------------------------
app.post('/notes', requireAuth, (req, res) => {
  const { body } = req.body;
  if (!body) {
    return res.status(400).json({ error: 'body is required' });
  }

  const note = {
    id: nextNoteId++,
    userId: req.userId,
    body,
    created_at: new Date().toISOString(),
  };
  notes.set(note.id, note);
  res.status(201).json(note);
});

// ---------------------------------------------------------------------------
// DELETE /notes/:id
// INTENTIONAL WEAKNESS: ownership is NOT verified before deletion.
// Any authenticated user can delete any note by ID.
// Threat #2: Tampering — IDOR on Note DELETE (missing ownership check)
// Threat #6: Elevation of Privilege — attacker accesses another user's data
// Mitigation: check note.userId === req.userId before deleting
// ---------------------------------------------------------------------------
app.delete('/notes/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!notes.has(id)) {
    return res.status(404).json({ error: 'Note not found' });
  }
  notes.delete(id);
  res.json({ deleted: true });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Notes app running on http://localhost:${PORT}`);
});
