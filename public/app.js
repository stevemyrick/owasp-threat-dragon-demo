// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let token = localStorage.getItem('token');
let currentUser = localStorage.getItem('username');

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
if (token) {
  showNotesPanel();
  loadNotes();
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
async function register() {
  const username = get('username');
  const password = get('password');
  clearMsg('auth-msg');

  try {
    const res = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) return setMsg('auth-msg', data.error, 'error');
    setMsg('auth-msg', 'Registered! You can now log in.', 'success');
  } catch {
    setMsg('auth-msg', 'Network error', 'error');
  }
}

async function login() {
  const username = get('username');
  const password = get('password');
  clearMsg('auth-msg');

  try {
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) return setMsg('auth-msg', data.error, 'error');

    token = data.token;
    currentUser = username;
    localStorage.setItem('token', token);
    localStorage.setItem('username', username);
    showNotesPanel();
    loadNotes();
  } catch {
    setMsg('auth-msg', 'Network error', 'error');
  }
}

function logout() {
  token = null;
  currentUser = null;
  localStorage.removeItem('token');
  localStorage.removeItem('username');
  document.getElementById('notes-list').innerHTML = '';
  document.getElementById('notes-panel').style.display = 'none';
  document.getElementById('auth-panel').style.display = '';
  clearMsg('auth-msg');
  clearMsg('notes-msg');
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------
async function loadNotes() {
  try {
    const res = await fetch('/notes', { headers: authHeader() });
    if (res.status === 401) return logout();
    const notes = await res.json();
    renderNotes(notes);
  } catch {
    setMsg('notes-msg', 'Failed to load notes', 'error');
  }
}

async function addNote() {
  const body = document.getElementById('note-body').value.trim();
  clearMsg('notes-msg');
  if (!body) return setMsg('notes-msg', 'Note body cannot be empty', 'error');

  try {
    const res = await fetch('/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeader() },
      body: JSON.stringify({ body }),
    });
    if (res.status === 401) return logout();
    if (!res.ok) {
      const data = await res.json();
      return setMsg('notes-msg', data.error, 'error');
    }
    document.getElementById('note-body').value = '';
    loadNotes();
  } catch {
    setMsg('notes-msg', 'Failed to add note', 'error');
  }
}

async function deleteNote(id) {
  try {
    const res = await fetch(`/notes/${id}`, {
      method: 'DELETE',
      headers: authHeader(),
    });
    if (res.status === 401) return logout();
    loadNotes();
  } catch {
    setMsg('notes-msg', 'Failed to delete note', 'error');
  }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------
function renderNotes(notes) {
  const list = document.getElementById('notes-list');
  if (notes.length === 0) {
    list.innerHTML = '<li style="color:#9ca3af;font-size:0.9rem;">No notes yet.</li>';
    return;
  }
  list.innerHTML = notes.map(n => `
    <li>
      <div class="note-body">
        <div>${escapeHtml(n.body)}</div>
        <div class="note-meta">ID: ${n.id} &middot; ${new Date(n.created_at).toLocaleString()}</div>
      </div>
      <button class="btn-danger" onclick="deleteNote(${n.id})">Delete</button>
    </li>
  `).join('');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function showNotesPanel() {
  document.getElementById('auth-panel').style.display = 'none';
  document.getElementById('notes-panel').style.display = '';
  document.getElementById('logged-in-as').textContent = currentUser ? `Logged in as: ${currentUser}` : '';
}

function authHeader() {
  return { Authorization: `Bearer ${token}` };
}

function get(id) {
  return document.getElementById(id).value.trim();
}

function clearMsg(id) {
  const el = document.getElementById(id);
  el.textContent = '';
  el.className = 'error';
}

function setMsg(id, msg, type = 'error') {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = type === 'success' ? 'success' : 'error';
}

// escapeHtml prevents stored XSS from rendering.
// NOTE: The server intentionally does NOT sanitize input — the XSS surface
// exists in the stored data. This client-side escape is added only so the demo
// app doesn't actually execute scripts in your browser during the presentation.
// In the threat model discussion, point out that relying solely on client-side
// escaping is insufficient without server-side validation.
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
