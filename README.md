# Notes App — OWASP Threat Dragon Demo

A minimal Node.js notes application built as a demo subject for [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) threat modeling.

The app is intentionally simple so its architecture is easy to explain to an audience, and it contains a handful of **intentional security weaknesses** that map directly to pre-populated threats in the included Threat Dragon model file.

---

## Prerequisites

- [Node.js](https://nodejs.org/) 18 or later
- npm (comes with Node.js)

---

## Installation

```bash
npm install
```

---

## Running the App

```bash
npm start
```

Then open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Using the App

1. **Register** a username and password
2. **Log in** — a JWT is issued and stored in `localStorage`
3. **Add notes** using the text area
4. **Delete notes** with the Delete button
5. **Log out** to clear the session

Note IDs are shown beneath each note body — useful for demonstrating the IDOR weakness live.

---

## Intentional Security Weaknesses

These are deliberate design choices for demo purposes. Each maps to a threat in the Threat Dragon file.

| # | Weakness | Location in code | Threat Dragon threat |
|---|---|---|---|
| 1 | No rate limiting on `POST /login` | `server.js` line ~78 | #1 Spoofing — Brute Force |
| 2 | `DELETE /notes/:id` doesn't check note ownership | `server.js` line ~133 | #2 Tampering — IDOR |
| 3 | JWT secret is hardcoded as `'secret123'` | `server.js` line ~11 | #3 Information Disclosure — Hardcoded Secret |
| 4 | No HTTPS enforcement | deployment config | #4 Information Disclosure — No HTTPS |
| 5 | No rate limiting on any endpoint | `server.js` (all routes) | #5 Denial of Service |
| 6 | IDOR enables cross-user data access | `server.js` line ~133 | #6 Elevation of Privilege |

---

## Opening the Threat Model in Threat Dragon

### Desktop App
1. Download and install [Threat Dragon](https://github.com/OWASP/threat-dragon/releases)
2. Open the app and choose **"Open Model from File System"**
3. Navigate to `ThreatDragonModels/Threat Model v2/Threat Model v2.json` and open it
4. The diagram **"Notes App Data Flow"** will load with all 6 threats pre-populated

### Web App
1. Go to [https://www.threatdragon.com](https://www.threatdragon.com)
2. Choose **"Open Model from File System"**
3. Browse to `ThreatDragonModels/Threat Model v2/Threat Model v2.json`

Cells with open threats are highlighted in red/orange. Click any component or data flow to inspect its threats, then use the **+ Add Threat** button to add new ones live during your demo.

---

## Demo Flow Suggestion

1. Show the running app — register, log in, add a note
2. Open `threat-model/notes-app.td.json` in Threat Dragon
3. Walk the diagram: trust boundaries, actors, processes, data flows
4. Click the **Login Request** flow → show threats #1, #4, #5
5. Click the **Express API** process → show threats #2, #6 (IDOR)
6. Click the **Auth Service** process → show threat #3 (hardcoded secret)
7. Demonstrate the IDOR live: log in as a second user, `DELETE /notes/<id>` from user 1's session using DevTools
8. Add a new threat to show the full workflow
