// vuln-server.js
// PURPOSE: intentionally vulnerable example (educational only).
// Run: node vuln-server.js

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// --- In-memory DB, vulnerable SQL usage (string concatenation)
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    email TEXT,
    password TEXT,
    created_at TEXT
  )`);
});

// Vulnerability: no HTTPS enforcement, no helmet, no input validation
app.get('/signup', (req, res) => {
  res.send(`
    <form method="POST" action="/signup">
      <input name="username" placeholder="username" />
      <input name="email" placeholder="email" />
      <input name="password" placeholder="password" />
      <button>Sign up</button>
    </form>
  `);
});

// Vulnerability #1: storing plaintext password still requires bcrypt for hashing
// TODO: Implement rate-limiting middleware to prevent brute-force attacks
app.post('/signup', (req, res) => {
  const { username, email, password } = req.body;

  // Fix #1: Use parameterized queries to prevent SQL injection
  const sql = `INSERT INTO users (username,email,password,created_at)
               VALUES (?,?,?,?)`;
  db.run(sql, [username, email, password, new Date().toISOString()], function(err) {
    if (err) return res.status(500).send('An error occurred during signup.'); // Fix #2: Generic error message to prevent info leakage
    
    // Fix #3: Create a secure session cookie (HttpOnly, Secure)
    res.cookie('session', `${this.lastID}`, { maxAge: 24*3600*1000, httpOnly: true, secure: true }); 
    
    // Fix #4: Escape username to prevent reflected XSS
    const escapedUsername = (username || '').replace(/[&<>"']/g, function (match) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
      }[match];
    });
    res.send(`Welcome <b>${escapedUsername}</b>! Account created. ID=${this.lastID}`);
  });
});

// Fix #5: Removed debug endpoint that leaks full DB (sensitive data)
// In a production app, this kind of functionality should be secured with strong authentication/authorization,
// or ideally, not exist at all.

app.listen(3000, () => console.log('VULN server listening on :3000'));
