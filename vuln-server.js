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

// Vulnerability: no HTTPS enforcement, no helmet, no rate limit, no input validation
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

// Vulnerability #1: string concatenation → SQL injection
// Vulnerability #2: storing plaintext password
// Vulnerability #3: no validation, no rate-limiting, no captcha
app.post('/signup', (req, res) => {
  const { username, email, password } = req.body;

  // Vulnerability #4: showing raw DB errors to users
  const sql = `INSERT INTO users (username,email,password,created_at)
               VALUES ('${username}','${email}','${password}','${new Date().toISOString()}')`;
  db.run(sql, function(err) {
    if (err) return res.status(500).send('DB-ERR: ' + err.message); // leaks info
    // Vulnerability #5: creating an insecure session cookie (no HttpOnly, no Secure flag)
    res.cookie('session', `${this.lastID}`, { maxAge: 24*3600*1000 }); 
    // Vulnerability #6: reflected XSS via username echo
    res.send(`Welcome <b>${username}</b>! Account created. ID=${this.lastID}`);
  });
});

// Vulnerability #7: debug endpoint that leaks full DB (sensitive data)
app.get('/dump-users', (req, res) => {
  db.all("SELECT * FROM users", (e, rows) => res.json(rows));
});

app.listen(3000, () => console.log('VULN server listening on :3000'));
