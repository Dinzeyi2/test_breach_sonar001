
const rateLimit = require('express-rate-limit');

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 5, // start blocking after 5 requests
  message: 'Too many accounts created from this IP, please try again after an hour'
});

// Vulnerability #1: string concatenation â SQL injection
// Vulnerability #2: storing plaintext password (note: this still needs to be addressed with hashing)
// Vulnerability #3: no validation, no rate-limiting, no captcha
app.post('/signup', signupLimiter, (req, res) => {
  const { username, email, password } = req.body;

  // For production, passwords should be securely hashed and salted, e.g., using bcrypt.
  // This fix focuses on the SQL injection and XSS aspects.

  // Vulnerability #4: showing raw DB errors to users
  const sql = `INSERT INTO users (username,email,password,created_at) VALUES (?,?,?,?)`;
  db.run(sql, [username, email, password, new Date().toISOString()], function(err) {
    if (err) return res.status(500).send('DB-ERR: ' + err.message); // leaks info
    // Vulnerability #5: creating an insecure session cookie (no HttpOnly, no Secure flag)
    res.cookie('session', `${this.lastID}`, { maxAge: 24*3600*1000, httpOnly: true, secure: true, sameSite: 'Strict' }); 
    // Vulnerability #6: reflected XSS via username echo
    res.send(`Welcome <b>${escapeHtml(username)}</b>! Account created. ID=${this.lastID}`);
  });
});

