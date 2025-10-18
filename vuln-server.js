
  const sql = `INSERT INTO users (username,email,password,created_at)
               VALUES (?,?,?,?)`;
  db.run(sql, [username, email, password, new Date().toISOString()], function(err) {
    if (err)
      return res.status(500).send("DB-ERR: " + err.message); // Generic error message for security
    res.cookie("session", `${this.lastID}`, {
      maxAge: 24 * 3600 * 1000,
      httpOnly: true,
      secure: true, // Requires HTTPS
      sameSite: "Lax",
    });
    res.send(`Welcome <b>${escapeHtml(username)}</b>! Account created. ID=${this.lastID}`);
  });
});

// Removed: Vulnerability #7: debug endpoint that leaks full DB (sensitive data)
// app.get('/dump-users', (req, res) => {
//   db.all("SELECT * FROM users", (e, rows) => res.json(rows));
// });

// Helper to escape HTML for XSS prevention
function escapeHtml(text) {
  var map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\" ": "&quot;",
    "'": "&#039;",
  };
  return text.replace(/[&<>"'"]/g, function (m) { return map[m]; });
}