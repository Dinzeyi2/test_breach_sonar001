
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