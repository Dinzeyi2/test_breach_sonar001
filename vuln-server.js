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