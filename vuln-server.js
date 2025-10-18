// Consider adding HTTPS enforcement in a production environment
// For example, by using a reverse proxy (nginx, Apache) or a middleware like 'require-https'.

app.get('/signup', (req, res) => {
  res.send(`
    <form method="POST" action="/signup">
      <input name="username" placeholder="username" />
      <input name="email" placeholder="email" />
      <input name="password" type="password" placeholder="password" />
      <button>Sign up</button>
    </form>
  `);
});