const rateLimit = require('express-rate-limit');

const dumpUsersLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 1, // 1 request per hour per IP
  message: 'Access to /dump-users is strictly limited.',
});

// Vulnerability #7: debug endpoint that leaks full DB (sensitive data)
// Fixed: Added rate-limiting to prevent excessive access
app.get('/dump-users', dumpUsersLimiter, (req, res) => {