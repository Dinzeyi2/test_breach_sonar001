const rateLimit = require('express-rate-limit');
// ... other imports

// Rate limiting for signup to prevent brute-force attacks and abuse
const signUpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per 15 minutes per IP
  message: 'Too many accounts created from this IP, please try again after an hour',
});

// Vulnerability #1: string concatenation â†’ SQL injection
// Vulnerability #2: storing plaintext password
// Vulnerability #3: no validation, no rate-limiting, no captcha
app.post('/signup', signUpLimiter, (req, res) => {
  const { username, email, password } = req.body;