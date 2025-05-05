const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Replace these with secure values in a real app (e.g., from environment variables)
const JWT_SECRET = 'your_jwt_secret';
const ENCRYPTION_KEY = crypto.randomBytes(32); // Must be 32 bytes
const IV = crypto.randomBytes(16); // Must be 16 bytes

const encrypt = (payload) => {
  // 1. Create JWT
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

  // 2. Encrypt JWT
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return IV and encrypted token as a combined string (hex)
  return `${IV.toString('hex')}:${encrypted}`;
};

const decrypt = (token) => {
  // 1. Extract IV and encrypted JWT
  const [ivHex, encryptedToken] = token.split(':');
  const iv = Buffer.from(ivHex, 'hex');

  // 2. Decrypt the token
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encryptedToken, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  // 3. Verify and decode JWT
  return jwt.verify(decrypted, JWT_SECRET);
};

module.exports = {
  encrypt,
  decrypt,
};
