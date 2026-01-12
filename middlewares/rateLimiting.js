// ========================================
// server/middlewares/rateLimiting.js
// ========================================
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const { redis } = require('../config/redish');

const createRateLimiter = (options) => {
  const {
    windowMs = 15 * 60 * 1000,
    max = 100,
    prefix = 'rl',
    skipSuccessfulRequests = false
  } = options;

  return rateLimit({
    store: new RedisStore({
      client: redis,
      prefix: `${prefix}:`
    }),
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests,
    handler: (req, res) => {
      console.warn(`Rate limit exceeded for ${req.ip} on ${prefix}`);
      res.status(429).json({
        status: 'fail',
        code: 'RATE_LIMITED',
        message: 'Too many requests, please try again later',
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
  });
};

const authLimiters = {
  // Login attempts - 5 per 15 minutes
  login: createRateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 5,
    prefix: 'login',
    skipSuccessfulRequests: true
  }),
  
  // Registration - 3 per hour
  register: createRateLimiter({
    windowMs: 60 * 60 * 1000,
    max: 3,
    prefix: 'register'
  }),
  
  // Password reset - 3 per hour
  passwordReset: createRateLimiter({
    windowMs: 60 * 60 * 1000,
    max: 3,
    prefix: 'pwd-reset'
  }),
  
  // General API - 100 per 15 minutes
  global: createRateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 100,
    prefix: 'global'
  }),
  
  // 2FA verification - 10 per 5 minutes
  twoFactor: createRateLimiter({
    windowMs: 5 * 60 * 1000,
    max: 10,
    prefix: '2fa'
  })
};

module.exports = authLimiters;