const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const mongoSanitize = require('express-mongo-sanitize');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const { logger } = require('./utils/logger.util');
require('dotenv').config();
const { promisify } = require('util');
const unlinkAsync = promisify(fs.unlink);

// Import middlewares
const { uploadBlogImage, handleUploadErrors } = require('./middlewares/blogMiddleware');
const errorHandler = require('./middlewares/error.middleware');

const app = express();
const PORT = process.env.PORT || 5000;

// Create HTTP server
const server = http.createServer(app);
// === CORS - Strict in production ===
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  // Add your real frontend domain in production, e.g.:
  'https://everestkit.com',
  'https://www.everestkit.com'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Cookie',
    'X-Session-ID',
    'x-session-id',
    'X-Client-Fingerprint',
    'x-client-fingerprint',
    'X-User-Agent',
    'x-user-agent'
  ]
}));

app.options('*', cors());

// === Helmet - Strong security headers ===
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Adjust if using nonce or hash in future
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"], // Tighten further if using WebSockets/APIs
      frameAncestors: ["'none'"],
    },
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard: { action: 'deny' },
  xssFilter: false, // Deprecated, Helmet handles via CSP
}));

// Additional explicit headers (some overlap with Helmet, but safe)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});


// === Rate Limiting + Slow Down (Smart Throttling) ===

// First: Slow down after 100 requests in 15 minutes
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 100,          // Allow 100 fast requests
  delayMs: (hits) => (hits - 100) * 200, // Then add 200ms delay per extra request
  maxDelayMs: 5000,         // Max delay: 5 seconds
});

app.use('/api/', speedLimiter);

// Second: Hard limit after 300 requests (fallback protection)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded: ${req.ip}`);
    res.status(429).json({
      success: false,
      message: 'Too many requests. Please slow down and try again later.'
    });
  },
  skip: (req) => req.path === '/health' // Don't limit health check
});

app.use('/api/', apiLimiter);

// Optional: Stricter limit for sensitive auth routes
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 15,                  // Only 15 login/register attempts per hour
  message: {
    success: false,
    message: 'Too many attempts. Please try again in an hour.'
  }
});

app.use('/api/users/login', authLimiter);
app.use('/api/users/register', authLimiter);
app.use('/api/users/forgot-password', authLimiter);

// === Other Security Middleware ===
app.use(mongoSanitize({ replaceWith: '_' }));
app.use(cookieParser());

// Body parsing - safe limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// === MongoDB Connection ===
const dbURI = process.env.MONGO_URI;
if (!dbURI) {
  logger.error('MONGO_URI is not set in .env file');
  process.exit(1);
}

mongoose.connect(dbURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 60000,
  maxPoolSize: 50,
})
.then(() => logger.info('MongoDB connected successfully'))
.catch((err) => {
  logger.error('MongoDB connection error:', err);
  process.exit(1);
});

mongoose.connection.on('connected', () => logger.info('Mongoose connected to DB'));
mongoose.connection.on('error', err => logger.error('Mongoose connection error:', err));
mongoose.connection.on('disconnected', () => logger.warn('Mongoose disconnected'));

// === Uploads Directory & Static Serving ===
const uploadsDir = './uploads';
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  logger.info(`Created uploads directory: ${uploadsDir}`);
}

app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  maxAge: process.env.NODE_ENV === 'production' ? '30d' : '0',
  setHeaders: (res, filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    if (['.jpg', '.jpeg', '.png', '.webp', '.gif'].includes(ext)) {
      res.setHeader('Content-Type', `image/${ext.substring(1)}`);
    }
    if (process.env.NODE_ENV === 'production') {
      res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
    }
  }
}));

// File upload route
app.post('/uploads', uploadBlogImage, handleUploadErrors, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    logger.info(`File uploaded: ${req.file.filename}`);
    res.json({
      success: true,
      filePath: `/uploads/${req.file.filename}`,
      fileName: req.file.filename,
      mimetype: req.file.mimetype,
      size: req.file.size
    });
  } catch (err) {
    logger.error('Upload error:', err);
    if (req.file?.path) {
      try { await unlinkAsync(req.file.path); } catch {}
    }
    res.status(500).json({ success: false, error: 'Upload failed' });
  }
});

// Routes
app.use('/api/ads', require('./routes/adsRoutes'));
app.use('/api/blogs', require('./routes/blogRoutes'));
app.use('/api/users', require('./routes/userRoutes'));
app.use('/api/services', require('./routes/serviceRoutes'));
app.use('/api/messages', require('./routes/messageRoutes'));
app.use('/api/pdf', require('./routes/pdf.routes'));
app.use('/api/word', require('./routes/wordRoutes'));
app.use('/api/photo-to-pdf', require('./routes/photoToPdfRoutes'));
app.use('/api/pdf-to-jpg', require('./routes/pdfToJpgRoutes'));
app.use('/api/chat', require('./routes/chatRoutes'));
app.use('/api/client', require('./routes/clientsRoutes'));


// === Health Check ===
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'UP',
    timestamp: new Date().toISOString(),
    dbState: mongoose.connection.readyState,
    uptime: process.uptime(),
    env: process.env.NODE_ENV || 'development'
  });
});

// === 404 & Error Handling ===
app.use((req, res) => {
  logger.warn(`404: ${req.originalUrl} - ${req.ip}`);
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

app.use(errorHandler);

// === Server Start ===
server.listen(PORT, () => {
  console.log('\n');
  console.log(`                    ███╗   ███╗   ███╗   ██╗   ███████╗`);
  console.log(`                    ████╗ ████║   ████╗  ██║   ╚══███╔╝`);
  console.log(`                    ██╔████╔██║   ██╔██╗ ██║     ███╔╝ `);
  console.log(`                    ██║╚██╔╝██║   ██║╚██╗██║    ███╔╝  `);
  console.log(`                    ██║ ╚═╝ ██║   ██║ ╚████║   ███████╗`);
  console.log(`                    ╚═╝     ╚═╝   ╚═╝  ╚═══╝   ╚══════╝\n`);

  logger.info(`Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`Health: http://localhost:${PORT}/health`);
  logger.info('Rate limiting + throttling ACTIVE');
  logger.info('Helmet security headers ACTIVE');
  logger.info('Swagger REMOVED - API surface hidden');
  logger.info('MNZ SYSTEM FULLY OPERATIONAL — AUTHORITY ENGAGED');
});

// Graceful shutdown
process.on('unhandledRejection', (err) => {
  logger.error('Unhandled Rejection:', err);
  server.close(() => process.exit(1));
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down...');
  server.close(() => process.exit(0));
});

module.exports = app;