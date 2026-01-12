// ========================================
// server/middlewares/authMiddleware.js (COMPLETE & PRODUCTION-READY)
// ========================================
const jwt = require("jsonwebtoken");
const User = require("../models/userModels");
const { createHash } = require("crypto");
const { isTokenBlacklisted, getSession, storeSession } = require('../config/redish');

// Security configuration
const SECURITY_CONFIG = {
  TOKEN_MIN_LENGTH: 50,
  SESSION_TIMEOUT: 60 * 60 * 1000, // 1 hour
  ALLOW_NO_REDIS: process.env.NODE_ENV !== 'production', // Graceful degradation in development
  MAX_SESSION_AGE: 7 * 24 * 60 * 60 * 1000 // 7 days max session age
};

// ========================
// Token Verification
// ========================
const verifyToken = async (token, req) => {
  // Validate token presence and format
  if (!token || typeof token !== 'string') {
    throw new Error("INVALID_TOKEN_FORMAT");
  }

  if (token.length < SECURITY_CONFIG.TOKEN_MIN_LENGTH) {
    throw new Error("INVALID_TOKEN_FORMAT");
  }

  // Check Redis blacklist with graceful fallback
  try {
    const isBlacklisted = await isTokenBlacklisted(token);
    if (isBlacklisted) {
      throw new Error("REVOKED_TOKEN");
    }
  } catch (redisError) {
    // Log but continue if Redis is unavailable (fail-open for availability)
    console.warn('⚠️ Redis blacklist check failed:', redisError.message);
    // In production, you might want to be more strict here
    if (process.env.NODE_ENV === 'production' && !redisError.message.includes('ECONNREFUSED')) {
      throw new Error("AUTH_SERVICE_UNAVAILABLE");
    }
  }

  // Verify JWT token
  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET, { 
      ignoreExpiration: false,
      algorithms: ['HS256']
    });
  } catch (jwtError) {
    if (jwtError.name === 'TokenExpiredError') {
      throw new Error("TOKEN_EXPIRED");
    } else if (jwtError.name === 'JsonWebTokenError') {
      throw new Error("INVALID_TOKEN_SIGNATURE");
    } else {
      throw new Error("INVALID_TOKEN");
    }
  }

  // Verify token structure
if (!decoded.id || !decoded.role || decoded.sessionVersion === undefined) {
      throw new Error("MALFORMED_TOKEN");
  }

  // Verify client fingerprint for session hijack protection
  const clientFingerprint = createHash('sha256')
    .update((req.headers['user-agent'] || 'unknown') + (req.ip || 'unknown'))
    .digest('hex');
  
  if (decoded.fingerprint !== clientFingerprint) {
    console.warn('🔐 Client fingerprint mismatch:', {
      expected: decoded.fingerprint?.substring(0, 8),
      actual: clientFingerprint.substring(0, 8),
      ip: req.ip,
      userAgent: req.headers['user-agent']?.substring(0, 50)
    });
    throw new Error("INVALID_CLIENT_CONTEXT");
  }

  return decoded;
};

// ========================
// Token Extraction
// ========================
const extractToken = (req) => {
  // Priority: Authorization header > Cookie token
  if (req.headers.authorization) {
    const authHeader = req.headers.authorization;
    if (authHeader.startsWith('Bearer ')) {
      return authHeader.slice(7);
    }
    // Support for "Token" prefix as well
    if (authHeader.startsWith('Token ')) {
      return authHeader.slice(6);
    }
  }

  // Check for token in cookies
  if (req.cookies?.token) {
    return req.cookies.token;
  }

  // Check for token in query string (for specific use cases)
  if (req.query?.token && process.env.NODE_ENV !== 'production') {
    console.warn('⚠️ Using token in query string - not recommended for production');
    return req.query.token;
  }

  return null;
};

// ========================
// Session ID Extraction
// ========================
const extractSessionId = (decoded, req) => {
  // Priority: Token payload > Header > Body
  if (decoded.sessionId) {
    return decoded.sessionId;
  }

  if (req.headers['x-session-id']) {
    return req.headers['x-session-id'];
  }

  if (req.body?.sessionId) {
    return req.body.sessionId;
  }

  return null;
};

// ========================
// Session Validation
// ========================
const validateSession = async (userId, sessionId) => {
  if (!userId || !sessionId) {
    throw new Error("INVALID_SESSION_PARAMS");
  }

  try {
    const session = await getSession(userId, sessionId);
    
    if (!session) {
      throw new Error("SESSION_NOT_FOUND");
    }

    // Check if session is too old
    const sessionAge = Date.now() - new Date(session.createdAt).getTime();
    if (sessionAge > SECURITY_CONFIG.MAX_SESSION_AGE) {
      throw new Error("SESSION_EXPIRED");
    }

    // Update last activity (non-blocking)
    const updatedSession = {
      ...session,
      lastActive: new Date(),
      lastIP: session.lastIP || 'unknown',
      activityCount: (session.activityCount || 0) + 1
    };

    // Update session in background
    storeSession(userId, sessionId, updatedSession, 604800)
      .catch(err => console.error('❌ Session update failed:', err.message));

    return updatedSession;
  } catch (error) {
    // Handle Redis connectivity issues
    if (error.message.includes('ECONNREFUSED') || error.message.includes('Redis')) {
      if (SECURITY_CONFIG.ALLOW_NO_REDIS) {
        console.warn('⚠️ Redis unavailable, proceeding without session validation');
        return {
          sessionId,
          userId,
          lastActive: new Date(),
          createdAt: new Date()
        };
      } else {
        throw new Error("SESSION_SERVICE_UNAVAILABLE");
      }
    }
    throw error;
  }
};

// ========================
// User Validation
// ========================
const validateUser = async (userId, sessionVersion) => {
  if (!userId) {
    throw new Error("INVALID_USER_ID");
  }

  const user = await User.findOne({
    _id: userId,
    active: true
  }).select('-password -__v -refreshToken -passwordHistory');

  if (!user) {
    throw new Error("USER_INACTIVE");
  }

  // Verify session version
  if (sessionVersion !== user.sessionVersion) {
    console.warn('🔐 Session version mismatch:', {
      userId,
      tokenVersion: sessionVersion,
      userVersion: user.sessionVersion
    });
    throw new Error("SESSION_REVOKED");
  }

  return user;
};

// ========================
// Main Auth Middleware
// ========================
const authMiddleware = async (req, res, next) => {
  const startTime = Date.now();
  
  try {
    // Extract token from request
    const token = extractToken(req);
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        code: "NO_TOKEN",
        message: "Authentication token required"
      });
    }

    // Verify JWT token
    const decoded = await verifyToken(token, req);

    // Extract session ID
    const sessionId = extractSessionId(decoded, req);
    if (!sessionId) {
      throw new Error("MISSING_SESSION_ID");
    }

    // Validate session in Redis
    const session = await validateSession(decoded.id, sessionId);
    req.sessionId = sessionId;
    req.session = session;

    // Check token age against session timeout
    const tokenAge = Date.now() - (decoded.iat * 1000);
    if (tokenAge > SECURITY_CONFIG.SESSION_TIMEOUT) {
      throw new Error("SESSION_TIMEOUT");
    }

    // Validate user account
    const user = await validateUser(decoded.id, decoded.sessionVersion);

    // Attach user to request
    req.user = {
      id: user._id,
      email: user.email,
      role: user.role,
      username: user.username,
      sessionVersion: user.sessionVersion,
      lastLogin: user.lastLogin
    };

    // Log successful authentication
    const processingTime = Date.now() - startTime;
    console.log(`🔐 Auth successful: ${user.email} (${user.role}) - ${processingTime}ms`);

    next();
  } catch (error) {
    const processingTime = Date.now() - startTime;
    console.error(`🔐 Auth failed in ${processingTime}ms:`, error.message);
    handleAuthError(error, req, res);
  }
};

// ========================
// Error Handling
// ========================
const handleAuthError = (error, req, res) => {
  const errorMap = {
    // JWT Errors
    TokenExpiredError: { code: "TOKEN_EXPIRED", message: "Session expired. Please login again.", status: 401 },
    JsonWebTokenError: { code: "INVALID_TOKEN", message: "Invalid authentication token.", status: 401 },
    INVALID_TOKEN_SIGNATURE: { code: "INVALID_TOKEN", message: "Invalid token signature.", status: 401 },
    MALFORMED_TOKEN: { code: "INVALID_TOKEN", message: "Malformed authentication token.", status: 400 },
    
    // Token Errors
    INVALID_TOKEN_FORMAT: { code: "INVALID_TOKEN", message: "Invalid token format.", status: 400 },
    REVOKED_TOKEN: { code: "REVOKED_TOKEN", message: "Session has been terminated.", status: 401 },
    
    // Session Errors
    SESSION_NOT_FOUND: { code: "SESSION_NOT_FOUND", message: "Session not found. Please login again.", status: 401 },
    SESSION_EXPIRED: { code: "SESSION_EXPIRED", message: "Session expired due to inactivity.", status: 401 },
    SESSION_TIMEOUT: { code: "SESSION_TIMEOUT", message: "Session timed out. Please login again.", status: 401 },
    SESSION_REVOKED: { code: "SESSION_REVOKED", message: "Session invalidated. Please login again.", status: 401 },
    MISSING_SESSION_ID: { code: "MISSING_SESSION", message: "Session identifier required.", status: 400 },
    INVALID_SESSION_PARAMS: { code: "INVALID_SESSION", message: "Invalid session parameters.", status: 400 },
    
    // User Errors
    USER_INACTIVE: { code: "USER_INACTIVE", message: "Account deactivated or not found.", status: 403 },
    INVALID_USER_ID: { code: "INVALID_USER", message: "Invalid user identifier.", status: 400 },
    
    // Security Errors
    INVALID_CLIENT_CONTEXT: { code: "SESSION_HIJACK", message: "Suspicious activity detected.", status: 401 },
    
    // Service Errors
    SESSION_SERVICE_UNAVAILABLE: { code: "SERVICE_UNAVAILABLE", message: "Authentication service temporarily unavailable.", status: 503 },
    AUTH_SERVICE_UNAVAILABLE: { code: "SERVICE_UNAVAILABLE", message: "Authentication service error.", status: 503 }
  };

  const errorInfo = errorMap[error.name] || errorMap[error.message] || {
    code: "AUTH_ERROR",
    message: "Authentication failed",
    status: 500
  };

  // Log detailed error information
  console.error('🔐 Authentication Error:', {
    code: errorInfo.code,
    message: error.message,
    endpoint: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.headers['user-agent']?.substring(0, 100)
  });

  res.status(errorInfo.status).json({
    status: 'fail',
    code: errorInfo.code,
    message: errorInfo.message,
    // Include additional info in development
    ...(process.env.NODE_ENV === 'development' && { 
      debug: error.message,
      stack: error.stack 
    })
  });
};

// ========================
// Role Authorization
// ========================
const authorizeRoles = (...allowedRoles) => {
  const roleHierarchy = {
    admin: ['admin', 'moderator', 'user'],
    moderator: ['moderator', 'user'],
    user: ['user']
  };

  return (req, res, next) => {
    try {
      if (!req.user?.role) {
        throw new Error("MISSING_ROLE");
      }

      const userRole = req.user.role;
      const effectiveRoles = roleHierarchy[userRole] || [];
      
      // Check if user has any of the allowed roles
      const hasAccess = allowedRoles.some(role => effectiveRoles.includes(role));

      if (!hasAccess) {
        console.warn(`🚫 Access denied: ${req.user.email} (${userRole}) tried to access ${req.originalUrl}`);
        throw new Error("INSUFFICIENT_PRIVILEGES");
      }

      next();
    } catch (error) {
      res.status(403).json({
        status: 'fail',
        code: "FORBIDDEN",
        message: "Insufficient permissions to access this resource"
      });
    }
  };
};

// ========================
// Optional Session-Aware Middleware (for transition)
// ========================
const sessionAwareAuth = async (req, res, next) => {
  try {
    await authMiddleware(req, res, next);
  } catch (error) {
    // Allow requests without session ID during transition period
    if (error.message === "MISSING_SESSION_ID" && process.env.NODE_ENV !== 'production') {
      console.warn('⚠️ Client missing session ID (transition mode):', {
        endpoint: req.originalUrl,
        userAgent: req.headers['user-agent']?.substring(0, 50)
      });
      
      // Continue without session validation
      // Remove this in production!
      return next();
    }
    
    // Re-throw all other errors
    throw error;
  }
};

// ========================
// Optional: Soft Auth Middleware (for public routes that optionally use auth)
// ========================
const softAuthMiddleware = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (token) {
      // Try to authenticate but don't fail if it doesn't work
      await authMiddleware(req, res, () => {});
    }
  } catch (error) {
    // Silently ignore auth errors for soft auth
    console.log('🔐 Soft auth failed (non-critical):', error.message);
  }
  
  next();
};

module.exports = {
  authMiddleware,
  authorizeRoles,
  sessionAwareAuth,
  softAuthMiddleware,
  extractToken 
};