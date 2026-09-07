// ========================================
// server/config/redis.js (COMPLETE & CORRECTED)
// ========================================
const Redis = require('ioredis');

// Redis configuration
const redisConfig = {
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD,
  db: 0,
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    console.log(`Redis connection attempt ${times}, retrying in ${delay}ms`);
    return delay;
  },
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: false,
  reconnectOnError: (err) => {
    console.error('Redis reconnect on error:', err.message);
    return true;
  },
  connectTimeout: 10000,
  commandTimeout: 5000
};

const redis = new Redis(redisConfig);

// ========================
// Event Listeners
// ========================
redis.on('connect', () => {
  console.log('✅ Redis connected successfully');
});

redis.on('error', (err) => {
  console.error('❌ Redis connection error:', err.message);
});

redis.on('ready', () => {
  console.log('🚀 Redis is ready to accept commands');
});

redis.on('close', () => {
  console.warn('🔌 Redis connection closed');
});

redis.on('reconnecting', (time) => {
  console.log(`🔄 Redis reconnecting in ${time}ms`);
});

// ========================
// Token Blacklist Functions
// ========================
const blacklistToken = async (token, ttl = 3600) => {
  try {
    if (!token) {
      console.warn('Blacklist token called with empty token');
      return false;
    }

    const hash = require('crypto')
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
    await redis.setex(`blacklist:${hash}`, ttl, '1');
    
    console.log('✅ Token blacklisted successfully');
    return true;
  } catch (error) {
    console.error('❌ Token blacklist error:', error.message);
    return false;
  }
};

const isTokenBlacklisted = async (token) => {
  try {
    if (!token) {
      return true; // Consider empty token as blacklisted for safety
    }

    const hash = require('crypto')
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
    const result = await redis.exists(`blacklist:${hash}`);
    const isBlacklisted = result === 1;
    
    return isBlacklisted;
  } catch (error) {
    console.error('❌ Token check error:', error.message);
    // If Redis is down, assume token is not blacklisted to avoid blocking users
    return false;
  }
};

// ========================
// Session Management Functions
// ========================
const storeSession = async (userId, sessionId, sessionData, ttlSeconds = 604800) => {
  try {
    if (!userId || !sessionId) {
      throw new Error('User ID and Session ID are required');
    }

    // ✅ CONSISTENT: Use "session:" prefix everywhere
    const key = `session:${userId}:${sessionId}`;
    
    // Store session data
    await redis.setex(key, ttlSeconds, JSON.stringify(sessionData));
    
    // Also store session ID in user's session list for easy retrieval
    const userSessionsKey = `user_sessions:${userId}`;
    await redis.sadd(userSessionsKey, sessionId);
    await redis.expire(userSessionsKey, ttlSeconds);
    
    console.log(`✅ Session stored: ${sessionId.substring(0, 8)}...`);
    return true;
  } catch (error) {
    console.error('❌ Session storage failed:', error.message);
    throw error;
  }
};

const getSession = async (userId, sessionId) => {
  try {
    if (!userId || !sessionId) {
      console.warn('Get session called with missing userId or sessionId');
      return null;
    }

    const key = `session:${userId}:${sessionId}`;
    const data = await redis.get(key);
    
    if (!data) {
      console.log(`Session not found: ${sessionId.substring(0, 8)}...`);
      return null;
    }
    
    return JSON.parse(data);
  } catch (error) {
    console.error('❌ Session get error:', error.message);
    return null;
  }
};

const deleteSession = async (userId, sessionId) => {
  try {
    if (!userId || !sessionId) {
      console.warn('Delete session called with missing userId or sessionId');
      return false;
    }

    const key = `session:${userId}:${sessionId}`;
    await redis.del(key);
    
    // Remove from user sessions set
    const userSessionsKey = `user_sessions:${userId}`;
    await redis.srem(userSessionsKey, sessionId);
    
    console.log(`🗑️ Session deleted: ${sessionId.substring(0, 8)}...`);
    return true;
  } catch (error) {
    console.error('❌ Session delete error:', error.message);
    return false;
  }
};

const getAllUserSessions = async (userId) => {
  try {
    if (!userId) {
      console.warn('Get all user sessions called with missing userId');
      return [];
    }

    // Get all session IDs for user from the set
    const userSessionsKey = `user_sessions:${userId}`;
    const sessionIds = await redis.smembers(userSessionsKey);
    
    const sessions = [];
    
    // Fetch each session data
    for (const sessionId of sessionIds) {
      const key = `session:${userId}:${sessionId}`;
      const data = await redis.get(key);
      if (data) {
        try {
          sessions.push(JSON.parse(data));
        } catch (parseError) {
          console.error('Failed to parse session data:', parseError.message);
        }
      }
    }
    
    console.log(`🔍 Found ${sessions.length} sessions for user ${userId}`);
    return sessions;
  } catch (error) {
    console.error('❌ Get all sessions error:', error.message);
    return [];
  }
};

const deleteAllUserSessions = async (userId, excludeSessionId = null) => {
  try {
    if (!userId) {
      console.warn('Delete all user sessions called with missing userId');
      return false;
    }

    const userSessionsKey = `user_sessions:${userId}`;
    const sessionIds = await redis.smembers(userSessionsKey);
    
    let deletedCount = 0;
    let preservedCount = 0;
    
    for (const sessionId of sessionIds) {
      if (excludeSessionId && sessionId === excludeSessionId) {
        preservedCount++;
        continue;
      }
      
      const key = `session:${userId}:${sessionId}`;
      await redis.del(key);
      await redis.srem(userSessionsKey, sessionId);
      deletedCount++;
    }
    
    console.log(`🗑️ Deleted ${deletedCount} sessions, preserved ${preservedCount}`);
    return true;
  } catch (error) {
    console.error('❌ Delete all sessions error:', error.message);
    return false;
  }
};

const updateSessionActivity = async (userId, sessionId) => {
  try {
    if (!userId || !sessionId) {
      return false;
    }

    const session = await getSession(userId, sessionId);
    if (session) {
      session.lastActive = new Date();
      await storeSession(userId, sessionId, session, 604800);
      console.log(`🔄 Session activity updated: ${sessionId.substring(0, 8)}...`);
    }
    
    return true;
  } catch (error) {
    console.error('❌ Update session activity error:', error.message);
    return false;
  }
};

// ========================
// Utility Functions
// ========================
const checkRedisHealth = async () => {
  try {
    const result = await redis.ping();
    const isHealthy = result === 'PONG';
    
    if (isHealthy) {
      console.log('❤️ Redis health check passed');
    } else {
      console.error('💔 Redis health check failed - unexpected response');
    }
    
    return isHealthy;
  } catch (error) {
    console.error('💔 Redis health check failed:', error.message);
    return false;
  }
};

// ========================
// Graceful Shutdown
// ========================

let isShuttingDown = false;

const gracefulShutdown = async () => {
  if (isShuttingDown) {
    console.log('Shutdown already in progress...');
    return;
  }

  isShuttingDown = true;
  console.log('Closing Redis connection gracefully...');

  try {
    await redis.quit();
    console.log('Redis connection closed gracefully');
  } catch (error) {
    // This is now safe — we expect this if already closed
    console.log('Redis already closed or error during quit (this is fine)');
  } finally {
    // Force kill after 3 seconds max (prevents hanging forever)
    setTimeout(() => {
      console.error('Forced exit after timeout');
      process.exit(1);
    }, 3000);
  }
};

// Only register once
process.removeAllListeners('SIGTERM');
process.removeAllListeners('SIGINT');

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
// ========================
// Export All Functions
// ========================
module.exports = {
  // Redis client
  redis,
  
  // Token management
  blacklistToken,
  isTokenBlacklisted,
  
  // Session management
  storeSession,
  getSession,
  deleteSession,
  getAllUserSessions,
  deleteAllUserSessions,
  updateSessionActivity,
  
  // Health & utils
  checkRedisHealth,
  gracefulShutdown
};