// ========================================
// server/controllers/userController.js (COMPLETE & CORRECTED)
// ========================================
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/userModels');
const AuditLog = require('../models/auditLogModel');
const Moderation = require('../models/moderationModel');
const { SecurityEvents, notifySecurityEvent } = require('../utils/securityEvents');
const {
  storeSession,
  blacklistToken,
  deleteSession,
  deleteAllUserSessions,
  getAllUserSessions,
  redis 
} = require('../config/redish');
const {
  generateDeviceFingerprint,
  checkTrustedDevice,
  addTrustedDevice,
  getDeviceInfo
} = require('../utils/deviceFingerprint');
const { deleteOldProfileImage } = require('../middlewares/userMiddleware');

// ========================
// Token Helpers (UPDATED)
// ========================
const signToken = (id, role, req, sessionVersion, sessionId) => {
  const fingerprint = crypto
    .createHash('sha256')
    .update((req.headers['user-agent'] || 'unknown') + req.ip)
    .digest('hex');

  return jwt.sign(
    { 
      id, 
      role, 
      fingerprint, 
      sessionVersion,
      sessionId // ✅ EMBED sessionId in token
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
  );
};

const signRefreshToken = (id, sessionVersion) => {
  return jwt.sign(
    { id, sessionVersion },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );
};

// ========================
// 1. LOGIN (COMPLETE FIXED VERSION)
// ========================
exports.login = async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { email, password } = req.body;

    console.log(`🔐 Login attempt for: ${email}`);

    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }

    // 1. Find user and validate credentials
    const user = await User.findOne({ email }).select('+password +active');
    if (!user || !user.active) {
      console.log(`❌ Invalid credentials or inactive user: ${email}`);
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid credentials'
      });
    }

    // 2. Validate password with constant-time comparison
    const isValid = await user.comparePassword(password);
    if (!isValid) {
      console.log(`❌ Failed login attempt for: ${email}`);
      
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid credentials'
      });
    }

    console.log(`✅ Credentials validated for: ${email}`);

    // 3. Device Trust Check
    const fingerprint = generateDeviceFingerprint(req);
    const isTrusted = checkTrustedDevice(user, fingerprint);

    if (!isTrusted) {
      const device = getDeviceInfo(req);
      await notifySecurityEvent(user, SecurityEvents.NEW_DEVICE_LOGIN, {
        device: `${device.browser} on ${device.os}`,
        ip: req.ip,
        location: req.headers['cf-ipcountry'] || 'Unknown'
      });
    }

    // Add device to trusted list after successful login
    await addTrustedDevice(user, fingerprint, req);

    // 4. Update login time
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });

    console.log(`📝 User record updated: ${user._id}`);

    // 5. Generate session ID first
    const sessionId = crypto.randomBytes(20).toString('hex');
    const device = getDeviceInfo(req);

    const sessionData = {
      sessionId,
      userId: user._id.toString(),
      deviceInfo: `${device.browser} on ${device.os}`,
      userAgent: device.userAgent,
      ip: req.ip,
      location: req.headers['cf-ipcountry'] || 'Unknown',
      lastActive: new Date(),
      createdAt: new Date(),
      role: user.role
    };

    console.log(`🔄 Storing session in Redis: ${sessionId}`);
    
    // 6. Store session with error handling
    try {
      await storeSession(user._id.toString(), sessionId, sessionData, 604800);
      console.log(`✅ Session stored in Redis: ${sessionId}`);
    } catch (redisError) {
      console.error('❌ Redis session storage failed:', redisError);
      // Continue without session storage - don't block login
    }

    // 7. Generate tokens WITH SESSION ID EMBEDDED
    const token = signToken(user._id, user.role, req, user.sessionVersion, sessionId);
    const refreshToken = signRefreshToken(user._id, user.sessionVersion);

    console.log(`🔑 Tokens generated for user: ${user._id}`);

    // 8. Update user with refresh token hash
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    user.refreshToken = refreshTokenHash;
    await user.save({ validateBeforeSave: false });

    console.log(`💾 User refresh token updated: ${user._id}`);

    // 9. Set secure cookies
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/'
    };

    res.cookie('token', token, { 
      ...cookieOptions, 
      maxAge: 60 * 60 * 1000 
    });
    res.cookie('refreshToken', refreshToken, { 
      ...cookieOptions, 
      maxAge: 7 * 24 * 60 * 60 * 1000 
    });

    const endTime = Date.now();
    console.log(`🎉 Login completed in ${endTime - startTime}ms for: ${email}`);

    res.status(200).json({
      status: 'success',
      message: 'Login successful',
      token: token,
      data: {
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
          lastLogin: user.lastLogin
        },
        sessionId // Send sessionId to client
      }
    });

  } catch (error) {
    console.error('💥 Login Error:', error);
    
    // Specific error handling
    if (error.name === 'MongoError' || error.name === 'MongoServerError') {
      return res.status(503).json({
        status: 'error',
        message: 'Database temporarily unavailable. Please try again.'
      });
    }
    
    if (error.code === 'ECONNREFUSED' && error.port === 6379) {
      return res.status(503).json({
        status: 'error',
        message: 'Session service unavailable. Please try again.'
      });
    }

    res.status(500).json({
      status: 'error',
      message: 'Login failed. Please try again.'
    });
  }
};

// ========================
// 2. LOGOUT (ENHANCED)
// ========================
exports.logout = async (req, res) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    const sessionId = req.headers['x-session-id'] || req.body.sessionId || (req.user ? req.sessionId : null);

    if (token) {
      try {
        await blacklistToken(token, 3600);
      } catch (redisError) {
        console.error('Redis blacklist error:', redisError);
        // Continue with logout even if Redis fails
      }
    }

    if (sessionId && req.user) {
      try {
        await deleteSession(req.user.id, sessionId);
      } catch (redisError) {
        console.error('Redis session deletion error:', redisError);
      }
    }

    res.clearCookie('token', { path: '/' });
    res.clearCookie('refreshToken', { path: '/' });

    res.status(200).json({
      status: 'success',
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ status: 'error', message: 'Logout failed' });
  }
};

// ========================
// 3. REFRESH TOKEN (ENHANCED WITH SESSION ID)
// ========================
exports.refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    const currentSessionId = req.headers['x-session-id'] || req.body.sessionId;
    
    if (!refreshToken) {
      return res.status(401).json({ 
        status: 'fail', 
        message: 'No refresh token provided' 
      });
    }

    if (!currentSessionId) {
      return res.status(400).json({
        status: 'fail',
        message: 'Session ID required for token refresh'
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Create hash for comparison
    const refreshTokenHash = crypto.createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const user = await User.findOne({
      _id: decoded.id,
      refreshToken: refreshTokenHash,
      active: true
    });

    if (!user) {
      return res.status(401).json({ 
        status: 'fail', 
        message: 'Invalid or expired session' 
      });
    }

    // Check session version
    if (decoded.sessionVersion !== user.sessionVersion) {
      return res.status(401).json({ 
        status: 'fail', 
        message: 'Session invalidated' 
      });
    }

    // Generate new tokens WITH SAME SESSION ID
    const newToken = signToken(user._id, user.role, req, user.sessionVersion, currentSessionId);
    const newRefreshToken = signRefreshToken(user._id, user.sessionVersion);
    const newRefreshTokenHash = crypto.createHash('sha256')
      .update(newRefreshToken)
      .digest('hex');

    // Update refresh token hash
    user.refreshToken = newRefreshTokenHash;
    await user.save({ validateBeforeSave: false });

    // Set new cookies
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    };

    res.cookie('token', newToken, {
      ...cookieOptions,
      maxAge: 60 * 60 * 1000 // 1 hour
    });
    
    res.cookie('refreshToken', newRefreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({ 
      status: 'success', 
      message: 'Token refreshed successfully',
      data: {
        sessionId: currentSessionId // Return same session ID
      }
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        status: 'fail', 
        message: 'Invalid refresh token' 
      });
    }
    
    res.status(500).json({ 
      status: 'error', 
      message: 'Token refresh failed' 
    });
  }
};

// ========================
// 4. SESSION MANAGEMENT
// ========================
exports.getActiveSessions = async (req, res) => {
  try {
    const sessions = await getAllUserSessions(req.user.id);
    const currentSessionId = req.sessionId;
    
    const formatted = sessions.map(s => ({
      ...s,
      current: s.sessionId === currentSessionId
    }));
    
    res.json({ 
      status: 'success', 
      data: { sessions: formatted } 
    });
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch sessions' 
    });
  }
};

exports.revokeSession = async (req, res) => {
  try {
    const { sessionId } = req.params;
    const currentSessionId = req.sessionId;
    
    // Prevent revoking current session
    if (sessionId === currentSessionId) {
      return res.status(400).json({
        status: 'fail',
        message: 'Cannot revoke current session'
      });
    }
    
    await deleteSession(req.user.id, sessionId);
    
    res.json({ 
      status: 'success', 
      message: 'Session terminated' 
    });
  } catch (error) {
    console.error('Revoke session error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to revoke session' 
    });
  }
};

exports.revokeAllSessions = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const currentSessionId = req.sessionId;
    
    user.sessionVersion += 1;
    user.refreshToken = null;
    await user.save({ validateBeforeSave: false });

    // Delete all sessions except current
    await deleteAllUserSessions(req.user.id, currentSessionId);
    
    await notifySecurityEvent(user, SecurityEvents.SESSION_REVOKED, { 
      ip: req.ip,
      preservedSession: currentSessionId 
    });

    res.json({ 
      status: 'success', 
      message: 'All other sessions revoked' 
    });
  } catch (error) {
    console.error('Revoke all sessions error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to revoke sessions' 
    });
  }
};

// ========================
// 5. TRUSTED DEVICES
// ========================
exports.getTrustedDevices = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('trustedDevices');
    res.json({
      status: 'success',
      data: { devices: user.trustedDevices || [] }
    });
  } catch (error) {
    console.error('Get trusted devices error:', error);
    res.status(500).json({ status: 'error', message: 'Failed to fetch devices' });
  }
};

exports.removeTrustedDevice = async (req, res) => {
  try {
    const { fingerprint } = req.params;
    await User.updateOne(
      { _id: req.user.id },
      { $pull: { trustedDevices: { fingerprint } } }
    );
    res.json({ status: 'success', message: 'Device removed from trusted list' });
  } catch (error) {
    console.error('Remove trusted device error:', error);
    res.status(500).json({ status: 'error', message: 'Failed to remove device' });
  }
};

// ========================
// 6. PROFILE MANAGEMENT
// ========================
exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-__v -password -passwordChangedAt');

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          role: user.role,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt
        }
      }
    });
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch profile'
    });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const { username, email } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { username, email },
      {
        new: true,
        runValidators: true
      }
    ).select('-password -__v');

    res.status(200).json({
      status: 'success',
      message: 'Profile updated successfully',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide both current and new password'
      });
    }

    const user = await User.findById(req.user.id).select('+password');

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    const isPasswordCorrect = await user.comparePassword(currentPassword);
    if (!isPasswordCorrect) {
      return res.status(401).json({
        status: 'fail',
        message: 'Your current password is incorrect'
      });
    }

    user.password = newPassword;
    user.sessionVersion += 1;
    user.refreshToken = null;
    await user.save();

    await notifySecurityEvent(user, SecurityEvents.PASSWORD_CHANGED, { ip: req.ip });

    res.status(200).json({
      status: 'success',
      message: 'Password changed successfully. All sessions have been logged out.'
    });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to change password'
    });
  }
};

// ========================
// 7. REGISTRATION
// ========================
exports.register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const newUser = await User.create({
      username,
      email,
      password,
      sessionVersion: 1
    });

    // Generate session for new user
    const sessionId = crypto.randomBytes(20).toString('hex');
    const token = signToken(newUser._id, newUser.role, req, newUser.sessionVersion, sessionId);

    // Store session in Redis
    try {
      const device = getDeviceInfo(req);
      const sessionData = {
        sessionId,
        userId: newUser._id.toString(),
        deviceInfo: `${device.browser} on ${device.os}`,
        userAgent: device.userAgent,
        ip: req.ip,
        location: req.headers['cf-ipcountry'] || 'Unknown',
        lastActive: new Date(),
        createdAt: new Date(),
        role: newUser.role
      };
      await storeSession(newUser._id.toString(), sessionId, sessionData, 604800);
    } catch (redisError) {
      console.error('Redis session storage failed during registration:', redisError);
    }

    res.status(201).json({
      status: 'success',
      message: 'Registration successful',
      token,
      data: {
        user: {
          id: newUser._id,
          username: newUser.username,
          email: newUser.email,
          role: newUser.role
        },
        sessionId
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(400).json({
      status: 'fail',
      message: err.message || 'Registration failed'
    });
  }
};

// ========================
// 8. ACCOUNT MANAGEMENT
// ========================
exports.deactivateAccount = async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { active: false });

    // Clear sessions
    try {
      await deleteAllUserSessions(req.user.id);
    } catch (redisError) {
      console.error('Redis session cleanup error during deactivation:', redisError);
    }

    res.status(200).json({
      status: 'success',
      message: 'Account deactivated successfully'
    });
  } catch (err) {
    console.error('Deactivate account error:', err);
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        status: "fail",
        message: "No user found with that email",
      });
    }

    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    const resetURL = `${req.protocol}://${req.get("host")}/reset-password/${resetToken}`;

    try {
      await require("../utils/email").sendPasswordReset(user.email, resetURL);
      res.json({ status: "success", message: "Password reset link sent to email" });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
      return res.status(500).json({
        status: "error",
        message: "Error sending email. Try again later.",
      });
    }
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ status: "error", message: "Something went wrong" });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const hashedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        status: "fail",
        message: "Token is invalid or has expired",
      });
    }

    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.sessionVersion += 1;
    user.refreshToken = null;
    await user.save();

    res.json({
      status: "success",
      message: "Password reset successful. Please login.",
    });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(400).json({ status: "fail", message: "Password reset failed" });
  }
};

// ========================
// 9. SOCIAL LOGIN
// ========================
exports.socialLoginSuccess = async (req, res) => {
  try {
    const user = req.user;

    // Generate session for social login
    const sessionId = crypto.randomBytes(20).toString('hex');
    const token = signToken(user._id, user.role, req, user.sessionVersion, sessionId);
    const refreshToken = signRefreshToken(user._id, user.sessionVersion);

    user.refreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await user.save();

    const device = getDeviceInfo(req);

    // Store session
    try {
      await storeSession(user._id, sessionId, {
        sessionId,
        userId: user._id,
        deviceInfo: `${device.browser} on ${device.os}`,
        userAgent: device.userAgent,
        ip: req.ip,
        location: req.headers['cf-ipcountry'] || 'Unknown',
        lastActive: new Date(),
        createdAt: new Date()
      }, 604800);
    } catch (redisError) {
      console.error('Redis session storage failed during social login:', redisError);
    }

    res.cookie('token', token, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === 'production', 
      sameSite: 'lax', 
      maxAge: 3600000 
    });
    res.cookie('refreshToken', refreshToken, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === 'production', 
      sameSite: 'lax', 
      maxAge: 604800000 
    });

    res.redirect(`${process.env.FRONTEND_URL}/login-success?token=${token}&sessionId=${sessionId}`);
  } catch (err) {
    console.error('Social login error:', err);
    res.redirect(`${process.env.FRONTEND_URL}/login?error=social_login_failed`);
  }
};

// ========================
// 10. ADMIN FUNCTIONS
// ========================
exports.getAllUsers = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const total = await User.countDocuments();
    
    const users = await User.find()
      .skip(skip)
      .limit(limit)
      .select('-__v -password -refreshToken');

    res.status(200).json({
      status: 'success',
      pagination: {
        total,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
        limit
      },
      data: {
        users
      }
    });
  } catch (err) {
    console.error('Get all users error:', err);
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -refreshToken');

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    console.error('Get user by ID error:', err);
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.changeUserRole = async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role: req.body.role },
      {
        new: true,
        runValidators: true
      }
    ).select('-password -refreshToken');

    res.status(200).json({
      status: 'success',
      message: 'User role updated successfully',
      data: {
        user
      }
    });
  } catch (err) {
    console.error('Change user role error:', err);
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { active: false });

    // Clear user sessions
    try {
      await deleteAllUserSessions(req.params.id);
    } catch (redisError) {
      console.error('Redis session cleanup error during user deletion:', redisError);
    }

    res.status(200).json({
      status: 'success',
      message: 'User deactivated successfully'
    });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

// ========================
// 11. AUDIT & MODERATION
// ========================
exports.getAuditLogs = async (req, res) => {
  try {
    const logs = await AuditLog.find()
      .populate('performedBy', 'username email')
      .sort('-createdAt')
      .limit(100);

    res.status(200).json({
      status: 'success',
      data: { logs }
    });
  } catch (err) {
    console.error('Get audit logs error:', err);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch audit logs'
    });
  }
};

exports.getPendingModerationItems = async (req, res) => {
  try {
    const items = await Moderation.find({ status: 'pending' });
    res.json({ status: 'success', data: { items } });
  } catch (error) {
    console.error('Get pending moderation error:', error);
    res.status(500).json({ status: 'error', message: error.message });
  }
};

exports.approveContent = async (req, res) => {
  try {
    const item = await Moderation.findById(req.params.id);
    if (!item) {
      return res.status(404).json({ status: 'fail', message: 'Item not found' });
    }

    item.status = 'approved';
    await item.save();

    res.status(200).json({ 
      status: 'success', 
      message: 'Content approved successfully',
      data: { item } 
    });
  } catch (error) {
    console.error('Approve content error:', error);
    res.status(500).json({ status: 'error', message: error.message });
  }
};

// ========================
// ADMIN DELETE USER BY ID
// ========================
exports.deleteUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user)
      return res.status(404).json({ message: "User not found" });

    if (req.user.id === user.id)
      return res.status(400).json({ message: "You cannot delete yourself" });

    await User.findByIdAndDelete(req.params.id);

    res.json({ message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// ========================================
// UPDATE PROFILE PICTURE
// ========================================
exports.updateProfileImage = async (req, res) => {
  try {
    const userId = req.params.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Permission check (admin can update all, user only self)
    if (req.user.role !== "admin" && req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "You are not allowed to update this profile"
      });
    }

    // Delete old image
    if (user.profileImage) {
      await deleteOldProfileImage(user.profileImage);
    }

    user.profileImage = `/uploads/profiles/${req.file.filename}`;
    await user.save();

    res.json({
      success: true,
      message: "Profile image updated successfully",
      profileImage: user.profileImage
    });

  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};


module.exports = exports;