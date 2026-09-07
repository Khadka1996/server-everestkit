// server/utils/securityEvents.js
const AuditLog = require('../models/auditLogModel');

// Simple email function for now
const sendSimpleEmail = async (to, subject, text) => {
  console.log(`[EMAIL] To: ${to}, Subject: ${subject}`);
  console.log(`[EMAIL CONTENT] ${text}`);
  return true;
};

// Complete Security Events Enum
const SecurityEvents = {
  // Authentication Events
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILED: 'LOGIN_FAILED',
  LOGOUT: 'LOGOUT',
  REGISTER: 'REGISTER',
  
  // Password Events
  PASSWORD_CHANGED: 'PASSWORD_CHANGED',
  PASSWORD_RESET_REQUEST: 'PASSWORD_RESET_REQUEST',
  PASSWORD_RESET_SUCCESS: 'PASSWORD_RESET_SUCCESS',
  
  // Social Auth Events
  SOCIAL_SIGNUP: 'SOCIAL_SIGNUP',
  SOCIAL_LOGIN: 'SOCIAL_LOGIN',
  SOCIAL_LINKED: 'SOCIAL_LINKED',
  
  // Profile Events
  PROFILE_UPDATED: 'PROFILE_UPDATED',
  EMAIL_VERIFIED: 'EMAIL_VERIFIED',
  ACCOUNT_DEACTIVATED: 'ACCOUNT_DEACTIVATED',
  
  // Security Events
  UNUSUAL_ACTIVITY: 'UNUSUAL_ACTIVITY',
  NEW_DEVICE_LOGIN: 'NEW_DEVICE_LOGIN',
  MULTIPLE_FAILED_LOGINS: 'MULTIPLE_FAILED_LOGINS',
  SESSION_REVOKED: 'SESSION_REVOKED',
  SUSPICIOUS_LOGIN: 'SUSPICIOUS_LOGIN',
  
  // Admin Events
  ROLE_CHANGED: 'ROLE_CHANGED',
  USER_DELETED: 'USER_DELETED',
  USER_CREATED: 'USER_CREATED',
  
  // Content Moderation Events
  COMMENT_DELETED: 'COMMENT_DELETED',
  COMMENT_EDITED: 'COMMENT_EDITED',
  CONTENT_APPROVED: 'CONTENT_APPROVED',
  CONTENT_REJECTED: 'CONTENT_REJECTED',
  MARK_SPAM: 'MARK_SPAM',
  UNMARK_SPAM: 'UNMARK_SPAM',
  BULK_DELETE_SPAM: 'BULK_DELETE_SPAM'
};

const createAuditLog = async (action, userId, metadata = {}) => {
  try {
    // Determine target model based on context
    let targetModel = 'User';
    if (metadata.blogId) targetModel = 'Blog';
    if (metadata.commentId) targetModel = 'Comment';
    
    await AuditLog.create({
      action,
      targetId: userId,
      targetModel,
      performedBy: userId,
      ipAddress: metadata.ip || 'Unknown',
      userAgent: metadata.userAgent || 'Unknown',
      metadata: {
        ...metadata,
        timestamp: new Date()
      }
    });
    console.log(`✅ Audit log created: ${action} for user ${userId}`);
  } catch (error) {
    console.error('❌ Audit log creation error:', error.message);
  }
};

const notifySecurityEvent = async (user, event, details = {}) => {
  try {
    // Create audit log first
    await createAuditLog(event, user._id, details);
    
    // Email templates for all security events
    const emailTemplates = {
      [SecurityEvents.NEW_DEVICE_LOGIN]: {
        subject: '🔐 New Device Login Alert',
        template: `Hello ${user.username},

Your account was accessed from a new device.

Security Alert:
- Time: ${new Date().toLocaleString()}
- IP: ${details.ip || 'Unknown'}
- Device: ${details.device || 'Unknown'}
- Location: ${details.location || 'Unknown'}

If this was you, you can ignore this message.
If this wasn't you, please change your password immediately.

Best regards,
The Security Team`
      },
      
      [SecurityEvents.MULTIPLE_FAILED_LOGINS]: {
        subject: '🚨 Multiple Failed Login Attempts',
        template: `Hello ${user.username},

We detected multiple failed login attempts on your account.

Security Notice:
- Time: ${new Date().toLocaleString()}
- Failed Attempts: ${details.attempts || 'Multiple'}
- IP Address: ${details.ip || 'Unknown'}

For your security, we recommend changing your password.

Best regards,
The Security Team`
      },
      
      [SecurityEvents.LOGIN_SUCCESS]: {
        subject: '✅ Successful Login',
        template: `Hello ${user.username},

A successful login was detected on your account.

Login Details:
- Time: ${new Date().toLocaleString()}
- IP: ${details.ip || 'Unknown'}
- Device: ${details.device || 'Unknown'}

If this wasn't you, please contact support immediately.

Best regards,
The Security Team`
      },
      
      [SecurityEvents.SUSPICIOUS_LOGIN]: {
        subject: '⚠️ Suspicious Login Attempt',
        template: `Hello ${user.username},

We detected a suspicious login attempt on your account.

Details:
- Time: ${new Date().toLocaleString()}
- IP: ${details.ip || 'Unknown'}
- Reason: ${details.reason || 'Unusual activity detected'}

Please verify your account security.

Best regards,
The Security Team`
      },
      
      [SecurityEvents.PASSWORD_CHANGED]: {
        subject: '🔑 Password Changed Successfully',
        template: `Hello ${user.username},

Your password was changed successfully.

Change Details:
- Time: ${new Date().toLocaleString()}
- IP: ${details.ip || 'Unknown'}

If you didn't make this change, please contact support immediately.

Best regards,
The Security Team`
      },
      
      [SecurityEvents.SESSION_REVOKED]: {
        subject: '🔒 Sessions Revoked',
        template: `Hello ${user.username},

Your sessions have been revoked for security reasons.

Action Details:
- Time: ${new Date().toLocaleString()}
- Reason: ${details.reason || 'Security update'}

You'll need to login again on your devices.

Best regards,
The Security Team`
      }
    };
    
    const template = emailTemplates[event];
    if (template && user.email) {
      try {
        // Use simple email function for now
        await sendSimpleEmail(user.email, template.subject, template.template);
        console.log(`✅ Security notification sent to ${user.email} for: ${event}`);
      } catch (emailError) {
        console.error('❌ Email sending failed:', emailError.message);
      }
    }
    
  } catch (error) {
    console.error('❌ Security notification error:', error.message);
  }
};

// Enhanced unusual activity detection
const detectUnusualActivity = (user, currentLogin) => {
  if (!user.loginHistory || user.loginHistory.length === 0) {
    return false;
  }
  
  const recentLogins = user.loginHistory
    .slice(-5)
    .filter(login => login.ip && login.location);
  
  if (recentLogins.length === 0) return false;
  
  // Check for unusual location
  const unusualLocation = !recentLogins.some(login => 
    login.location === currentLogin.location
  );
  
  // Check for unusual IP pattern
  const unusualIP = !recentLogins.some(login => 
    login.ip === currentLogin.ip
  );
  
  return unusualLocation || unusualIP;
};

module.exports = {
  SecurityEvents,
  createAuditLog,
  notifySecurityEvent,
  detectUnusualActivity
};