// server/models/auditLogModel.js
const mongoose = require('mongoose');
const { Schema } = mongoose;

const auditLogSchema = new Schema({
  action: {
    type: String,
    required: true,
    enum: [
      // Login events
      'LOGIN_SUCCESS',
      'LOGIN_FAILED',
      
      // Social auth events
      'SOCIAL_SIGNUP',
      'SOCIAL_LOGIN', 
      'SOCIAL_LINKED',
      
      // Account events
      'PASSWORD_CHANGED',
      'EMAIL_VERIFIED',
      'PROFILE_UPDATED',
      
      // Security events
      'UNUSUAL_ACTIVITY',
      'NEW_DEVICE_LOGIN',
      'MULTIPLE_FAILED_LOGINS',
      'SESSION_REVOKED',
      
      // Admin events
      'ROLE_CHANGED',
      'USER_DELETED',

      // Add any other actions you're using
      'LOGOUT',
      'REGISTER',
      'PASSWORD_RESET_REQUEST',
      'PASSWORD_RESET_SUCCESS',
      'ACCOUNT_DEACTIVATED',
      'COMMENT_DELETED',
      'COMMENT_EDITED',
      'CONTENT_APPROVED',
      'CONTENT_REJECTED',
      'MARK_SPAM',
      'UNMARK_SPAM',
      'BULK_DELETE_SPAM'
    ],
    index: true
  },
  targetId: {
    type: Schema.Types.ObjectId,
    required: true,
    refPath: 'targetModel'
  },
  targetModel: {
    type: String,
    required: true,
    enum: ['User', 'Comment', 'Blog', 'Moderation']
  },
  performedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  metadata: {
    type: Schema.Types.Mixed,
    default: {}
  },
  ipAddress: {
    type: String,
    default: 'Unknown'
  },
  userAgent: {
    type: String,
    default: 'Unknown'
  }
}, {
  timestamps: true
});

// Indexes for better performance
auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ performedBy: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ targetId: 1, targetModel: 1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);