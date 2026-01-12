// ========================================
// server/models/userModels.js (CORRECTED - NO EMAIL VERIFICATION)
// ========================================
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Schema } = mongoose;

const UserSchema = new Schema(
  {
    username: {
      type: String,
      required: [true, 'Username is required'],
      unique: true,
      trim: true,
      minlength: [2, 'Username must be at least 2 characters long'],
      maxlength: [30, 'Username cannot exceed 30 characters'],
      index: true
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        'Please provide a valid email address'
      ],
      index: true
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [6, 'Password must be at least 6 characters long'],
      select: false
    },
    role: {
      type: String,
      enum: ['user', 'moderator', 'admin'],
      default: 'user',
      index: true
    },
    active: {
      type: Boolean,
      default: true,
      index: true
    },
    
    refreshToken: {
      type: String,
      select: false
    },
    sessionVersion: {
      type: Number,
      default: 0
    },
    
    // Device Trust
    trustedDevices: [{
      fingerprint: { type: String, required: true },
      name: String,
      lastUsed: Date,
      userAgent: String,
      addedAt: { type: Date, default: Date.now }
    }],
    
    // Password History
    passwordHistory: [{
      hash: String,
      changedAt: { type: Date, default: Date.now }
    }],
    
    // Compliance & Security
    passwordLastChanged: {
      type: Date,
      default: Date.now
    },
    passwordResetToken: String,
    passwordResetExpires: Date,
    
    profileImage: {
      type: String,
      default: null
    },
    bio: {
      type: String,
      maxlength: [500, 'Bio cannot exceed 500 characters'],
      default: ''
    },
    lastLogin: {
      type: Date,
      default: null
    }
    
    // ✅ REMOVED: Email verification fields - not required for login
  },
  {
    timestamps: true,
    toJSON: { 
      virtuals: true,
      transform: function(doc, ret) {
        delete ret.password;
        delete ret.refreshToken;
        delete ret.passwordHistory;
        delete ret.__v;
        return ret;
      }
    }
  }
);

// ========================
// Indexes
// ========================
UserSchema.index({ username: 'text', email: 'text' });
UserSchema.index({ 'trustedDevices.fingerprint': 1 });
UserSchema.index({ passwordResetExpires: 1 }, { expireAfterSeconds: 0 });

// ========================
// Virtuals
// ========================
UserSchema.virtual('isNewUser').get(function() {
  return Date.now() - this.createdAt < 24 * 60 * 60 * 1000; // Within 24 hours
});

UserSchema.virtual('passwordAgeDays').get(function() {
  if (!this.passwordLastChanged) return 0;
  return Math.floor((Date.now() - this.passwordLastChanged) / (1000 * 60 * 60 * 24));
});

// ========================
// Password History Methods
// ========================
UserSchema.methods.isPasswordInHistory = async function(candidatePassword) {
  const PASSWORD_HISTORY_LIMIT = 5;
  
  if (!this.passwordHistory || this.passwordHistory.length === 0) {
    return false;
  }
  
  // Check against recent passwords (last 5)
  const recentPasswords = this.passwordHistory.slice(-PASSWORD_HISTORY_LIMIT);
  
  for (const entry of recentPasswords) {
    if (await bcrypt.compare(candidatePassword, entry.hash)) {
      return true;
    }
  }
  
  return false;
};

// ========================
// Password Comparison Method (CONSTANT TIME)
// ========================
UserSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    // Input validation and constant-time comparison
    if (!candidatePassword || !this.password) {
      // Use bcrypt.compare with dummy data to maintain constant time
      const dummyHash = await bcrypt.hash('dummy', 10);
      await bcrypt.compare(candidatePassword || 'dummy', dummyHash);
      return false;
    }
    
    // Actual comparison - bcrypt.compare is timing-safe
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    // Log error but don't reveal details
    console.error('Password comparison error:', error.message);
    
    // Still maintain constant time on error
    const dummyHash = await bcrypt.hash('dummy', 10);
    await bcrypt.compare(candidatePassword || 'dummy', dummyHash);
    return false;
  }
};

// ========================
// Password Hashing Middleware
// ========================
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const PASSWORD_HISTORY_LIMIT = 5;
    
    // Store old password hash before changing
    if (!this.isNew && this.password) {
      const oldUser = await this.constructor.findById(this._id).select('+password');
      if (oldUser && oldUser.password) {
        // Check if new password is in history
        if (await this.isPasswordInHistory(this.password)) {
          const err = new Error('Password cannot be the same as your last 5 passwords');
          err.name = 'ValidationError';
          return next(err);
        }
        
        // Add old password to history
        this.passwordHistory.push({
          hash: oldUser.password,
          changedAt: new Date()
        });
        
        // Keep only last 5 passwords
        if (this.passwordHistory.length > PASSWORD_HISTORY_LIMIT) {
          this.passwordHistory.shift();
        }
      }
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(12); // Increased salt rounds for better security
    this.password = await bcrypt.hash(this.password, salt);
    this.passwordLastChanged = new Date();
    
    next();
  } catch (error) {
    next(error);
  }
});

// ========================
// Session Management Methods
// ========================
UserSchema.methods.invalidateSessions = async function() {
  this.sessionVersion += 1;
  this.refreshToken = null;
  return this.save();
};

UserSchema.methods.rotateSessionVersion = async function() {
  this.sessionVersion += 1;
  return this.save();
};

// ========================
// Password Reset Methods
// ========================
UserSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  return resetToken;
};

UserSchema.methods.clearPasswordResetToken = function() {
  this.passwordResetToken = undefined;
  this.passwordResetExpires = undefined;
  return this.save();
};

// ========================
// Device Trust Methods
// ========================
UserSchema.methods.addTrustedDevice = function(fingerprint, deviceInfo = {}) {
  const existingDevice = this.trustedDevices.find(device => 
    device.fingerprint === fingerprint
  );
  
  if (existingDevice) {
    // Update existing device
    existingDevice.lastUsed = new Date();
    if (deviceInfo.name) existingDevice.name = deviceInfo.name;
    if (deviceInfo.userAgent) existingDevice.userAgent = deviceInfo.userAgent;
  } else {
    // Add new device
    this.trustedDevices.push({
      fingerprint,
      name: deviceInfo.name || 'Unknown Device',
      userAgent: deviceInfo.userAgent || 'Unknown',
      lastUsed: new Date(),
      addedAt: new Date()
    });
    
    // Keep only last 10 devices
    if (this.trustedDevices.length > 10) {
      this.trustedDevices.sort((a, b) => new Date(b.lastUsed) - new Date(a.lastUsed));
      this.trustedDevices = this.trustedDevices.slice(0, 10);
    }
  }
  
  return this.save();
};

UserSchema.methods.removeTrustedDevice = function(fingerprint) {
  this.trustedDevices = this.trustedDevices.filter(
    device => device.fingerprint !== fingerprint
  );
  return this.save();
};

UserSchema.methods.isDeviceTrusted = function(fingerprint) {
  return this.trustedDevices.some(device => 
    device.fingerprint === fingerprint
  );
};

// ========================
// Static Methods
// ========================
UserSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase() });
};

UserSchema.statics.findByUsername = function(username) {
  return this.findOne({ username: username.toLowerCase() });
};

UserSchema.statics.findActiveUsers = function() {
  return this.find({ active: true });
};

// ========================
// Query Helpers
// ========================
UserSchema.query.byRole = function(role) {
  return this.where({ role });
};

UserSchema.query.active = function() {
  return this.where({ active: true });
};

// ========================
// Instance Methods
// ========================
UserSchema.methods.toSafeObject = function() {
  const userObject = this.toObject();
  
  // Remove sensitive fields
  delete userObject.password;
  delete userObject.refreshToken;
  delete userObject.passwordHistory;
  delete userObject.passwordResetToken;
  delete userObject.passwordResetExpires;
  delete userObject.__v;
  
  return userObject;
};

UserSchema.methods.updateLastLogin = function() {
  this.lastLogin = new Date();
  return this.save();
};

UserSchema.methods.deactivate = function() {
  this.active = false;
  this.sessionVersion += 1; // Invalidate all sessions
  this.refreshToken = null;
  return this.save();
};

UserSchema.methods.activate = function() {
  this.active = true;
  return this.save();
};

// ========================
// Export Model
// ========================
module.exports = mongoose.model('User', UserSchema);