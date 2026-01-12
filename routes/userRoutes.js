const express = require("express");
const router = express.Router();
const passport = require('../config/passport');
const userController = require("../controllers/userController");
const { 
  authMiddleware,
  authorizeRoles,
  sessionAwareAuth 
} = require("../middlewares/authMiddleware.js");
const { 
  validateRegister,
  validateLogin,
  validateUpdateUser,
  validateChangePassword,
  validateForgotPassword,
  validateResetPassword,
  validateUserIdParam,
  validateChangeUserRole
} = require("../middlewares/userValidation");
const {
  uploadProfileImage,
  processProfileImage,
  cleanupProfileImage
} = require('../middlewares/userMiddleware');

// Role protection middleware
const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        status: "fail",
        message: "You do not have permission to perform this action",
      });
    }
    next();
  };
};

// Session validation middleware (for routes that need session management)
const requireSession = (req, res, next) => {
  const sessionId = req.headers['x-session-id'] || req.body.sessionId;
  
  if (!sessionId) {
    return res.status(400).json({
      status: 'fail',
      message: 'Session ID required. Please include x-session-id header.'
    });
  }
  
  next();
};

// ========================
// AUTH ROUTES (Public)
// ========================

router.post("/register", validateRegister, userController.register);

router.post("/login", validateLogin, userController.login);

router.post("/logout", authMiddleware, userController.logout);

router.post("/refresh-token", userController.refreshToken);

router.post("/forgot-password", validateForgotPassword, userController.forgotPassword);

router.patch("/reset-password/:token", validateResetPassword, userController.resetPassword);

// ========================
// PROTECTED USER ROUTES
// ========================

router.get("/me", authMiddleware, userController.getMe);

router.patch("/update-profile", authMiddleware, validateUpdateUser, userController.updateProfile);

router.post("/change-password", authMiddleware, validateChangePassword, userController.changePassword);

router.delete("/deactivate", authMiddleware, userController.deactivateAccount);

// ========================
// SESSION MANAGEMENT ROUTES
// ========================

router.get("/sessions", authMiddleware, requireSession, userController.getActiveSessions);

router.delete("/sessions/:sessionId", authMiddleware, requireSession, userController.revokeSession);

router.delete("/sessions", authMiddleware, requireSession, userController.revokeAllSessions);

// ========================
// TRUSTED DEVICES ROUTES
// ========================

router.get("/trusted-devices", authMiddleware, userController.getTrustedDevices);

router.delete("/trusted-devices/:fingerprint", authMiddleware, userController.removeTrustedDevice);

// ========================
// SOCIAL AUTH ROUTES
// ========================

router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/auth/google/callback',
  passport.authenticate('google', { session: false }),
  userController.socialLoginSuccess
);

router.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

router.get('/auth/facebook/callback',
  passport.authenticate('facebook', { session: false }),
  userController.socialLoginSuccess
);

// ========================
// MODERATOR ROUTES
// ========================

router.get("/moderator/pending", authMiddleware, restrictTo("moderator", "admin"), userController.getPendingModerationItems);

router.patch("/moderator/approve/:id", authMiddleware, restrictTo("moderator", "admin"), userController.approveContent);

// ========================
// ADMIN ROUTES
// ========================

router.get("/admin/audit-logs", authMiddleware, restrictTo("admin"), userController.getAuditLogs);

router.get("/", authMiddleware, restrictTo("admin"), userController.getAllUsers);

router.get("/:id", authMiddleware, restrictTo("admin"), validateUserIdParam, userController.getUserById);

router.patch("/:id/role", authMiddleware, restrictTo("admin"), validateUserIdParam, validateChangeUserRole, userController.changeUserRole);

router.delete("/:id", authMiddleware, restrictTo("admin"), validateUserIdParam, userController.deleteUser);

router.put(
  "/:id/profile-image",
  authMiddleware,
  restrictTo("admin"),
  validateUserIdParam,
  uploadProfileImage,
  processProfileImage,
  userController.updateProfileImage
);

module.exports = router;