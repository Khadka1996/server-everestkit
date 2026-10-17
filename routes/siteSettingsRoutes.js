const express = require('express');
const router = express.Router();
const settingsController = require('../controllers/siteSettingsController');
const { authMiddleware, authorizeRoles } = require('../middlewares/authMiddleware.js');

// Public
router.get('/public', settingsController.getPublicSettings);
router.get('/ads.txt', settingsController.getAdsTxt);

// Admin only — code injection runs on every visitor's browser, so moderators
// are deliberately excluded.
router.use(authMiddleware, authorizeRoles('admin'));
router.get('/', settingsController.getSettings);
router.put('/', settingsController.updateSettings);

module.exports = router;
