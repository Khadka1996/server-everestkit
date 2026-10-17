const express = require('express');
const admin = require('../controllers/adminOverviewController');
const { authMiddleware, authorizeRoles } = require('../middlewares/authMiddleware.js');

const router = express.Router();

router.use(authMiddleware, authorizeRoles('admin', 'moderator'));
router.get('/overview', admin.getOverview);
router.get('/notifications', admin.getNotifications);
router.get('/comments', admin.getComments);
router.get('/audit-logs', authorizeRoles('admin'), admin.getAuditLogs);

module.exports = router;
