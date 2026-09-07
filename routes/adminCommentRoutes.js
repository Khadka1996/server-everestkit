const express = require('express');
const adminController = require('../controllers/adminController');
const { authMiddleware, authorizeRoles } = require('../middlewares/authMiddleware.js');

const router = express.Router();

router.use(authMiddleware, authorizeRoles('admin', 'moderator'));
router.get('/reported', adminController.getReportedComments);
router.patch('/:id/spam', adminController.toggleCommentSpam);
router.delete('/spam', authorizeRoles('admin'), adminController.deleteSpamComments);
router.delete('/:id', adminController.deleteAnyComment);

module.exports = router;
