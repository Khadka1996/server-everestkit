const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const adsController = require('../controllers/adsController');
const {
  validateAdvertisement,
  validateAdvertisementUpdate,
  validateTracking,
  uploadAdImage,
} = require('../middlewares/adsMiddleware');
const { authMiddleware, authorizeRoles } = require('../middlewares/authMiddleware.js');

// ---- Public (used by the website to render ads) ----
const trackLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(204).end(), // silently drop excess tracking
});

router.get('/public', adsController.getPublicAds);
router.post('/track', trackLimiter, validateTracking, adsController.track);

// ---- Admin only ----
router.use(authMiddleware, authorizeRoles('admin'));

router.get('/', adsController.getAllAdvertisements);
router.get('/stats', adsController.getStats);
router.post('/upload-image', uploadAdImage, adsController.uploadImage);
router.post('/', validateAdvertisement, adsController.createAdvertisement);
router.get('/:id', adsController.getAdvertisementById);
router.put('/:id', validateAdvertisementUpdate, adsController.updateAdvertisement);
router.patch('/:id/toggle', adsController.toggleAdvertisement);
router.post('/:id/duplicate', adsController.duplicateAdvertisement);
router.post('/:id/reset-stats', adsController.resetStats);
router.delete('/:id', adsController.deleteAdvertisement);

module.exports = router;
