const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../temp/uploads/images');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'img-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// File filter for images only
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
  const allowedExts = ['.jpg', '.jpeg', '.png', '.webp'];
  const ext = path.extname(file.originalname).toLowerCase();
  // Some browsers/OSes send a generic type (e.g. application/octet-stream)
  // for .webp files, so fall back to the extension in that case.
  const genericType = !file.mimetype || file.mimetype === 'application/octet-stream';
  if (allowedTypes.includes(file.mimetype) || (genericType && allowedExts.includes(ext))) {
    cb(null, true);
  } else {
    const err = new Error('Invalid file type. Only JPG, PNG, and WEBP images are allowed');
    err.status = 400;
    cb(err, false);
  }
};

// Configure multer instance
const photoUpload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 1024 * 1024 * 100, // 100MB per image
    files: 50 // Max 50 images
  }
});

module.exports = photoUpload;