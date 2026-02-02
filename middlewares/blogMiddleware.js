const multer = require('multer');
const path = require('path');

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    console.log('Multer destination: Processing file', file);
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    console.log('Multer filename: Received file', file);
    if (!file || !file.originalname) {
      console.error('Multer error: file.originalname is undefined', file);
      return cb(new Error('Invalid file: originalname is missing'));
    }
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `image-${uniqueSuffix}${ext}`);
  },
});

// Multer upload configuration
const uploadBlogImage = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    console.log('Multer fileFilter: Checking file', file);
    if (!file) {
      console.error('Multer fileFilter: No file provided');
      return cb(new Error('No file provided'));
    }
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      console.error('Multer fileFilter: Invalid file type', file.mimetype);
      cb(new Error('Invalid file type: Only JPEG, PNG, or WebP allowed'));
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
}).single('image');

// Handle Multer errors
const handleUploadErrors = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error('Multer error:', err.message, err);
    return res.status(400).json({
      success: false,
      error: `File upload error: ${err.message}`,
    });
  }
  if (err) {
    console.error('Upload error:', err.message, err);
    return res.status(400).json({
      success: false,
      error: err.message,
    });
  }
  next();
};

// Validate blog data
const validateBlogData = (req, res, next) => {
  console.log('validateBlogData: Request body', req.body, 'File', req.file);
  const { title, content } = req.body;
  if (!title || !content) {
    if (req.file) {
      const fs = require('fs').promises;
      fs.unlink(path.join(__dirname, '../uploads', req.file.filename)).catch((err) =>
        console.error('Error deleting file:', err)
      );
    }
    return res.status(400).json({
      success: false,
      error: 'Title and content are required',
    });
  }
  if (!req.file) {
    return res.status(400).json({
      success: false,
      error: 'Featured image is required',
    });
  }
  next();
};

module.exports = { uploadBlogImage, handleUploadErrors, validateBlogData };