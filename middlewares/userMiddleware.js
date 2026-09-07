const multer = require('multer');
const path = require('path');
const { promisify } = require('util');
const fs = require('fs');
const unlinkAsync = promisify(fs.unlink);
const sharp = require('sharp'); // For image processing

// Configure storage for user profile images
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, '../uploads/profiles');
    fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const userId = req.user?.id || 'unknown';
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `profile-${userId}-${uniqueSuffix}${ext}`);
  }
});

// Enhanced file filter for profile images
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
  const maxSize = 5 * 1024 * 1024; // 5MB
  
  if (!allowedTypes.includes(file.mimetype)) {
    return cb(new Error('Only JPEG, PNG, WebP, and GIF images are allowed'), false);
  }
  
  if (file.size > maxSize) {
    return cb(new Error('File size exceeds 5MB limit'), false);
  }
  
  cb(null, true);
};

// Configure multer upload
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 1 // Only one file
  }
}).single('profileImage');

// Middleware to handle profile image upload
const uploadProfileImage = (req, res, next) => {
  upload(req, res, async (err) => {
    if (err) {
      console.error('Profile image upload error:', err);
      
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          success: false,
          message: 'File size exceeds 5MB limit'
        });
      }
      
      if (err.message.includes('Only JPEG')) {
        return res.status(400).json({
          success: false,
          message: 'Only JPEG, PNG, WebP, and GIF images are allowed'
        });
      }
      
      return res.status(400).json({
        success: false,
        message: err.message || 'Failed to upload image'
      });
    }
    
    // If no file uploaded, continue without error
    if (!req.file) {
      return next();
    }
    
    next();
  });
};

// Middleware to process and optimize profile image
const processProfileImage = async (req, res, next) => {
  if (!req.file) return next();
  
  try {
    const processedFilename = `processed-${req.file.filename}`;
    const processedPath = path.join(req.file.destination, processedFilename);
    
    // Process image: resize, compress, convert to WebP for better performance
    await sharp(req.file.path)
      .resize(500, 500, { // Square 500x500
        fit: 'cover',
        position: 'center'
      })
      .jpeg({ 
        quality: 80,
        progressive: true 
      })
      .toFile(processedPath);
    
    // Delete original file
    await unlinkAsync(req.file.path);
    
    // Update file info with processed image
    req.file.filename = processedFilename;
    req.file.path = processedPath;
    req.file.mimetype = 'image/jpeg';
    
    next();
  } catch (processError) {
    console.error('Image processing error:', processError);
    
    // Clean up uploaded file if processing fails
    if (req.file) {
      try {
        await unlinkAsync(req.file.path);
      } catch (cleanupErr) {
        console.error('Cleanup error after processing failure:', cleanupErr);
      }
    }
    
    return res.status(500).json({
      success: false,
      message: 'Failed to process image'
    });
  }
};

// Middleware to clean up uploaded file if request fails
const cleanupProfileImage = async (req, res, next) => {
  const cleanupFile = async (filePath) => {
    try {
      if (fs.existsSync(filePath)) {
        await unlinkAsync(filePath);
        console.log(`Cleaned up profile image: ${filePath}`);
      }
    } catch (cleanupErr) {
      console.error('Profile image cleanup error:', cleanupErr);
    }
  };

  // Store original file path for cleanup
  const originalFile = req.file;
  
  res.on('finish', async () => {
    if (res.statusCode >= 400 && originalFile) {
      await cleanupFile(originalFile.path);
    }
  });

  // Also cleanup on request error
  req.on('error', async () => {
    if (originalFile) {
      await cleanupFile(originalFile.path);
    }
  });

  next();
};

// Helper to delete old profile image
const deleteOldProfileImage = async (imagePath) => {
  if (!imagePath) return;
  
  try {
    const fullPath = path.join(__dirname, '../uploads/profiles', path.basename(imagePath));
    
    if (fs.existsSync(fullPath)) {
      await unlinkAsync(fullPath);
      console.log(`Deleted old profile image: ${fullPath}`);
    }
  } catch (error) {
    console.error('Error deleting old profile image:', error);
  }
};

module.exports = {
  uploadProfileImage,
  processProfileImage,
  cleanupProfileImage,
  deleteOldProfileImage
};