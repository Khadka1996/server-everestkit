const { logger } = require('../utils/logger.util');

const errorHandler = (err, req, res, next) => {
  logger.error(`Error occurred: ${err.message}`);
  
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      success: false,
      message: 'File too large. Maximum size is 500MB'
    });
  }
  
  if (err.code === 'LIMIT_FILE_COUNT' || err.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({
      success: false,
      message: 'Too many files uploaded at once'
    });
  }

  if (err.message.includes('Invalid file type')) {
    return res.status(400).json({
      success: false,
      message: err.message.replace(/^Invalid file type\.\s*/, '') || 'Invalid file type'
    });
  }

  if (err.status && err.status < 500) {
    return res.status(err.status).json({ success: false, message: err.message });
  }

  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
};

module.exports = errorHandler;