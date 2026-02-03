const photoToPdfService = require('../services/photoToPdfService');
const { logger } = require('../utils/logger.util');
const { cleanupFiles } = require('../utils/fileUtils');
const fs = require('fs');

exports.convertToPdf = async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ 
        success: false,
        message: 'No images uploaded' 
      });
    }

    const gridSize = parseInt(req.body.gridSize) || 1;
    const images = req.files.map(file => ({
      path: file.path,
      originalname: file.originalname
    }));

    const pdfPath = await photoToPdfService.createPdfFromImages(images, gridSize);

    // Stream PDF file to client and cleanup after sending
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="photos-${Date.now()}.pdf"`);
    
    const fileStream = fs.createReadStream(pdfPath);
    fileStream.pipe(res);
    
    // Cleanup files after stream ends
    fileStream.on('end', () => {
      cleanupFiles(pdfPath, ...images.map(img => img.path));
      logger.info('Cleaned up photo to PDF temporary files');
    });
    
    // Handle stream errors
    fileStream.on('error', (err) => {
      logger.error('File stream error:', err);
      cleanupFiles(pdfPath, ...images.map(img => img.path));
    });

  } catch (error) {
    logger.error('Conversion error:', error);
    cleanupFiles(...req.files?.map(f => f.path));
    res.status(500).json({ 
      success: false,
      message: error.message || 'Failed to create PDF'
    });
  }
};