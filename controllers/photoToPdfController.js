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

    // Read PDF file and send as binary
    fs.readFile(pdfPath, (readErr, data) => {
      if (readErr) {
        logger.error('File read error:', readErr);
        cleanupFiles(pdfPath, ...images.map(img => img.path));
        return res.status(500).json({ 
          success: false,
          message: 'Failed to read PDF file'
        });
      }

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Length', data.length);
      res.send(data);
      
      // Cleanup files after sending
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