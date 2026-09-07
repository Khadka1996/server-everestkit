// controllers/wordController.js
const fs = require('fs');
const path = require('path');
const wordService = require('../services/wordService');

exports.convertToWord = async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ 
          success: false,
          message: 'No PDF file uploaded' 
        });
      }
  
      const result = await wordService.convertToWord({
        inputPath: req.file.path,
        originalname: req.file.originalname,
        format: req.body.format || 'docx'
      });
  
      // Set proper headers
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      res.setHeader('Content-Disposition', `attachment; filename="${path.parse(req.file.originalname).name}.docx"`);
  
      // Stream the file
      const fileStream = fs.createReadStream(result);
      fileStream.pipe(res);
  
      fileStream.on('error', (err) => {
        console.error('Stream error:', err);
        res.status(500).json({
          success: false,
          message: 'Failed to send converted file'
        });
      });
  
    } catch (error) {
      console.error('Conversion error:', error);
      res.status(500).json({ 
        success: false,
        message: error.message || 'PDF to Word conversion failed',
        // Only include stack in development
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
      });
    }
  };