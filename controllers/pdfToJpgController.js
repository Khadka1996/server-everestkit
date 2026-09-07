const fs = require('fs');
const pdfConversionService = require('../services/pdfToJpgService');
const upload = require('../config/multer.config');
const { cleanupFiles } = require('../utils/fileUtils');

const pdfToJpgController = {
  // Handle file upload and conversion
  convert: [
    upload.single('pdf'),
    async (req, res, next) => {
      try {
        if (!req.file) {
          return res.status(400).json({ error: 'No PDF file uploaded' });
        }

        const { quality = 90 } = req.body;
        const pdfPath = req.file.path;

        // Convert PDF to JPG
        const result = await pdfConversionService.convertPdfToJpg(pdfPath, quality);

        // Set appropriate headers and send file
        res.setHeader('Content-Type', result.type === 'single' ? 'image/jpeg' : 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);

        // Stream the file and clean up afterwards
        const fileStream = fs.createReadStream(result.path);
        fileStream.pipe(res);

        fileStream.on('close', () => {
          pdfConversionService.cleanupConversionFiles(result.path);
          cleanupFiles(pdfPath);
        });

        fileStream.on('error', (err) => {
          console.error('File stream error:', err);
          pdfConversionService.cleanupConversionFiles(result.path);
          cleanupFiles(pdfPath);
          next(err);
        });

      } catch (error) {
        if (req.file) cleanupFiles(req.file.path);
        next(error);
      }
    }
  ]
};

module.exports = pdfToJpgController;