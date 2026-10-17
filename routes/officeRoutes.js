const fs = require('fs');
const path = require('path');
const express = require('express');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const office = require('../controllers/officeController');

const router = express.Router();
const uploadDir = path.join(__dirname, '../temp/office/uploads');

// Accept a file only if its extension is one of `exts` (browsers report
// inconsistent MIME types for Office files, so the extension is the reliable signal).
const uploadFor = (exts, label) => {
  const upload = multer({
    storage: multer.diskStorage({
      destination: (req, file, cb) => {
        fs.mkdirSync(uploadDir, { recursive: true });
        cb(null, uploadDir);
      },
      filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.originalname).toLowerCase()}`);
      },
    }),
    fileFilter: (req, file, cb) => {
      const ok = exts.includes(path.extname(file.originalname).toLowerCase());
      if (ok) return cb(null, true);
      const err = new Error(`Please upload a ${label} file (${exts.join(', ')})`);
      err.status = 400;
      cb(err);
    },
    limits: { fileSize: 50 * 1024 * 1024, files: 1 },
  }).single('file');

  return (req, res, next) => upload(req, res, (err) => {
    if (!err) return next();
    const message = err.code === 'LIMIT_FILE_SIZE' ? 'File is too large. Maximum size is 50MB.' : err.message;
    res.status(400).json({ success: false, message });
  });
};

// Conversions are heavy — cap them per IP on top of the global API limiter.
const convertLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many conversions. Please wait a few minutes and try again.' },
});

const WORD = ['.doc', '.docx', '.odt', '.rtf', '.txt'];
const EXCEL = ['.xls', '.xlsx', '.ods', '.csv'];
const POWERPOINT = ['.ppt', '.pptx', '.odp', '.pps', '.ppsx'];
const PDF = ['.pdf'];

router.get('/health', office.health);

router.post('/word-to-pdf', convertLimiter, uploadFor(WORD, 'Word'), office.wordToPdf);
router.post('/excel-to-pdf', convertLimiter, uploadFor(EXCEL, 'Excel'), office.excelToPdf);
router.post('/powerpoint-to-pdf', convertLimiter, uploadFor(POWERPOINT, 'PowerPoint'), office.powerpointToPdf);
router.post('/pdf-to-word', convertLimiter, uploadFor(PDF, 'PDF'), office.pdfToWord);
router.post('/pdf-to-excel', convertLimiter, uploadFor(PDF, 'PDF'), office.pdfToExcel);
router.post('/pdf-to-powerpoint', convertLimiter, uploadFor(PDF, 'PDF'), office.pdfToPowerpoint);

module.exports = router;
