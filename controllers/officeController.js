const fs = require('fs');
const path = require('path');
const officeService = require('../services/officeService');
const { logger } = require('../utils/logger.util');

const MIME = {
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

// RFC 5987 header so non-English (e.g. Nepali) file names survive the download.
const contentDisposition = (filename) => {
  const ascii = filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
};

// multer decodes multipart file names as latin1; recover the UTF-8 name.
const originalBaseName = (file) => {
  let name = file.originalname;
  try { name = Buffer.from(name, 'latin1').toString('utf8'); } catch {}
  return path.parse(name).name.slice(0, 120) || 'document';
};

const sendAndCleanup = (res, { dir, outputPath }, filename, ext, uploadPath) => {
  const cleanup = () => {
    fs.promises.unlink(uploadPath).catch(() => {});
    officeService.removeDir(dir);
  };
  res.setHeader('Content-Type', MIME[ext]);
  res.setHeader('Content-Disposition', contentDisposition(filename));
  res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition, X-Conversion-Info');
  const stream = fs.createReadStream(outputPath);
  stream.on('error', (err) => {
    logger.error(`Stream error: ${err.message}`);
    if (!res.headersSent) res.status(500).end(); else res.destroy();
  });
  res.on('close', cleanup);
  stream.pipe(res);
};

const handler = (direction, ext, mode) => async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'Please choose a file to convert' });
  }
  const base = originalBaseName(req.file);
  const started = Date.now();
  try {
    const result = direction === 'toPdf'
      ? await officeService.officeToPdf(req.file.path)
      : await officeService.pdfToOffice(req.file.path, mode, ext);
    logger.info(`Converted ${req.file.originalname} -> ${ext} in ${Date.now() - started}ms`);
    if (result.info) res.setHeader('X-Conversion-Info', JSON.stringify(result.info));
    sendAndCleanup(res, result, `${base}.${ext}`, ext, req.file.path);
  } catch (err) {
    fs.promises.unlink(req.file.path).catch(() => {});
    res.status(err.status || 500).json({
      success: false,
      message: err.status ? err.message : 'Conversion failed. Please try again.',
    });
  }
};

exports.wordToPdf = handler('toPdf', 'pdf');
exports.excelToPdf = handler('toPdf', 'pdf');
exports.powerpointToPdf = handler('toPdf', 'pdf');
exports.pdfToWord = handler('fromPdf', 'docx', 'word');
exports.pdfToExcel = handler('fromPdf', 'xlsx', 'excel');
exports.pdfToPowerpoint = handler('fromPdf', 'pptx', 'powerpoint');

exports.health = async (req, res) => {
  const available = await officeService.checkAvailability();
  res.status(200).json({ success: true, ...available });
};
