const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const AdmZip = require('adm-zip');
const { cleanupFiles, ensureDirectory, validatePdfFile } = require('../utils/fileUtils');

const execPromise = util.promisify(exec);

class PdfConversionService {
  constructor() {
    this.tempDir = path.join(__dirname, '../temp/jpg_output');
    ensureDirectory(this.tempDir);
  }

  /**
   * Convert a PDF file to JPG image(s) using Poppler's `pdftoppm`.
   * Returns { path, filename, type } where type is 'single' or 'zip'.
   */
  async convertPdfToJpg(pdfPath, quality = 90) {
    if (!validatePdfFile(pdfPath)) {
      throw new Error('Invalid PDF file');
    }

    const q = Math.min(100, Math.max(10, parseInt(quality, 10) || 90));

    // Isolated working directory for this conversion
    const conversionDir = path.join(this.tempDir, `conv-${Date.now()}-${Math.round(Math.random() * 1e6)}`);
    ensureDirectory(conversionDir);

    const outputPrefix = path.join(conversionDir, 'page');

    try {
      // -r 150 : 150 DPI render, good balance of quality and size
      // -jpegopt quality=<q> : JPEG quality
      const command =
        `pdftoppm -jpeg -jpegopt quality=${q} -r 150 "${pdfPath}" "${outputPrefix}"`;

      await execPromise(command, { maxBuffer: 1024 * 1024 * 64 });

      const outputFiles = fs
        .readdirSync(conversionDir)
        .filter((f) => f.toLowerCase().endsWith('.jpg'))
        .sort((a, b) => {
          const na = parseInt(a.replace(/\D/g, ''), 10) || 0;
          const nb = parseInt(b.replace(/\D/g, ''), 10) || 0;
          return na - nb;
        })
        .map((f) => path.join(conversionDir, f));

      if (outputFiles.length === 0) {
        throw new Error('Conversion produced no images');
      }

      const baseName = path.basename(pdfPath, path.extname(pdfPath));

      if (outputFiles.length === 1) {
        return {
          path: outputFiles[0],
          filename: `${baseName}.jpg`,
          type: 'single',
        };
      }

      const zip = new AdmZip();
      outputFiles.forEach((file, i) => {
        zip.addLocalFile(file, '', `page-${i + 1}.jpg`);
      });
      const zipPath = path.join(conversionDir, 'converted.zip');
      zip.writeZip(zipPath);
      cleanupFiles(...outputFiles);

      return {
        path: zipPath,
        filename: `${baseName}-converted.zip`,
        type: 'zip',
      };
    } catch (error) {
      cleanupFiles(...fs.existsSync(conversionDir)
        ? fs.readdirSync(conversionDir).map((f) => path.join(conversionDir, f))
        : []);
      throw error;
    }
  }

  async cleanupConversionFiles(filePath) {
    try {
      const dirPath = path.dirname(filePath);
      cleanupFiles(filePath);

      if (fs.existsSync(dirPath) && fs.readdirSync(dirPath).length === 0) {
        fs.rmdirSync(dirPath);
      }
    } catch (error) {
      console.error('Error cleaning up conversion files:', error);
    }
  }
}

module.exports = new PdfConversionService();
