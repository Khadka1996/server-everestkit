const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const { logger } = require('../utils/logger.util');
const { PDFDocument } = require('pdf-lib');
const archiver = require('archiver');
const execPromise = util.promisify(exec);

class PDFService {
  constructor() {
    this.tempDir = path.join(__dirname, '../temp/processing');
    this.ensureTempDir();
  }

  ensureTempDir() {
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true });
    }
  }

  async compressPDF(inputPath, level, originalName) {
    const outputFileName = `compressed_${Date.now()}_${path.basename(originalName, '.pdf')}.pdf`;
    const outputPath = path.join(this.tempDir, outputFileName);
    
    try {
      const gsCommand = this.buildGhostscriptCommand(inputPath, outputPath, level);
      logger.info(`Executing Ghostscript command for: ${originalName}`);
      
      await this.executeGhostscript(gsCommand);
      
      if (!fs.existsSync(outputPath)) {
        throw new Error('Compression failed - no output file created');
      }
      
      return outputPath;
    } catch (error) {
      this.cleanupFailedProcess(outputPath);
      throw error;
    }
  }

  buildGhostscriptCommand(inputPath, outputPath, level) {
    const presets = {
      low: {
        settings: '/prepress',
        colorRes: 300,
        grayRes: 300
      },
      medium: {
        settings: '/ebook',
        colorRes: 150,
        grayRes: 150
      },
      high: {
        settings: '/screen',
        colorRes: 72,
        grayRes: 72
      }
    };
    
    const { settings, colorRes, grayRes } = presets[level] || presets.medium;
    
    return `gs -q -dNOPAUSE -dBATCH -dSAFER \
      -sDEVICE=pdfwrite \
      -dCompatibilityLevel=1.4 \
      -dPDFSETTINGS=${settings} \
      -dColorImageResolution=${colorRes} \
      -dGrayImageResolution=${grayRes} \
      -dAutoRotatePages=/None \
      -sOutputFile="${outputPath}" \
      "${inputPath}"`;
  }

  async executeGhostscript(command) {
    try {
      const { stderr } = await execPromise(command);
      if (stderr) {
        logger.warn(`Ghostscript warnings: ${stderr}`);
      }
    } catch (error) {
      logger.error(`Ghostscript execution failed: ${error.message}`);
      throw new Error('PDF compression failed');
    }
  }

//To merge the pdf 
async mergePDFs(filePaths, outputFilename) {
  const outputPath = path.join(this.tempDir, outputFilename);
  
  try {
    // Prepare Ghostscript command
    const inputFiles = filePaths.map(f => `"${f}"`).join(' ');
    const command = `gs -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile="${outputPath}" ${inputFiles}`;
    
    logger.info(`Merging ${filePaths.length} PDFs`);
    await execPromise(command);
    
    if (!fs.existsSync(outputPath)) {
      throw new Error('Merge failed - no output file created');
    }
    
    return outputPath;
  } catch (error) {
    this.cleanupFailedProcess(outputPath);
    throw error;
  }
}
 // ================== SPLIT PDF IMPLEMENTATION ==================
 async splitPDF({ inputPath, originalname, ranges, splitMode = 'custom', outputType = 'zip' }) {
  const splitDir = path.join(this.tempDir, 'split');
  if (!fs.existsSync(splitDir)) {
    fs.mkdirSync(splitDir, { recursive: true });
  }

  try {
    // 1. Load PDF and validate
    const pdfBytes = fs.readFileSync(inputPath);
    const pdfDoc = await PDFDocument.load(pdfBytes);
    const pageCount = pdfDoc.getPageCount();

    // 2. Parse ranges (supports "1-3;5-7" format from frontend)
    const pageSets = this.parseRanges(ranges, pageCount, splitMode);
    if (pageSets.length === 0) {
      throw new Error('No valid pages specified for splitting');
    }

    // 3. Process splitting
    const result = await this.processSplit({
      pdfDoc,
      pageSets,
      outputType,
      splitDir,
      originalname
    });

    return {
      outputPath: result.outputPath,
      tempFiles: [inputPath, ...result.tempFiles]
    };

  } catch (error) {
    logger.error(`Split failed: ${error.message}`);
    throw error;
  }
}

parseRanges(rangesStr, pageCount, splitMode) {
  if (splitMode === 'all') {
    // Split every page into individual PDFs
    return Array.from({ length: pageCount }, (_, i) => [i + 1]);
  }

  const pageSets = [];
  const rangeGroups = rangesStr.split(';').filter(Boolean);

  rangeGroups.forEach(range => {
    const pages = new Set();
    const parts = range.split(',').filter(Boolean);

    parts.forEach(part => {
      if (part.includes('-')) {
        const [start, end] = part.split('-').map(Number);
        if (start > 0 && end <= pageCount && start <= end) {
          for (let i = start; i <= end; i++) pages.add(i);
        }
      } else {
        const page = Number(part);
        if (page > 0 && page <= pageCount) pages.add(page);
      }
    });

    if (pages.size > 0) {
      pageSets.push(Array.from(pages).sort((a, b) => a - b));
    }
  });

  return pageSets;
}

async processSplit({ pdfDoc, pageSets, outputType, splitDir, originalname }) {
  const baseName = path.parse(originalname).name;
  const tempFiles = [];
  const splitFiles = [];

  // Create each split document
  for (let i = 0; i < pageSets.length; i++) {
    const pages = pageSets[i];
    const newPdf = await PDFDocument.create();
    
    // Copy selected pages (0-indexed in pdf-lib)
    for (const pageNum of pages) {
      const [copiedPage] = await newPdf.copyPages(pdfDoc, [pageNum - 1]);
      newPdf.addPage(copiedPage);
    }

    // Save split PDF
    const pdfBytes = await newPdf.save();
    const fileName = `${baseName}_${pages.join('-')}.pdf`;
    const filePath = path.join(splitDir, fileName);
    fs.writeFileSync(filePath, pdfBytes);
    tempFiles.push(filePath);
    splitFiles.push(filePath);
  }

  if (outputType === 'individual') {
    return { tempFiles };
  }

  // Create ZIP archive
  const zipPath = path.join(splitDir, `${baseName}_split.zip`);
  const output = fs.createWriteStream(zipPath);
  const archive = archiver('zip', { zlib: { level: 9 } });

  return new Promise((resolve, reject) => {
    output.on('close', () => resolve({ outputPath: zipPath, tempFiles: [...tempFiles, zipPath] }));
    archive.on('error', err => reject(err));

    archive.pipe(output);
    splitFiles.forEach(file => {
      archive.file(file, { name: path.basename(file) });
    });
    archive.finalize();
  });
}

cleanupFailedProcess(outputPath) {
  try {
    if (fs.existsSync(outputPath)) {
      fs.unlinkSync(outputPath);
    }
  } catch (err) {
    logger.error(`Cleanup error: ${err.message}`);
  }
}
}

module.exports = new PDFService();