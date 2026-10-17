// services/officeService.js
// Office <-> PDF conversions.
//   Office -> PDF : LibreOffice (headless)        — apt install libreoffice-writer libreoffice-calc libreoffice-impress
//   PDF -> Office : scripts/pdf_convert.py (Python) — Server/.venv-tools with pdf2docx pdfplumber openpyxl python-pptx pymupdf
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { logger } = require('../utils/logger.util');

const SERVER_ROOT = path.join(__dirname, '..');
const WORK_ROOT = path.join(SERVER_ROOT, 'temp/office');

const SOFFICE = process.env.LIBREOFFICE_PATH || 'soffice';
const PYTHON = process.env.PYTHON_TOOLS_PATH ||
  (fs.existsSync(path.join(SERVER_ROOT, '.venv-tools/bin/python'))
    ? path.join(SERVER_ROOT, '.venv-tools/bin/python')
    : 'python3');
const PY_SCRIPT = path.join(SERVER_ROOT, 'scripts/pdf_convert.py');

const TIMEOUT_MS = Number(process.env.OFFICE_CONVERT_TIMEOUT_MS) || 120000;
const MAX_CONCURRENT = Math.max(1, Number(process.env.OFFICE_CONVERT_CONCURRENCY) || Math.min(3, os.cpus().length));

// Conversions are CPU/memory heavy; queue them instead of running unbounded.
let running = 0;
const queue = [];
const withSlot = (fn) => new Promise((resolve, reject) => {
  const run = async () => {
    running++;
    try { resolve(await fn()); } catch (e) { reject(e); } finally {
      running--;
      if (queue.length) queue.shift()();
    }
  };
  if (running < MAX_CONCURRENT) run(); else queue.push(run);
});

const run = (cmd, args, opts = {}) => new Promise((resolve, reject) => {
  execFile(cmd, args, { timeout: TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024, ...opts }, (err, stdout, stderr) => {
    if (err) {
      if (err.code === 'ENOENT') err.userMessage = 'This converter is not installed on the server yet.';
      else if (err.killed) err.userMessage = 'The conversion took too long. Please try a smaller file.';
      err.stderr = String(stderr || '').trim();
      return reject(err);
    }
    resolve({ stdout: String(stdout || ''), stderr: String(stderr || '') });
  });
});

const makeJobDir = () => {
  fs.mkdirSync(WORK_ROOT, { recursive: true });
  return fs.mkdtempSync(path.join(WORK_ROOT, 'job-'));
};

const removeDir = (dir) => fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});

class ConversionError extends Error {
  constructor(message, status = 422) { super(message); this.status = status; }
}

/** Office file -> PDF with LibreOffice. Returns { dir, outputPath }; caller removes dir. */
const officeToPdf = (inputPath) => withSlot(async () => {
  const dir = makeJobDir();
  try {
    const src = path.join(dir, `input${path.extname(inputPath).toLowerCase()}`);
    await fs.promises.copyFile(inputPath, src);
    // A private profile per job lets several LibreOffice conversions run in parallel.
    const profile = `file://${path.join(dir, 'profile')}`;
    await run(SOFFICE, [
      `-env:UserInstallation=${profile}`,
      '--headless', '--norestore', '--nolockcheck', '--nodefault',
      '--convert-to', 'pdf', '--outdir', dir, src,
    ], { env: { ...process.env, HOME: dir } });
    const outputPath = path.join(dir, 'input.pdf');
    if (!fs.existsSync(outputPath)) throw new ConversionError('Could not convert this file. It may be damaged or password-protected.');
    return { dir, outputPath };
  } catch (err) {
    await removeDir(dir);
    throw toUserError(err, 'LibreOffice');
  }
});

/** PDF -> docx/xlsx/pptx with the Python helper. */
const pdfToOffice = (inputPath, mode, ext, options = {}) => withSlot(async () => {
  const dir = makeJobDir();
  try {
    const src = path.join(dir, 'input.pdf');
    await fs.promises.copyFile(inputPath, src);
    const outputPath = path.join(dir, `output.${ext}`);
    const { stdout } = await run(PYTHON, ['-I', PY_SCRIPT, mode, src, outputPath, JSON.stringify(options)], { cwd: dir });
    if (!fs.existsSync(outputPath)) throw new ConversionError('Could not convert this PDF.');
    let info = {};
    try { info = JSON.parse(stdout.trim().split('\n').pop()); } catch {}
    return { dir, outputPath, info };
  } catch (err) {
    await removeDir(dir);
    throw toUserError(err, 'Python converter');
  }
});

function toUserError(err, tool) {
  if (err instanceof ConversionError) return err;
  logger.error(`${tool} conversion failed: ${err.message}${err.stderr ? ` | ${err.stderr.slice(-500)}` : ''}`);
  if (err.userMessage) return new ConversionError(err.userMessage, err.code === 'ENOENT' ? 503 : 422);
  // The Python helper prints a friendly message as its last stderr line.
  const last = (err.stderr || '').split('\n').filter(Boolean).pop();
  if (last && /password/i.test(last)) return new ConversionError(last);
  return new ConversionError('Could not convert this file. It may be damaged, password-protected or unsupported.');
}

/** Which converters are installed — used by GET /api/convert/health. */
const checkAvailability = async () => {
  const probe = (cmd, args) => run(cmd, args, { timeout: 20000 }).then(() => true).catch(() => false);
  const [libreoffice, python] = await Promise.all([
    probe(SOFFICE, ['--version']),
    probe(PYTHON, ['-I', '-c', 'import pdf2docx, pdfplumber, openpyxl, pptx, pymupdf']),
  ]);
  return { libreoffice, python };
};

module.exports = { officeToPdf, pdfToOffice, removeDir, checkAvailability, ConversionError };
