/*
 * Node 20 LTS is the supported runtime for this server (see .nvmrc / "engines").
 *
 * If someone installs under Node >= 24, `buffer.SlowBuffer` has been removed and
 * `buffer-equal-constant-time` (a transitive dependency of jsonwebtoken) throws
 * at require time, taking the whole server down before it can listen. This
 * script applies a tiny, idempotent compatibility shim so a mismatched local
 * Node version doesn't block development. On Node 20 it is a no-op.
 */
const fs = require('fs');
const path = require('path');

const target = path.join(
  __dirname,
  '..',
  'node_modules',
  'buffer-equal-constant-time',
  'index.js'
);

try {
  if (!fs.existsSync(target)) process.exit(0);
  const original = fs.readFileSync(target, 'utf8');
  const needle = "var SlowBuffer = require('buffer').SlowBuffer;";
  const replacement =
    "var SlowBuffer = require('buffer').SlowBuffer || require('buffer').Buffer;";

  if (original.includes(replacement)) process.exit(0); // already patched
  if (!original.includes(needle)) process.exit(0); // unexpected shape, leave it

  fs.writeFileSync(target, original.replace(needle, replacement));
  console.log('[postinstall] applied SlowBuffer compat shim to buffer-equal-constant-time');
} catch (err) {
  // Never fail the install over this.
  console.warn('[postinstall] node-compat shim skipped:', err.message);
}
