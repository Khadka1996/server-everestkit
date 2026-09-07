// ========================================
// PART 4: Device Fingerprinting Utility
// server/utils/deviceFingerprint.js
// ========================================
const crypto = require('crypto');

const generateDeviceFingerprint = (req) => {
  const components = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    req.ip || req.connection.remoteAddress || ''
  ].join('|');
  
  return crypto
    .createHash('sha256')
    .update(components)
    .digest('hex');
};

const getDeviceInfo = (req) => {
  const userAgent = req.headers['user-agent'] || 'Unknown';
  
  // Simple device detection
  let deviceType = 'Desktop';
  if (/mobile/i.test(userAgent)) deviceType = 'Mobile';
  else if (/tablet/i.test(userAgent)) deviceType = 'Tablet';
  
  // Browser detection
  let browser = 'Unknown';
  if (/chrome/i.test(userAgent)) browser = 'Chrome';
  else if (/firefox/i.test(userAgent)) browser = 'Firefox';
  else if (/safari/i.test(userAgent)) browser = 'Safari';
  else if (/edge/i.test(userAgent)) browser = 'Edge';
  
  return {
    type: deviceType,
    browser,
    userAgent: userAgent.substring(0, 100),
    ip: req.ip || req.connection.remoteAddress
  };
};

const checkTrustedDevice = (user, fingerprint) => {
  if (!user.trustedDevices || user.trustedDevices.length === 0) {
    return false;
  }
  
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  
  return user.trustedDevices.some(device => 
    device.fingerprint === fingerprint &&
    device.lastUsed > thirtyDaysAgo
  );
};

const addTrustedDevice = async (user, fingerprint, req) => {
  const deviceInfo = getDeviceInfo(req);
  const MAX_TRUSTED_DEVICES = 5;
  
  // Remove existing entry for this fingerprint
  user.trustedDevices = user.trustedDevices.filter(
    d => d.fingerprint !== fingerprint
  );
  
  // Add new entry
  user.trustedDevices.push({
    fingerprint,
    name: `${deviceInfo.browser} on ${deviceInfo.type}`,
    userAgent: deviceInfo.userAgent,
    lastUsed: new Date()
  });
  
  // Keep only the most recent devices
  if (user.trustedDevices.length > MAX_TRUSTED_DEVICES) {
    user.trustedDevices.sort((a, b) => b.lastUsed - a.lastUsed);
    user.trustedDevices = user.trustedDevices.slice(0, MAX_TRUSTED_DEVICES);
  }
  
  await user.save();
};

const removeTrustedDevice = async (user, fingerprint) => {
  user.trustedDevices = user.trustedDevices.filter(
    d => d.fingerprint !== fingerprint
  );
  await user.save();
};

module.exports = {
  generateDeviceFingerprint,
  getDeviceInfo,
  checkTrustedDevice,
  addTrustedDevice,
  removeTrustedDevice
};