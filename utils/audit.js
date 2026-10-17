const AuditLog = require('../models/auditLogModel');
const { logger } = require('./logger.util');

// Fire-and-forget audit entry; never lets a logging failure break the request.
const audit = (req, action, targetModel, targetId, metadata = {}) => {
  if (!req.user?.id || !targetId) return;
  AuditLog.create({
    action,
    targetModel,
    targetId,
    performedBy: req.user.id,
    metadata,
    ipAddress: req.ip || 'Unknown',
    userAgent: req.headers['user-agent'] || 'Unknown',
  }).catch((err) => logger.warn(`Audit log failed (${action}): ${err.message}`));
};

module.exports = { audit };
