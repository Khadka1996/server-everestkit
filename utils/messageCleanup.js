const cron = require('node-cron');
const { ChatMessage } = require('../models/chatModel');
const fs = require('fs');
const path = require('path');

const cleanupOldMessages = async () => {
  try {
    // This is redundant with MongoDB TTL but provides logging
    const cutoffDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const result = await ChatMessage.deleteMany({ createdAt: { $lt: cutoffDate } });
    console.log(`Cleanup: Deleted ${result.deletedCount} messages older than 7 days`);
  } catch (error) {
    console.error('Cleanup error:', error);
  }
};

const cleanupTempFiles = async () => {
  try {
    const tempDirs = [
      path.join(__dirname, '../temp/processing'),
      path.join(__dirname, '../temp/uploads'),
      path.join(__dirname, '../temp/jpg_output'),
      path.join(__dirname, '../temp/converted')
    ];

    const cutoffTime = Date.now() - (24 * 60 * 60 * 1000); // 24 hours
    let deletedCount = 0;

    for (const dir of tempDirs) {
      if (!fs.existsSync(dir)) continue;

      try {
        const files = fs.readdirSync(dir);
        for (const file of files) {
          const filePath = path.join(dir, file);
          const stats = fs.statSync(filePath);
          
          // Delete if file is older than 24 hours
          if (stats.mtimeMs < cutoffTime) {
            if (stats.isDirectory()) {
              fs.rmSync(filePath, { recursive: true, force: true });
            } else {
              fs.unlinkSync(filePath);
            }
            deletedCount++;
          }
        }
      } catch (err) {
        console.error(`Error cleaning directory ${dir}:`, err.message);
      }
    }

    if (deletedCount > 0) {
      console.log(`Cleanup: Deleted ${deletedCount} old temporary files (24+ hours)`);
    }
  } catch (error) {
    console.error('Temp file cleanup error:', error);
  }
};

const scheduleCleanup = () => {
  // Run message cleanup daily at midnight
  cron.schedule('0 0 * * *', cleanupOldMessages);
  console.log('Scheduled message cleanup job');
  
  // Run temp file cleanup every 6 hours
  cron.schedule('0 */6 * * *', cleanupTempFiles);
  console.log('Scheduled temp file cleanup job (every 6 hours)');
};

module.exports = {
  cleanupOldMessages,
  cleanupTempFiles,
  scheduleCleanup
};