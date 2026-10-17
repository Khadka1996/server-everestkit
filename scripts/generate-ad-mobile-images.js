// One-off: create the ~480px phone copy for ad images uploaded before
// mobile variants existed.  Usage: node scripts/generate-ad-mobile-images.js
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const sharp = require('sharp');
const Advertisement = require('../models/adsModel');

(async () => {
  await mongoose.connect(process.env.MONGO_URI);
  const ads = await Advertisement.find({ type: 'image', imagePath: /^\/uploads\/ads\//, $or: [{ imageMobilePath: '' }, { imageMobilePath: null }, { imageMobilePath: { $exists: false } }] });
  const done = new Map(); // one variant per image file, shared by every ad using it
  for (const ad of ads) {
    if (!done.has(ad.imagePath)) {
      const input = path.join(__dirname, '..', ad.imagePath);
      if (!fs.existsSync(input)) { console.log(`skip ${ad.name}: file missing`); continue; }
      const meta = await sharp(input, { animated: true }).metadata();
      const animated = (meta.pages || 1) > 1;
      if (meta.width <= 600) { done.set(ad.imagePath, ''); continue; }
      const mobileRel = ad.imagePath.replace(/(\.[a-z0-9]+)$/i, '-m.webp');
      await sharp(input, { animated })
        .resize({ width: 480, withoutEnlargement: true })
        .webp(animated ? { quality: 55, effort: 2, loop: 0 } : { quality: 80 })
        .toFile(path.join(__dirname, '..', mobileRel));
      const { size } = fs.statSync(path.join(__dirname, '..', mobileRel));
      console.log(`${ad.imagePath} -> ${mobileRel} (${Math.round(size / 1024)} KB)`);
      done.set(ad.imagePath, mobileRel);
    }
    ad.imageMobilePath = done.get(ad.imagePath);
    await ad.save();
  }
  console.log(`updated ${ads.length} ad(s)`);
  await mongoose.disconnect();
})().catch((err) => { console.error(err); process.exit(1); });
