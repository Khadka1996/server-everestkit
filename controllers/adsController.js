const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
const sharp = require("sharp");
const Advertisement = require("../models/adsModel");
const SiteSettings = require("../models/siteSettingsModel");
const { logger } = require("../utils/logger.util");
const { audit } = require("../utils/audit");

const EDITABLE_FIELDS = [
  "name", "type", "imagePath", "websiteLink", "altText", "openInNewTab",
  "network", "code", "renderMode", "placement", "size", "pages", "devices",
  "isActive", "startDate", "endDate", "weight",
];

const pick = (src) =>
  EDITABLE_FIELDS.reduce((acc, key) => {
    if (src[key] !== undefined) acc[key] = src[key] === "" && /Date$/.test(key) ? null : src[key];
    return acc;
  }, {});

// "live" | "scheduled" | "expired" | "paused"
const statusOf = (ad, now = new Date()) => {
  if (!ad.isActive) return "paused";
  if (ad.startDate && ad.startDate > now) return "scheduled";
  if (ad.endDate && ad.endDate <= now) return "expired";
  return "live";
};

const withComputed = (ad) => {
  const obj = ad.toObject ? ad.toObject() : ad;
  return {
    ...obj,
    status: statusOf(obj),
    ctr: obj.impressions ? Number(((obj.clicks / obj.impressions) * 100).toFixed(2)) : 0,
  };
};

// ---- Public feed cache (invalidated on every admin write) ----
let publicCache = { data: null, expires: 0 };
const PUBLIC_TTL_MS = 60 * 1000;
exports.invalidatePublicCache = () => { publicCache = { data: null, expires: 0 }; };
const invalidate = exports.invalidatePublicCache;

const removeUploadedImage = async (imagePath, exceptId) => {
  if (!imagePath || !imagePath.startsWith("/uploads/ads/")) return;
  const stillUsed = await Advertisement.exists({ imagePath, _id: { $ne: exceptId } });
  if (stillUsed) return;
  const file = path.join(__dirname, "..", imagePath);
  fs.promises.unlink(file).catch(() => {});
};

const badId = (res) => res.status(400).json({ success: false, message: "Invalid advertisement id" });

// ================= Admin =================

// Re-encode uploads as WebP (animated GIF/WebP stay animated) so a large
// banner doesn't slow the site down. Returns the final path and dimensions so
// the dashboard can suggest a placement.
exports.uploadImage = async (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: "No image uploaded" });
  const input = req.file.path;
  const originalBytes = req.file.size;
  try {
    const meta = await sharp(input, { animated: true }).metadata();
    const animated = (meta.pages || 1) > 1;
    const width = meta.width;
    const height = meta.pageHeight || meta.height;
    const maxWidth = animated ? 960 : 1600;
    const outName = `${path.parse(req.file.filename).name}.webp`;
    const output = path.join(path.dirname(input), outName);

    await sharp(input, { animated })
      .resize({ width: maxWidth, withoutEnlargement: true })
      .webp(animated ? { quality: 60, effort: 2, loop: 0 } : { quality: 82 }) // loop: 0 = repeat forever
      .toFile(output);

    const { size: finalBytes } = await fs.promises.stat(output);
    if (output !== input) fs.promises.unlink(input).catch(() => {});
    const scale = width > maxWidth ? maxWidth / width : 1;
    res.status(201).json({
      success: true,
      imagePath: `/uploads/ads/${outName}`,
      width: Math.round(width * scale),
      height: Math.round(height * scale),
      originalWidth: width,
      originalHeight: height,
      animated,
      originalBytes,
      finalBytes,
    });
  } catch (error) {
    // Unreadable by sharp (rare) — keep the original file as uploaded.
    logger.warn(`Ad image optimisation skipped: ${error.message}`);
    res.status(201).json({ success: true, imagePath: `/uploads/ads/${req.file.filename}`, originalBytes, finalBytes: originalBytes });
  }
};

exports.getAllAdvertisements = async (req, res) => {
  try {
    const { placement, type, status, search } = req.query;
    const query = {};
    if (placement) query.placement = placement;
    if (type) query.type = type;
    if (search) query.name = { $regex: String(search).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), $options: "i" };

    let ads = (await Advertisement.find(query).sort({ createdAt: -1 }).lean()).map(withComputed);
    if (status) ads = ads.filter((a) => a.status === status);

    res.status(200).json({ success: true, advertisements: ads });
  } catch (error) {
    logger.error(`Fetch ads failed: ${error.message}`);
    res.status(500).json({ success: false, message: "Error fetching advertisements" });
  }
};

exports.getStats = async (req, res) => {
  try {
    const ads = await Advertisement.find({}, "isActive startDate endDate impressions clicks placement").lean();
    const now = new Date();
    const totals = ads.reduce(
      (acc, ad) => {
        acc.impressions += ad.impressions || 0;
        acc.clicks += ad.clicks || 0;
        acc[statusOf(ad, now)] += 1;
        return acc;
      },
      { total: ads.length, live: 0, paused: 0, scheduled: 0, expired: 0, impressions: 0, clicks: 0 }
    );
    totals.ctr = totals.impressions ? Number(((totals.clicks / totals.impressions) * 100).toFixed(2)) : 0;
    res.status(200).json({ success: true, stats: totals });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error fetching ad stats" });
  }
};

exports.getAdvertisementById = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return badId(res);
  try {
    const ad = await Advertisement.findById(req.params.id);
    if (!ad) return res.status(404).json({ success: false, message: "Advertisement not found" });
    res.status(200).json({ success: true, advertisement: withComputed(ad) });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error fetching advertisement" });
  }
};

exports.createAdvertisement = async (req, res) => {
  try {
    const ad = await Advertisement.create({ ...pick(req.body), createdBy: req.user?.id });
    invalidate();
    audit(req, "AD_CREATED", "Advertisement", ad._id, { name: ad.name, type: ad.type, placement: ad.placement });
    logger.info(`Ad created: "${ad.name}" (${ad.type}/${ad.placement}) by ${req.user?.email}`);
    res.status(201).json({ success: true, message: "Advertisement created", advertisement: withComputed(ad) });
  } catch (error) {
    const status = error.name === "ValidationError" ? 400 : 500;
    res.status(status).json({ success: false, message: status === 400 ? error.message : "Error creating advertisement" });
  }
};

exports.updateAdvertisement = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return badId(res);
  try {
    const ad = await Advertisement.findById(req.params.id);
    if (!ad) return res.status(404).json({ success: false, message: "Advertisement not found" });

    const previousImage = ad.imagePath;
    ad.set(pick(req.body));

    // Re-check type-specific requirements against the merged document
    if (ad.type === "image" && (!ad.imagePath || !ad.websiteLink)) {
      return res.status(400).json({ success: false, message: "Image ads need a banner image and a link" });
    }
    if (ad.type === "code" && !String(ad.code || "").trim()) {
      return res.status(400).json({ success: false, message: "Code ads need the ad network code" });
    }
    if (ad.startDate && ad.endDate && ad.endDate <= ad.startDate) {
      return res.status(400).json({ success: false, message: "End date must be after start date" });
    }

    await ad.save();
    if (previousImage && previousImage !== ad.imagePath) await removeUploadedImage(previousImage, ad._id);
    invalidate();
    audit(req, "AD_UPDATED", "Advertisement", ad._id, { name: ad.name, fields: Object.keys(pick(req.body)) });
    res.status(200).json({ success: true, message: "Advertisement updated", advertisement: withComputed(ad) });
  } catch (error) {
    const status = error.name === "ValidationError" ? 400 : 500;
    res.status(status).json({ success: false, message: status === 400 ? error.message : "Error updating advertisement" });
  }
};

exports.toggleAdvertisement = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return badId(res);
  try {
    const ad = await Advertisement.findById(req.params.id);
    if (!ad) return res.status(404).json({ success: false, message: "Advertisement not found" });
    ad.isActive = !ad.isActive;
    await ad.save();
    invalidate();
    res.status(200).json({ success: true, message: ad.isActive ? "Ad activated" : "Ad paused", advertisement: withComputed(ad) });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error updating advertisement" });
  }
};

exports.duplicateAdvertisement = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return badId(res);
  try {
    const ad = await Advertisement.findById(req.params.id).lean();
    if (!ad) return res.status(404).json({ success: false, message: "Advertisement not found" });
    const copy = await Advertisement.create({
      ...pick(ad),
      name: `${ad.name} (copy)`.slice(0, 120),
      isActive: false,
      createdBy: req.user?.id,
    });
    invalidate();
    res.status(201).json({ success: true, message: "Advertisement duplicated (paused)", advertisement: withComputed(copy) });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error duplicating advertisement" });
  }
};

exports.resetStats = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return badId(res);
  try {
    const ad = await Advertisement.findByIdAndUpdate(req.params.id, { impressions: 0, clicks: 0 }, { new: true });
    if (!ad) return res.status(404).json({ success: false, message: "Advertisement not found" });
    res.status(200).json({ success: true, message: "Stats reset", advertisement: withComputed(ad) });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error resetting stats" });
  }
};

exports.deleteAdvertisement = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return badId(res);
  try {
    const ad = await Advertisement.findByIdAndDelete(req.params.id);
    if (!ad) return res.status(404).json({ success: false, message: "Advertisement not found" });
    await removeUploadedImage(ad.imagePath, ad._id);
    invalidate();
    audit(req, "AD_DELETED", "Advertisement", ad._id, { name: ad.name });
    logger.info(`Ad deleted: "${ad.name}" by ${req.user?.email}`);
    res.status(200).json({ success: true, message: "Advertisement deleted" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error deleting advertisement" });
  }
};

// ================= Public =================

// Everything the frontend needs to render ads, in one cached request.
exports.getPublicAds = async (req, res) => {
  try {
    if (!publicCache.data || publicCache.expires < Date.now()) {
      const now = new Date();
      const [ads, settings] = await Promise.all([
        Advertisement.find({
          isActive: true,
          $and: [
            { $or: [{ startDate: null }, { startDate: { $lte: now } }] },
            { $or: [{ endDate: null }, { endDate: { $gt: now } }] },
          ],
        })
          .select("name type imagePath websiteLink altText openInNewTab code renderMode placement size pages devices weight endDate")
          .lean(),
        SiteSettings.getSingleton(),
      ]);

      const s = settings.ads || {};
      publicCache = {
        expires: Date.now() + PUBLIC_TTL_MS,
        data: {
          settings: {
            enabled: s.enabled !== false,
            showOnMobile: s.showOnMobile !== false,
            hideForAdmins: s.hideForAdmins !== false,
            showAdLabel: s.showAdLabel !== false,
            adsenseFallback: s.adsenseFallback !== false,
            popupDelaySeconds: s.popupDelaySeconds ?? 8,
            popupFrequencyHours: s.popupFrequencyHours ?? 24,
            stickyDismissible: s.stickyDismissible !== false,
            excludedPaths: s.excludedPaths || [],
          },
          // An ad whose end date passes inside the cache window must not keep showing.
          ads: ads.map(({ endDate, ...ad }) => ({ ...ad, _expires: endDate ? new Date(endDate).getTime() : null })),
        },
      };
    }

    const nowMs = Date.now();
    const data = {
      ...publicCache.data,
      ads: publicCache.data.ads.filter((a) => !a._expires || a._expires > nowMs).map(({ _expires, ...a }) => a),
    };
    res.set("Cache-Control", "public, max-age=30");
    res.status(200).json({ success: true, ...data });
  } catch (error) {
    logger.error(`Public ads failed: ${error.message}`);
    res.status(200).json({ success: true, settings: { enabled: false }, ads: [] });
  }
};

// Batched impression/click counter: { impressions: [id...], clicks: [id...] }
exports.track = async (req, res) => {
  try {
    const count = (ids = []) =>
      [...new Set(ids)].reduce((acc, id) => acc.set(id, (acc.get(id) || 0) + 1), new Map());
    const ops = [];
    for (const [id] of count(req.body.impressions)) {
      ops.push({ updateOne: { filter: { _id: id }, update: { $inc: { impressions: 1 } } } });
    }
    for (const [id] of count(req.body.clicks)) {
      ops.push({ updateOne: { filter: { _id: id }, update: { $inc: { clicks: 1 } } } });
    }
    if (ops.length) await Advertisement.bulkWrite(ops, { ordered: false });
    res.status(204).end();
  } catch (error) {
    res.status(204).end(); // tracking must never break the page
  }
};
