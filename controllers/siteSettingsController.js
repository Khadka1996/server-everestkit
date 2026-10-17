const SiteSettings = require("../models/siteSettingsModel");
const { invalidatePublicCache } = require("./adsController");
const { audit } = require("../utils/audit");
const { logger } = require("../utils/logger.util");

const CODE_KEYS = ["head", "bodyStart", "sidebar", "footer", "customCss", "customJs"];
const AD_BOOL_KEYS = ["enabled", "showOnMobile", "hideForAdmins", "showAdLabel", "adsenseFallback", "stickyDismissible"];
const MAX_CODE = 50000;

let publicCache = { data: null, expires: 0 };
const invalidate = () => {
  publicCache = { data: null, expires: 0 };
  invalidatePublicCache();
};

const clampInt = (v, min, max, fallback) => {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
};

const serialize = (doc) => ({
  codeInjection: doc.codeInjection,
  ads: doc.ads,
  updatedAt: doc.updatedAt,
});

// GET /api/settings (admin)
exports.getSettings = async (req, res) => {
  try {
    const doc = await SiteSettings.getSingleton();
    res.status(200).json({ success: true, settings: serialize(doc) });
  } catch (error) {
    logger.error(`Get settings failed: ${error.message}`);
    res.status(500).json({ success: false, message: "Error loading settings" });
  }
};

// PUT /api/settings (admin) — body: { codeInjection?: {...}, ads?: {...} }
exports.updateSettings = async (req, res) => {
  try {
    const doc = await SiteSettings.getSingleton();
    const snapshot = () => JSON.parse(JSON.stringify({ codeInjection: doc.codeInjection, ads: doc.ads }));
    const before = snapshot();
    const changed = [];
    const { codeInjection, ads } = req.body || {};

    if (codeInjection && typeof codeInjection === "object") {
      for (const key of CODE_KEYS) {
        const block = codeInjection[key];
        if (!block || typeof block !== "object") continue;
        if (block.code !== undefined) {
          if (typeof block.code !== "string") return res.status(400).json({ success: false, message: `${key}: code must be text` });
          if (block.code.length > MAX_CODE) return res.status(400).json({ success: false, message: `${key}: code is too long (max ${MAX_CODE.toLocaleString()} characters)` });
          doc.codeInjection[key].code = block.code;
        }
        if (block.enabled !== undefined) doc.codeInjection[key].enabled = Boolean(block.enabled);
        changed.push(`codeInjection.${key}`);
      }
    }

    if (ads && typeof ads === "object") {
      for (const key of AD_BOOL_KEYS) {
        if (ads[key] !== undefined) { doc.ads[key] = Boolean(ads[key]); changed.push(`ads.${key}`); }
      }
      if (ads.popupDelaySeconds !== undefined) { doc.ads.popupDelaySeconds = clampInt(ads.popupDelaySeconds, 0, 600, 8); changed.push("ads.popupDelaySeconds"); }
      if (ads.popupFrequencyHours !== undefined) { doc.ads.popupFrequencyHours = clampInt(ads.popupFrequencyHours, 0, 720, 24); changed.push("ads.popupFrequencyHours"); }
      if (ads.excludedPaths !== undefined) {
        const list = Array.isArray(ads.excludedPaths) ? ads.excludedPaths : String(ads.excludedPaths).split(/\r?\n/);
        doc.ads.excludedPaths = list
          .map((p) => String(p).trim())
          .filter((p) => p.startsWith("/"))
          .slice(0, 100);
        changed.push("ads.excludedPaths");
      }
      if (ads.adsTxt !== undefined) {
        if (typeof ads.adsTxt !== "string" || ads.adsTxt.length > 20000) {
          return res.status(400).json({ success: false, message: "ads.txt must be text (max 20,000 characters)" });
        }
        doc.ads.adsTxt = ads.adsTxt;
        changed.push("ads.adsTxt");
      }
    }

    // Record only what actually changed (the dashboard always sends every field).
    const after = snapshot();
    changed.length = 0;
    for (const section of ["codeInjection", "ads"]) {
      for (const key of Object.keys(after[section] || {})) {
        if (JSON.stringify(after[section][key]) !== JSON.stringify(before[section]?.[key])) changed.push(`${section}.${key}`);
      }
    }

    doc.updatedBy = req.user?.id;
    doc.markModified("codeInjection");
    doc.markModified("ads");
    await doc.save();
    invalidate();

    audit(req, "SETTINGS_UPDATED", "SiteSettings", doc._id, { changed });
    logger.info(`Site settings updated by ${req.user?.email}: ${changed.join(", ") || "nothing"}`);
    res.status(200).json({ success: true, message: "Settings saved", settings: serialize(doc) });
  } catch (error) {
    logger.error(`Update settings failed: ${error.message}`);
    res.status(500).json({ success: false, message: "Error saving settings" });
  }
};

// GET /api/settings/public — only the enabled code blocks, for the website to inject.
exports.getPublicSettings = async (req, res) => {
  try {
    if (!publicCache.data || publicCache.expires < Date.now()) {
      const doc = await SiteSettings.getSingleton();
      const codeInjection = {};
      for (const key of CODE_KEYS) {
        const block = doc.codeInjection?.[key];
        if (block?.enabled && block.code?.trim()) codeInjection[key] = block.code;
      }
      publicCache = { data: { codeInjection }, expires: Date.now() + 60 * 1000 };
    }
    res.set("Cache-Control", "public, max-age=30");
    res.status(200).json({ success: true, ...publicCache.data });
  } catch (error) {
    res.status(200).json({ success: true, codeInjection: {} });
  }
};

// GET /api/settings/ads.txt — plain text for the frontend's /ads.txt route.
exports.getAdsTxt = async (req, res) => {
  try {
    const doc = await SiteSettings.getSingleton();
    res.type("text/plain").set("Cache-Control", "public, max-age=300").send(doc.ads?.adsTxt || "");
  } catch (error) {
    res.type("text/plain").send("");
  }
};
