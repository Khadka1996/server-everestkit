const fs = require("fs");
const path = require("path");
const multer = require("multer");
const { body, validationResult } = require("express-validator");
const { AD_PLACEMENTS, AD_PAGES, AD_SIZES } = require("../models/adsModel");

const isHttpUrl = (value) => {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
};

// Images uploaded for banner ads live under /uploads/ads/
const adsUploadDir = path.join(__dirname, "../uploads/ads");

const adImageUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      fs.mkdirSync(adsUploadDir, { recursive: true });
      cb(null, adsUploadDir);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase() || ".jpg";
      cb(null, `ad-${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
    },
  }),
  fileFilter: (req, file, cb) => {
    const okType = ["image/jpeg", "image/png", "image/webp", "image/gif"].includes(file.mimetype);
    const okExt = [".jpg", ".jpeg", ".png", ".webp", ".gif"].includes(path.extname(file.originalname).toLowerCase());
    if (okType && okExt) return cb(null, true);
    const err = new Error("Only JPG, PNG, WEBP or GIF images are allowed");
    err.status = 400;
    cb(err);
  },
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
}).single("image");

exports.uploadAdImage = (req, res, next) => {
  adImageUpload(req, res, (err) => {
    if (!err) return next();
    const message = err.code === "LIMIT_FILE_SIZE" ? "Image must be 5MB or smaller" : err.message;
    res.status(400).json({ success: false, message });
  });
};

const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: errors.array()[0].msg,
      errors: errors.array(),
    });
  }
  next();
};

// `partial` = PATCH-style update where every field is optional.
const adRules = (partial) => {
  const opt = (chain) => (partial ? chain.optional() : chain);
  return [
    opt(body("name")).isString().trim().isLength({ min: 1, max: 120 }).withMessage("Ad name is required (max 120 characters)"),
    opt(body("type")).isIn(["image", "code"]).withMessage("Type must be image or code"),
    opt(body("placement")).isIn(AD_PLACEMENTS).withMessage("Invalid placement"),
    body("size").optional().isIn(AD_SIZES).withMessage("Invalid size"),
    body("renderMode").optional().isIn(["iframe", "inline"]).withMessage("Invalid render mode"),
    body("devices").optional().isIn(["all", "desktop", "mobile"]).withMessage("Invalid device target"),
    body("pages").optional().isArray().withMessage("Pages must be a list"),
    body("pages.*").optional().isIn(AD_PAGES).withMessage("Invalid page group"),
    body("weight").optional().isInt({ min: 1, max: 10 }).withMessage("Weight must be between 1 and 10").toInt(),
    body("isActive").optional().isBoolean().toBoolean(),
    body("openInNewTab").optional().isBoolean().toBoolean(),
    body("startDate").optional({ values: "null" }).isISO8601().withMessage("Invalid start date"),
    body("endDate").optional({ values: "null" }).isISO8601().withMessage("Invalid end date"),
    body("altText").optional().isString().isLength({ max: 200 }),
    body("network").optional().isString().isLength({ max: 60 }),
    body("code").optional().isString().isLength({ max: 20000 }).withMessage("Ad code is too long (max 20,000 characters)"),
    body("websiteLink")
      .optional({ values: "falsy" })
      .custom(isHttpUrl)
      .withMessage("Website link must be a full http:// or https:// URL"),
    body("imagePath")
      .optional({ values: "falsy" })
      .custom((v) => v.startsWith("/uploads/") || isHttpUrl(v))
      .withMessage("Image must be an uploaded file or an https:// URL"),
    // Cross-field rules that depend on the ad type
    body().custom((value, { req }) => {
      const b = req.body;
      if (partial && !b.type) return true;
      if (b.type === "image") {
        if (!b.imagePath) throw new Error("Please upload a banner image");
        if (!b.websiteLink) throw new Error("Please enter the link the banner should open");
      }
      if (b.type === "code" && !String(b.code || "").trim()) {
        throw new Error("Please paste the ad code from your ad network");
      }
      if (b.startDate && b.endDate && new Date(b.endDate) <= new Date(b.startDate)) {
        throw new Error("End date must be after start date");
      }
      return true;
    }),
    handleValidation,
  ];
};

exports.validateAdvertisement = adRules(false);
exports.validateAdvertisementUpdate = adRules(true);

exports.validateTracking = [
  body("impressions").optional().isArray({ max: 30 }),
  body("impressions.*").optional().isMongoId(),
  body("clicks").optional().isArray({ max: 10 }),
  body("clicks.*").optional().isMongoId(),
  handleValidation,
];
