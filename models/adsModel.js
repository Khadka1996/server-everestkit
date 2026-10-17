const mongoose = require("mongoose");

// Where an ad can appear. The frontend renders <AdSlot placement="..."> at
// each of these spots; global placements are rendered once per page by the
// root layout.
const AD_PLACEMENTS = [
  "top",            // Top of page banner (tools, blog, services, home)
  "middle",         // In-content, between sections
  "bottom",         // Bottom of page banner
  "sidebar_top",    // Blog article sidebar, above "Latest Articles"
  "sidebar_bottom", // Blog article sidebar, below "Latest Articles"
  "in_article_1",   // Inside a blog article, after the 1st paragraph
  "in_article_2",   // Inside a blog article, after the 2nd paragraph
  "in_article_end", // Inside a blog article, after the last paragraph
  "in_feed",        // Between sections on the home page / between blog cards
  "article_popup",  // Blog article only: popup on open, closes itself after 5s
  "popup",          // Global: modal popup after a delay
  "sticky_footer",  // Global: sticky bar fixed to the bottom of the screen
  "global_script",  // Global: page-level script (popunder, social bar, push)
];

const GLOBAL_PLACEMENTS = ["popup", "article_popup", "sticky_footer", "global_script"];

// Page groups an ad can be limited to.
const AD_PAGES = ["home", "tools", "blog", "services", "other"];

const AD_SIZES = ["responsive", "728x90", "970x90", "468x60", "320x50", "320x100", "300x250", "336x280", "160x600", "300x600"];

const advertisementSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },

    // image: our own banner (image + link)
    // code:  third-party ad network snippet (Adsterra, PropellerAds, Monetag, Media.net, ...)
    type: { type: String, enum: ["image", "code"], required: true, default: "image" },

    // --- image ads ---
    imagePath: { type: String, trim: true },
    imageMobilePath: { type: String, trim: true, default: "" }, // ~480px copy served to phones
    websiteLink: { type: String, trim: true },
    altText: { type: String, trim: true, maxlength: 200, default: "" },
    openInNewTab: { type: Boolean, default: true },

    // --- code ads ---
    network: { type: String, trim: true, maxlength: 60, default: "" },
    code: { type: String, maxlength: 20000, default: "" },
    // iframe: runs isolated in a sandboxed frame (safe default for banners)
    // inline: runs directly on the page (needed for popunders, social bars, push)
    renderMode: { type: String, enum: ["iframe", "inline"], default: "iframe" },

    placement: { type: String, enum: AD_PLACEMENTS, required: true, index: true },
    size: { type: String, enum: AD_SIZES, default: "responsive" },

    // Targeting
    pages: { type: [{ type: String, enum: AD_PAGES }], default: [] }, // empty = all pages
    devices: { type: String, enum: ["all", "desktop", "mobile"], default: "all" },

    // Scheduling
    isActive: { type: Boolean, default: true, index: true },
    startDate: { type: Date, default: null },
    endDate: { type: Date, default: null },

    // Rotation: when several ads share a placement, higher weight shows more often
    weight: { type: Number, min: 1, max: 10, default: 5 },

    // Stats
    impressions: { type: Number, default: 0 },
    clicks: { type: Number, default: 0 },

    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

advertisementSchema.index({ isActive: 1, placement: 1 });

const Advertisement = mongoose.model("Advertisement", advertisementSchema);

module.exports = Advertisement;
module.exports.AD_PLACEMENTS = AD_PLACEMENTS;
module.exports.GLOBAL_PLACEMENTS = GLOBAL_PLACEMENTS;
module.exports.AD_PAGES = AD_PAGES;
module.exports.AD_SIZES = AD_SIZES;
