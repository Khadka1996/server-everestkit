const mongoose = require("mongoose");

// Single-document collection holding site-wide settings that the admin edits
// from Dashboard > Settings. Always read/written through SiteSettings.getSingleton().
const codeBlock = {
  enabled: { type: Boolean, default: false },
  code: { type: String, maxlength: 50000, default: "" },
};

const siteSettingsSchema = new mongoose.Schema(
  {
    key: { type: String, default: "site", unique: true },

    // Code injection — lets the admin paste verification tags, analytics,
    // ad-network scripts, etc. without logging in to the VPS.
    codeInjection: {
      head: codeBlock,       // inside <head>
      bodyStart: codeBlock,  // right after <body> opens
      sidebar: codeBlock,    // inside blog article sidebars
      footer: codeBlock,     // before </body>
      customCss: codeBlock,  // raw CSS (no <style> tag needed)
      customJs: codeBlock,   // raw JavaScript (no <script> tag needed)
    },

    ads: {
      enabled: { type: Boolean, default: true },            // master switch
      showOnMobile: { type: Boolean, default: true },
      hideForAdmins: { type: Boolean, default: true },      // don't count/show ads to logged-in admins
      showAdLabel: { type: Boolean, default: true },        // small "Advertisement" label above ads
      adsenseFallback: { type: Boolean, default: true },    // show AdSense in a slot when no custom ad exists
      scriptAdsOnly: { type: Boolean, default: false },     // only network script (code) ads run; image ads are held back
      popupDelaySeconds: { type: Number, min: 0, max: 600, default: 8 },
      popupFrequencyHours: { type: Number, min: 0, max: 720, default: 24 }, // 0 = every page load
      stickyDismissible: { type: Boolean, default: true },
      excludedPaths: { type: [String], default: [] },        // e.g. ["/contact", "/tools/calculator"]
      adsTxt: { type: String, maxlength: 20000, default: "" }, // served at /ads.txt
    },

    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true, minimize: false }
);

siteSettingsSchema.statics.getSingleton = async function () {
  let doc = await this.findOne({ key: "site" });
  if (!doc) doc = await this.create({ key: "site" });
  return doc;
};

module.exports = mongoose.model("SiteSettings", siteSettingsSchema);
