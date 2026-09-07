// server/config/passport.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const User = require('../models/userModels');
const crypto = require('crypto');

// Helper to generate random password for social users
const generateRandomPassword = () => crypto.randomBytes(16).toString('hex');

// GOOGLE STRATEGY
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/api/users/auth/google/callback",
  scope: ['profile', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ email: profile.emails[0].value });

    if (!user) {
      user = await User.create({
        username: profile.displayName.replace(/\s+/g, '').toLowerCase(),
        email: profile.emails[0].value,
        password: generateRandomPassword(),
        isVerified: true,
        role: 'user'
      });
    }

    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

// FACEBOOK STRATEGY
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "/api/users/auth/facebook/callback",
  profileFields: ['id', 'displayName', 'emails']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let email = profile.emails?.[0]?.value || `${profile.id}@facebook.com`;
    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({
        username: profile.displayName.replace(/\s+/g, '').toLowerCase(),
        email,
        password: generateRandomPassword(),
        isVerified: true,
        role: 'user'
      });
    }

    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

module.exports = passport;