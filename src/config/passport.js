import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import {
  googleCallbackUrl,
  googleClientId,
  googleClientSecret,
} from "./env.js";
import User from "../models/User.js";

passport.use(
  new GoogleStrategy(
    {
      clientID: googleClientId,
      clientSecret: googleClientSecret,
      callbackURL: googleCallbackUrl,
    },
    async (accessToken, refreshToken, profile, done) => {
      // Case 1 / Case 2 logic goes here — this is the part we design carefully
      try {
        const googleId = profile.id;
        const email = profile.emails?.[0]?.value?.toLocaleLowerCase().trim();
        const emailVerified = profile.emails?.[0]?.verified;
        const name = profile.displayName;
        if (!email) return done(new Error("Google account has no email"), null);

        let user = await User.findOne({ googleId });
        if (user) {
          return done(null, user);
        }
        user = await User.findOne({ email });
        if (user) {
          if (!emailVerified) {
            return done(new Error("Email not verified by Google"), null);
          }
          user.googleId = googleId;
          user.isEmailVerified = true;
          await user.save();
          return done(null, user);
        }
        const newUser = await User.create({
          name,
          email,
          googleId,
          isEmailVerified: true,
        });
        return done(null, newUser);
      } catch (error) {
         return done(error, null);
      }
    },
  ),
);

export default passport;
