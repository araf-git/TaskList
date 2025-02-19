import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import passport from "passport";
import bcrypt from "bcrypt";
import generateTokens from "../utils/gengerateTokens.js";
import User from "../model/user.js";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://task-list-two-rho.vercel.app/auth/google/callback", //backend callback
    },
    async (access_token, refresh_token, profile, done) => {
      // console.log("Profile", profile);


      try {

        // Check if user already exists in the database
        let user = await User.findOne({ email: profile._json.email });


        if (!user) {

          const lastSixDigitsID = profile.id.substring(profile.id.length - 6);
          const lastTwoDigitsName = profile._json.name.substring(
            profile._json.name.length - 2
          );
          const newPass = lastTwoDigitsName + lastSixDigitsID;
          // Generate salt and hash password
          const salt = await bcrypt.genSalt(10)
          const hashedPassword = await bcrypt.hash(newPass, salt);


          user = await User.create({
            name: profile._json.name,
            email: profile._json.email,
            verified: true,
            password: hashedPassword,
          });
          
        }


        // Generate JWT tokens
        const { access_token, refresh_token } = await generateTokens(user);
        return done(null, {
          user,
          access_token,
          refresh_token,
        });
      } catch (error) {
        return done(error);
      }
    }
  )
);
