import express from "express";
import passport from "passport";
import setCookie from "../utils/setCookie.js";
import "../config/googleStrategy.js";

const router = express.Router();

// Google Auth Routes
// 1st step - hit this route from frontend
router
  .get(
    "/",
    passport.authenticate("google", {
      session: false,
      scope: ["profile", "email"],
    })
  )

  // 3rd step
  .get(
    "/callback",
    passport.authenticate("google", {
      session: false,
      failureRedirect: `${process.env.HOST}/login`,
    }),
    (req, res) => {
      // Access user object and tokens from req.user
      const { user, access_token, refresh_token } = req.user;

      setCookie(res, refresh_token);


      // Successful authentication, redirect home.
      res.redirect(`${process.env.HOST}/redirect/${access_token}`);
    }
  );

export default router;
