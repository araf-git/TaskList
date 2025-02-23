import express from "express";
import limiter from "../config/rateLimit.js";
import {
  signUp,
  login,
  changePassword,
  userInfo,
  sendPasswordResetEmail,
  passwordReset,
  refresh,
  logout,
  verifyEmail,
} from "../controller/auth.js";
import checkUserAuth from "../middleware/auth.js";

const router = express.Router();

router
  // Public route
  .post("/signup", limiter, signUp)
  .post("/verify-email", limiter, verifyEmail)
  .post("/login", limiter, login)
  .post("/forgot-password", limiter, sendPasswordResetEmail)
  .post("/reset-password/:id/:reset_token", limiter, passwordReset)
  .post("/refresh", limiter, refresh)

  // Protected route
  .post("/change-password", checkUserAuth, limiter, changePassword)
  .get("/userinfo", checkUserAuth, limiter, userInfo)
  .post("/logout", checkUserAuth, limiter, logout);
export default router;
