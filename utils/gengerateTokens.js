import jwt from "jsonwebtoken";
import RefreshToken from "../model/refreshToken.js";

const generateTokens = async (user) => {
  try {
    // Generate tokens
    const access_token = jwt.sign(
      { userID: user._id },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "20s" }
    );

    const refresh_token = jwt.sign(
      { userID: user._id },
      process.env.REFRESH_SECRET_KEY,
      { expiresIn: "5d" }
    );

    // Find existing refresh token
    const userRefreshToken = await RefreshToken.findOne({ userId: user._id });

    if (userRefreshToken) {
      // Blacklist the existing refresh token
      // userRefreshToken.blacklisted = true;
      // await userRefreshToken.save();

      // Delete old refresh token (if you want to remove instead of blacklist)
      await RefreshToken.findOneAndDelete({ userId: user._id });
    }

    // Save new refresh token
    await new RefreshToken({ userId: user._id, token: refresh_token }).save();

    return { access_token, refresh_token };
  } catch (error) {
    throw error;
  }
};

export default generateTokens;
