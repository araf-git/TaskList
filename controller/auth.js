import Joi from "joi";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import transporter from "../config/email.js";
import RefreshToken from "../model/refreshToken.js";
import OTP from "../utils/emailOTP.js";
import EmailVerification from "../model/EmailVerification.js";
import generateTokens from "../utils/gengerateTokens.js"
import setCookie from "../utils/setCookie.js";
import User from "../model/user.js";

// done

export const signUp = async (req, res) => {
  const signUpSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string()
      .min(6)
      .max(30)
      .pattern(new RegExp("^[a-zA-Z0-9]+$")) // Optional regex for alphanumeric only
      .required(),
  });

  const { error } = signUpSchema.validate(req.body);

  if (error) {
    return res.status(400).json({ message: error.details[0].message }); // Send specific error message
  }

  const { name, email, password } = req.body;
  try {
    const user = await User.findOne({
      $or: [{ email }, { name }],
    });

    if (user) {
      return res.status(400).json({
        message:
          user.email === email
            ? "Already Signed Up Using this email! Please Login"
            : "This name is already taken. Please choose a different one.",
      });
    }

    if (name && email && password) {
      const salt = await bcrypt.genSalt(10);
      console.log(salt);
      const hashedPassword = await bcrypt.hash(password, salt);
      const newUser = new User({ name, email, password: hashedPassword });
      const doc = await newUser.save();

      // console.log(doc);
      await OTP(doc);
      return res.status(201).json({
        message: "Registration Successful. Check Your Email for OTP",
      });
    } else {
      return res.status(400).json({
        message: "All fields are required",
      });
    }
  } catch (error) {
    return res.status(500).json({
      message: "Unable to Register",
    });
  }
};

// Email Verification

export const verifyEmail = async (req, res) => {
  const otpSchema = Joi.object({
    email: Joi.string().email().required(),
    otp: Joi.string()
      .length(4)
      .pattern(/^\d{4}$/)
      .required(),
  });

  const { error } = otpSchema.validate(req.body);

  if (error) {
    return res.status(400).json({ message: error.details[0].message }); // Send specific error message
  }

  const { email, otp } = req.body;
  console.log(req.body);
  try {
    const existingUser = await User.findOne({ email });
    console.log(existingUser);
    // Check if email doesn't exists
    if (!existingUser) {
      return res
        .status(404)
        .json({ status: "failed", message: "Email doesn't exists" });
    }

    // Check if email is already verified
    if (existingUser.verified) {
      return res
        .status(400)
        .json({ status: "failed", message: "Email is already verified" });
    }

    // Check if the form OTP matches the database OTP
    const emailVerification = await EmailVerification.findOne({
      userId: existingUser._id,
      otp,
    });
    console.log("hello", emailVerification);

    // if no otp found in database give user a new otp
    if (!emailVerification) {
      if (!existingUser.verified) {
        // console.log(existingUser);
        await OTP(existingUser);
        return res.status(400).json({
          status: "failed",
          message: "Invalid OTP, new OTP sent to your email",
        });
      }
      return res.status(400).json({ status: "failed", message: "Invalid OTP" });
    }

    // Check if OTP is expired
    const currentTime = new Date();
    // 15 * 60 * 1000 calculates the expiration period in milliseconds(15 minutes).
    const expirationTime = new Date(
      emailVerification.createdAt.getTime() + 15 * 60 * 1000
    );
    if (currentTime > expirationTime) {
      // OTP expired, send new OTP
      await OTP(req, existingUser);
      return res.status(400).json({
        status: "failed",
        message: "OTP expired, new OTP sent to your email",
      });
    }

    // OTP is valid and not expired, mark email as verified
    existingUser.verified = true;
    await existingUser.save();

    // Delete email verification document
    await EmailVerification.deleteMany({ userId: existingUser._id });
    return res.status(200).json({
      status: "success",
      message: "Email verified successfully. Please Login",
    });
  } catch (error) {
    // console.error(error);
    res.status(500).json({
      status: "failed",
      message: "Unable to verify email, please try again later",
    });
  }
};

export const login = async (req, res) => {
  const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string()
      .min(6)
      .max(30)
      .pattern(new RegExp("^[a-zA-Z0-9]+$")) // Optional regex for alphanumeric only
      .required(),
  });

  const { error } = loginSchema.validate(req.body);

  if (error) {
    return res.status(400).json({ message: error.details[0].message }); // Send specific error message
  }

  const { email, password } = req.body;
  try {
    if (email && password) {
      const user = await User.findOne({ email });
      // console.log(user)
      if (!user) {
        return res.status(400).json({ message: "User not registered" });
      }

      // check if user is verified
      if (!user.verified) {
        return res.status(400).json({ message: "Your Account is not Active" });
      }

      const passwordMatched = await bcrypt.compare(password, user.password);
      if (!passwordMatched) {
        return res.status(400).json({ message: "Invalid email or password" });
      }

      const { access_token, refresh_token } = await generateTokens(user);
      // console.log(access_token, refresh_token);

      setCookie(res, refresh_token);

      return res.status(200).json({
        message: "Login Successful",
        access_token,
      });
    } else {
      return res.status(400).json({ message: "All fields are required" });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Unable to Login",
    });
  }
};

export const userInfo = async (req, res) => {
  const { userID } = req.user;
  // console.log(userID)
  try {
    const user = await User.findById(userID).select(
      "-password -updatedAt -__v"
    ); // Fetch user without password
    // console.log(user)
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({type: "success", message: "fetched user details successfully", user});
  } catch (error) {
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

// implemented on my own

export const changePassword = async (req, res) => {
  const changePassSchema = Joi.object({
    password: Joi.string()
      .min(6)
      .max(30)
      .pattern(new RegExp("^[a-zA-Z0-9]+$")) // Optional regex for alphanumeric only
      .required(),
  });

  const { error } = changePassSchema.validate(req.body);

  if (error) {
    return res.status(400).json({ message: error.details[0].message }); // Send specific error message
  }

  const { password } = req.body;
  const { userID } = req.user;
  try {
    const user = await User.findById(userID);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Unable to change password",
    });
  }
};

export const sendPasswordResetEmail = async (req, res) => {
  const resetSchema = Joi.object({
    email: Joi.string().email().required(),
  });

  const { error } = resetSchema.validate(req.body);

  if (error) {
    return res.status(400).json({ message: error.details[0].message }); // Send specific error message
  }

  const { email } = req.body;

  try {
    const user = await User.findOne({ email }).select(
      "-password -updatedAt -__v"
    );

    if (!user) {
      return res
        .status(404)
        .json({ message: "No User Found Using This Email" });
    }
    // console.log(user);
    // console.log(process.env.JWT_RESET_KEY);
    const secret = user._id + process.env.JWT_RESET_KEY;
    // console.log(secret);
    const reset_token = jwt.sign({ userID: user._id }, secret, {
      expiresIn: "5m",
    });
    const link = `${process.env.HOST}/reset-password/${user._id}/${reset_token}`;
    console.log(link);

    // Uncomment to send email in production
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: user.email,
      subject: "Password Reset Link",
      html: `<a href="${link}">Click Here</a> to Reset Your Password`,
    });

    return res.status(200).json({
      message: "Password Reset Email Sent... Please Check Your Email",
    });
  } catch (error) {
    // console.error(error);
    return res.status(500).json({
      message: "Unable to send password reset email",
    });
  }
};

export const passwordReset = async (req, res) => {
  const { password } = req.body;
  const { id, reset_token } = req.params;
  console.log(password, id, reset_token);
  // Joi validation schema
  const schema = Joi.object({
    // id: Joi.string().length(24).hex().required(),  // MongoDB ObjectId validation
    password: Joi.string()
      .min(6)
      .max(30)
      .pattern(new RegExp("^[a-zA-Z0-9]+$")) // Optional regex for alphanumeric only
      .required(),
    reset_token: Joi.string().required(),
  });

  // Validate the parameters
  // const { error } = schema.validate({ id, password, reset_token });
  const { error } = schema.validate({ password, reset_token });

  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const new_secret = user._id + process.env.JWT_RESET_KEY;
    try {
      const verified = jwt.verify(reset_token, new_secret);
      if (verified.userID !== user._id.toString()) {
        return res.status(400).json({ message: "Invalid token" });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      user.password = hashedPassword;
      await user.save();
      return res.status(200).json({
        message: "Password Reset Successfully",
      });
    } catch (error) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }
  } catch (error) {
    return res.status(500).json({ message: "Internal server error" });
  }
};

// done

export const refresh = async (req, res) => {
  const refreshSchema = Joi.object({
    refresh_token: Joi.string().required(),
  });

  // Validate incoming refresh token
  const { error } = refreshSchema.validate(req.cookies);

  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const refresh_token = req.cookies?.refresh_token;
  if (!refresh_token) {
    return res
      .status(400)
      .json({ message: "Refresh token not found in cookies" });
  }

  try {
    // Check if the refresh token exists in the database
    const refreshtoken = await RefreshToken.findOne({
      token: refresh_token,
    });
    if (!refreshtoken) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    // Verify the refresh token
    const validity = jwt.verify(
      refreshtoken.token,
      process.env.REFRESH_SECRET_KEY
    );
    const { userID } = validity;

    // Fetch the user from the database
    const user = await User.findById(userID);
    if (!user) {
      return res.status(404).json({ message: "No user found!" });
    }

    // Generate new tokens by calling generateTokens
    const { access_token, refresh_token: newRefreshToken } =
      await generateTokens(user);

    // const { access_token, refresh_token: newRefreshToken } what is newRefreshToken? short short short. accessing refresh_token as newRefreshToken?
    // ChatGPT said:
    // Yes, newRefreshToken is just a renamed version of refresh_token. This syntax is called destructuring with aliasing. It renames refresh_token to newRefreshToken for clarity or to avoid naming conflicts.

    // Respond with the new refresh token and access token
    setCookie(res, newRefreshToken);

    return res.status(201).json({
      message: "Refresh Successful",
      access_token,
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Something went wrong", error: err.message });
  }
};

export const logout = async (req, res) => {
  // Validation
  const refreshSchema = Joi.object({
    refresh_token: Joi.string().required(),
  });

  const { error } = refreshSchema.validate(req.cookies);

  if (error) {
    return res.status(400).json({ message: error.details[0].message }); // Return validation error
  }

  try {
    // Delete the refresh token from the database
    // const result = await RefreshToken.deleteOne({
    //   token: req.cookies.refresh_token,
    // });

    const result = await RefreshToken.findOneAndUpdate(
      { token: req.cookies.refresh_token },
      { $set: { blacklisted: true } },
      { new: true }
    );

    // Check if a token was actually deleted
    // if (result.deletedCount === 0) {
    //   return res
    //     .status(404)
    //     .json({ message: "Refresh token not found or already deleted" });
    // }

    console.log(result.blacklisted);

    res.cookie("refresh_token", "", {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      expires: new Date(0),
    });

    // Success response
    return res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    // Handle database errors
    return res
      .status(500)
      .json({ message: "Something went wrong in the database" });
  }
};
