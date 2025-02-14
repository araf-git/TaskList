import Joi from "joi";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../model/user.js";
import transporter from "../config/email.js";
import RefreshToken from "../model/refreshToken.js";

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
    return res
      .status(400)
      .json({ type: "error", message: error.details[0].message }); // Send specific error message
  }

  const { name, email, password } = req.body;
  try {
    const user = await User.findOne({
      $or: [{ email }, { name }],
    });

    if (user) {
      return res.status(400).json({
        type: "error",
        message:
          user.email === email
            ? "Already Signed Up Using this email! Please Login"
            : "This name is already taken. Please choose a different one.",
      });
    }

    if (name && email && password) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const newUser = new User({ name, email, password: hashedPassword });
      const doc = await newUser.save();

      // Create Token
      const access_token = jwt.sign(
        { userID: doc._id },
        process.env.JWT_SECRET_KEY,
        {
          expiresIn: "20s",
        }
      );

      const refresh_token = jwt.sign(
        { userID: doc._id },
        process.env.REFRESH_SECRET_KEY,
        {
          expiresIn: "5d",
        }
      );
      // console.log(refresh_token)
      // database whitelist
      try {
        await RefreshToken.create({ token: refresh_token });
      } catch (error) {
        console.log('"Error saving refresh token', error.message);
      }

      // Set token in HTTP-only cookie
      res.cookie("refresh_token", refresh_token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 5 * 24 * 60 * 60 * 1000, // 5 days
      });

      return res.status(201).json({
        type: "success",
        message: "Registration Successful",
        access_token,
      });
    } else {
      return res.status(400).json({
        type: "error",
        message: "All fields are required",
      });
    }
  } catch (error) {
    return res.status(500).json({
      type: "error",
      message: "Unable to Register",
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
    return res
      .status(400)
      .json({ type: "error", message: error.details[0].message }); // Send specific error message
  }

  const { email, password } = req.body;
  try {
    if (email && password) {
      const user = await User.findOne({ email });
      // console.log(user)
      if (!user) {
        return res
          .status(400)
          .json({ type: "error", message: "User not registered" });
      }

      const passwordMatched = await bcrypt.compare(password, user.password);
      if (!passwordMatched) {
        return res
          .status(400)
          .json({ type: "error", message: "Invalid email or password" });
      }

      const access_token = jwt.sign(
        { userID: user._id },
        process.env.JWT_SECRET_KEY,
        {
          expiresIn: "20s",
        }
      );

      const refresh_token = jwt.sign(
        { userID: user._id },
        process.env.REFRESH_SECRET_KEY,
        {
          expiresIn: "5d",
        }
      );
      // console.log(refresh_token)
      // database whitelist
      try {
        await RefreshToken.create({ token: refresh_token });
      } catch (error) {
        console.log('"Error saving refresh token', error.message);
      }

      // // Set token in HTTP-only cookie
      res.cookie("refresh_token", refresh_token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 5 * 24 * 60 * 60 * 1000,
      });

      return res.status(200).json({
        type: "success",
        message: "Login Successful",
        access_token,
      });
    } else {
      return res
        .status(400)
        .json({ type: "error", message: "All fields are required" });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      type: "error",
      message: "Unable to Login",
    });
  }
};

export const userInfo = async (req, res) => {
  const { userID } = req.user;
  // console.log(userID)
  try {
    const user = await User.findById(userID);
    if (!user) {
      return res.status(404).json({ type: "error", message: "User not found" });
    }

    return res.status(200).json({
      type: "success",
      message: "fetched user details successfully",
      user,
    });
  } catch (error) {
    return res
      .status(500)
      .json({ type: "error", message: "Internal Server Error" });
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
    return res
      .status(400)
      .json({ type: "error", message: error.details[0].message }); // Send specific error message
  }

  const { password } = req.body;
  const { userID } = req.user;
  try {
    const user = await User.findById(userID);
    if (!user) {
      return res.status(404).json({ type: "error", message: "User not found" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({
      type: "success",
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      type: "error",
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
    return res
      .status(400)
      .json({ type: "error", message: error.details[0].message }); // Send specific error message
  }

  const { email } = req.body;

  try {
    const user = await User.findOne({ email }).select(
      "-password -updatedAt -__v"
    );

    if (!user) {
      return res
        .status(404)
        .json({ type: "error", message: "No User Found Using This Email" });
    }
    // console.log(user);
    // console.log(process.env.JWT_RESET_KEY);
    const secret = user._id + process.env.JWT_RESET_KEY;
    // console.log(secret);
    const reset_token = jwt.sign({ userID: user._id }, secret, {
      expiresIn: "5m",
    });
    const link = `http://localhost:3000/reset-password/${user._id}/${reset_token}`;
    console.log(link);

    // Uncomment to send email in production
    // await transporter.sendMail({
    //   from: process.env.EMAIL_FROM,
    //   to: user.email,
    //   subject: "Password Reset Link",
    //   html: `<a href="${link}">Click Here</a> to Reset Your Password`,
    // });

    return res.status(200).json({
      type: "success",
      message: "Password Reset Email Sent... Please Check Your Email",
    });
  } catch (error) {
    // console.error(error);
    return res.status(500).json({
      type: "error",
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
    return res
      .status(400)
      .json({ type: "error", message: error.details[0].message });
  }

  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ type: "error", message: "User not found" });
    }

    const new_secret = user._id + process.env.JWT_RESET_KEY;
    try {
      const verified = jwt.verify(reset_token, new_secret);
      if (verified.userID !== user._id.toString()) {
        return res
          .status(400)
          .json({ type: "error", message: "Invalid token" });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      user.password = hashedPassword;
      await user.save();
      return res.status(200).json({
        type: "success",
        message: "Password Reset Successfully",
      });
    } catch (error) {
      return res
        .status(400)
        .json({ type: "error", message: "Invalid or expired token" });
    }
  } catch (error) {
    return res
      .status(500)
      .json({ type: "error", message: "Internal server error" });
  }
};

// done

export const refresh = async (req, res) => {
  const refreshSchema = Joi.object({
    refresh_token: Joi.string().required(),
  });

  // // Declare refresh_token before using it
  // const refresh_token = req.cookies?.refresh_token;

  // Validate incoming refresh token
  const { error } = refreshSchema.validate(req.cookies);

  if (error) {
    return res
      .status(400)
      .json({ type: "error", message: error.details[0].message });
  }

  const refresh_token = req.cookies?.refresh_token;
  console.log(refresh_token); // Now it's safe to log refresh_token
  if (!refresh_token) {
    return res
      .status(400)
      .json({ type: "error", message: "Refresh token not found in cookies" });
  }
  try {
    //   // Check if the refresh token exists in the database
    const refreshtoken = await RefreshToken.findOne({
      token: refresh_token,
    });
    if (!refreshtoken) {
      return res
        .status(401)
        .json({ type: "error", message: "Invalid refresh token" });
    }
    // console.log(refreshtoken);
    //   // Verify the refresh token
    const validity = jwt.verify(
      refreshtoken.token,
      process.env.REFRESH_SECRET_KEY
    );
    const { userID } = validity;
    //   // Fetch the user from the database
    const user = await User.findById(userID);
    if (!user) {
      return res.status(404).json({ type: "error", message: "No user found!" });
    }
    // console.log(user, "found by refresh token");

    try {
      // //   // Generate new tokens
      const access_token = jwt.sign(
        { userID: user._id },
        process.env.JWT_SECRET_KEY,
        { expiresIn: "20s" }
      );
      // console.log(access_token);

      // Add a unique component (e.g., timestamp) to ensure the refresh token is different each time
      let refresh_token = jwt.sign(
        { userID: user._id, timestamp: Date.now() }, // Add a timestamp to make the token unique
        process.env.REFRESH_SECRET_KEY,
        { expiresIn: "5d" }
      );
      // console.log(refresh_token);

      // Remove the old refresh token and save the new one
      await RefreshToken.deleteOne({ token: refreshtoken.token });
      await RefreshToken.create({ token: refresh_token });

      //   // Respond with new tokens
      res.cookie("refresh_token", refresh_token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 5 * 24 * 60 * 60 * 1000, // 5 days
      });

      return res.status(201).json({
        type: "success",
        message: "Refresh Successful",
        access_token,
      });
    } catch (error) {
      console.log("error generating tokenssss", error);
    }
  } catch (err) {
    return res
      .status(500)
      .json({ type: "error", message: "Something went wrong" });
  }
};

export const logout = async (req, res) => {
  // console.log('refresh cookie', req.cookies.refresh_token)
  // Validation
  const refreshSchema = Joi.object({
    refresh_token: Joi.string().required(),
  });
  // console.log(req.cookies.refresh_token)
  // const { error } = refreshSchema.validate(req.body);
  const { error } = refreshSchema.validate(req.cookies);
  // console.log('error', error)
  if (error) {
    return res
      .status(400)
      .json({ type: "error", message: error.details[0].message }); // Return validation error
  }

  try {
    // Delete the refresh token from the database
    const result = await RefreshToken.deleteOne({
      // token: req.body.refresh_token,
      token: req.cookies.refresh_token,
    });

    // Check if a token was actually deleted
    if (result.deletedCount === 0) {
      return res.status(404).json({
        type: "error",
        message: "Refresh token not found or already deleted",
      });
    }

    res.cookie("refresh_token", "", {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      expires: new Date(0),
    });

    // Success response
    return res
      .status(200)
      .json({ type: "success", message: "Logged out successfully" });
  } catch (err) {
    // Handle database errors
    return res
      .status(500)
      .json({ type: "error", message: "Something went wrong in the database" });
  }
};
