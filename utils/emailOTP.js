import transporter from "../config/email.js";
import EmailVerification from "../model/EmailVerification.js";

const OTP = async (user) => {
  // Generate a random 4-digit number
  const otp = Math.floor(1000 + Math.random() * 9000);
  console.log(otp);

  // Save OTP in Database
  await new EmailVerification({ userId: user._id, otp: otp }).save();

  //  OTP Verification Link
  const otpVerificationLink = `localhost:3000/auth/verify-email`;
  console.log(otpVerificationLink)
  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: user.email,
    subject: "OTP - Verify your account",
    html: `<p>Dear ${user.name},</p><p>Thank you for signing up with our website. To complete your registration, please verify your email address by entering the following one-time password (OTP): ${otpVerificationLink} </p>
    <h2>OTP: ${otp}</h2>
    <p>This OTP is valid for 15 minutes. If you didn't request this OTP, please ignore this email.</p>`,
  });

  return otp;
};

export default OTP;
