import mongoose from "mongoose";
const { Schema } = mongoose;

const refreshTokenSchema = new Schema(
  {
    token: { type: String, unique: true },
  },
  { timestamps: true }
);

const RefreshToken = mongoose.model("RefreshToken", refreshTokenSchema);
export default RefreshToken;
