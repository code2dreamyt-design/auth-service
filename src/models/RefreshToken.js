import mongoose from "mongoose";

const refreshTokenSchema = new mongoose.Schema({
  tokenHash: { type: String,unique:true, required: true, index: true },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },
  revoked: { type: Boolean, default: false },
  family: { type: String, required: true, index: true },
  createdByIp: { type: String },
  userAgent: { type: String },
  expiresAt: { type: Date, required: true, index: { expires: "0s" } },
  createdAt: { type: Date, default: Date.now },
});

const RefreshToken = mongoose.model("RefreshToken", refreshTokenSchema);

export default RefreshToken;
