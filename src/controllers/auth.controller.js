import {
  appName,
  emailVerificationExpiry,
  nodeEnv,
  passwordResetExpiryTime,
  refreshExpiry,
  twoFactorSecretCode,
} from "../config/env.js";
import User from "../models/User.js";
import ms from "ms";
import {
  generateAccessToken,
  generateRawToken,
  hashToken,
  issueRefreshToken,
  rotateRefreshToken,
} from "../services/token.service.js";
import RefreshToken from "../models/RefreshToken.js";
import {
  sendPasswordResetEmail,
  sendVerificationEmail,
} from "../services/email.service.js";
import { generateSecret, generateURI, verify } from "otplib";
import QRCode from "qrcode";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { decrypt, encrypt } from "../utils/encryption.js";
export const signup = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({
      message: "Invalid or empty input",
    });
  }
  try {
    const isExists = await User.findOne({ email: email.toLowerCase().trim() });
    if (isExists)
      return res.status(409).json({ message: "Email already registered" });

    const user = await User.create({
      name,
      email,
      password,
    });
    if (user) {
      const rawEmailVerificationToken = generateRawToken();
      const hashVerificationToken = hashToken(rawEmailVerificationToken);
      user.verificationTokenHash = hashVerificationToken;
      user.verificationExpiry = new Date(
        Date.now() + ms(emailVerificationExpiry),
      );
      await user.save();
      sendVerificationEmail(user, rawEmailVerificationToken).catch(err=>console.error("Verification email failed",err.message));
    }

    const accessToken = generateAccessToken(user._id);
    const rawRefreshToken = await issueRefreshToken(
      user._id,
      null,
      req.ip,
      req.headers["user-agent"],
    );
    res.cookie("refreshToken", rawRefreshToken, {
      httpOnly: true,
      secure: nodeEnv === "production",
      sameSite: "strict",
      maxAge: ms(refreshExpiry),
    });
    return res.status(201).json({
      user,
      accessToken,
    });
  } catch (error) {
    
    if (error.code === 11000) {
      return res.status(409).json({ message: "Email already registered" });
    }
    console.log(error.message);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
};
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Re-check your Inputs" });
    }

    const user = await User.findOne({
      email: email.toLowerCase().trim(),
    }).select("+password");
    if (!user || !user.password) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    if (user.lockUntil && user.lockUntil > Date.now()) {
      return res
        .status(401)
        .json({ message: "Invalid credentials" });
    }
    const isPasswordCorrect = await user.comparePassword(password);
    if (!isPasswordCorrect) {
      user.loginAttempts = user.loginAttempts + 1;
      if (user.loginAttempts >= 5) {
        user.loginAttempts = 0;
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
      }
      await user.save();
      return res.status(401).json({ message: "Invalid credentials" });
    }
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    if (user.twoFactorEnabled) {
      const twoFactorToken = jwt.sign(
        { sub: user._id.toString(), purpose: "2fa" },
        twoFactorSecretCode,
        { expiresIn: "5m" },
      );
      return res.status(200).json({ requires2FA: true, twoFactorToken });
    }

    const accessToken = generateAccessToken(user._id);

    const rawRefreshToken = await issueRefreshToken(
      user._id,
      null,
      req.ip,
      req.headers["user-agent"],
    );

    res.cookie("refreshToken", rawRefreshToken, {
      httpOnly: true,
      secure: nodeEnv === "production",
      sameSite: "strict",
      maxAge: ms(refreshExpiry),
    });
    return res.status(200).json({
      user,
      accessToken,
    });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
};

export const refresh = async (req, res) => {
  const currentRawToken = req.cookies.refreshToken;
  if (!currentRawToken || typeof currentRawToken !== "string") {
    return res
      .status(401)
      .json({ message: "No refresh token", code: "NO_TOKEN" });
  }

  let tokenObject;
  try {
    tokenObject = await rotateRefreshToken(
      currentRawToken,
      req.ip,
      req.headers["user-agent"],
    );
  } catch (error) {
    console.log(error.message);
    res.clearCookie("refreshToken");
    return res
      .status(401)
      .json({ message: error.message, code: "REFRESH_FAILED" });
  }
  try {
    const accessToken = generateAccessToken(tokenObject.userId);

    res.cookie("refreshToken", tokenObject.rawToken, {
      httpOnly: true,
      secure: nodeEnv === "production",
      sameSite: "strict",
      maxAge: ms(refreshExpiry),
    });
    return res.status(200).json({
      accessToken,
    });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken || typeof refreshToken !== "string") {
      res.clearCookie("refreshToken");
      return res.status(200).json({ message: "Already logged Out" });
    }

    const tokenHash = hashToken(refreshToken); // renamed — no more collision
    const isTokenInDb = await RefreshToken.findOne({ tokenHash });

    if (!isTokenInDb) {
      res.clearCookie("refreshToken");
      return res.status(200).json({ message: "Already logged Out" });
    }

    res.clearCookie("refreshToken");
    await RefreshToken.deleteMany({ family: isTokenInDb.family });
    return res.status(200).json({ message: "Logged out" }); // fixed message too
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal Server Error" }); // statu → status
  }
};

export const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    return res.status(200).json({ user });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;
    if (!token || typeof token !== "string") {
      return res.status(400).json({ message: "Invalid verification link" });
    }

    const tokenHash = hashToken(token);
    const user = await User.findOne({
      verificationTokenHash: tokenHash,
      verificationExpiry: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ message: "Invalid or expired verification link" });
    }

    user.isEmailVerified = true;
    user.verificationTokenHash = undefined;
    user.verificationExpiry = undefined;
    user.verificationEmailCount = undefined;
    user.verificationEmailCountResetAt = undefined;
    await user.save();

    return res.status(200).json({ message: "Email verified" });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const resendEmail = async (req, res) => {
  try {
    const now = new Date();
    const userId = req.userId;

    //reset count if any exist
    await User.updateOne(
      {
        _id: userId,

        $or: [
          { verificationEmailCountResetAt: { $exists: false } },
          { verificationEmailCountResetAt: { $lte: now } },
        ],
      },
      {
        $set: {
          verificationEmailCount: 0,
          verificationEmailCountResetAt: new Date(
            now.getTime() + 24 * 60 * 60 * 1000,
          ),
        },
      },
    );

    //start reset count
    const newVerificationToken = generateRawToken();
    const tokenHash = hashToken(newVerificationToken);
    const updated = await User.findOneAndUpdate(
      {
        _id: userId,
        verificationEmailCount: { $lt: 5 },
      },
      {
        $inc: { verificationEmailCount: 1 },
        $set: {
          verificationTokenHash: tokenHash,
          verificationExpiry: new Date(
            now.getTime() + ms(emailVerificationExpiry),
          ),
        },
      },
      {
        new: true,
      },
    );

    if (!updated) {
      return res
        .status(429)
        .json({ message: "Daily email limit reached. Try again later." });
    }

    await sendVerificationEmail(updated, newVerificationToken);
    return res.status(200).json({ message: "Verification email sent" });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

//case 1 when user is not logged in
export const forgetPassword = async (req, res) => {
  try {
    const now = new Date();
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({
        message: "Invalid or empty input",
      });
    }

    await User.updateOne(
      {
        email: email.toLowerCase().trim(),
        $or: [
          { passwordResetCountResetAt: { $exists: false } },
          { passwordResetCountResetAt: { $lte: now } },
        ],
      },
      {
        $set: {
          passwordResetCount: 0,
          passwordResetCountResetAt: new Date(
            now.getTime() + 24 * 60 * 60 * 1000,
          ),
        },
      },
    );
    const rawPassResetToken = generateRawToken();
    const tokenHash = hashToken(rawPassResetToken);

    const updated = await User.findOneAndUpdate(
      {
        email: email.toLowerCase().trim(),
        passwordResetCount: { $lt: 5 },
      },
      {
        $inc: {
          passwordResetCount: 1,
        },
        $set: {
          passwordResetTokenHash: tokenHash,
          passwordResetExpiry: new Date(
            now.getTime() + ms(passwordResetExpiryTime),
          ),
        },
      },
      {
        new: true,
      },
    );
    if (updated) {
      sendPasswordResetEmail(updated, rawPassResetToken).catch((err) =>
        console.log("Password reset email failed:", err.message),
      );
    }
    return res
      .status(200)
      .json({ message: "Password change link is sent to your email" });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};
//case 2 already loggen in and forget password

export const resetPassword = async (req, res) => {
  try {
    const now = new Date();
    const { rawPassResetToken } = req.params;
    if (!rawPassResetToken || typeof rawPassResetToken !== "string")
      return res.status(400).json({ message: "Invalid Link try again" });
    const tokenHash = hashToken(rawPassResetToken);
    const { newPassword } = req.body;
    if (!newPassword) return res.status(400).json({ message: "Invalid input" });
    const user = await User.findOne({
      passwordResetTokenHash: tokenHash,
      passwordResetExpiry: { $gt: now },
    });
    if (!user)
      return res
        .status(400)
        .json({ message: "Password reset token is invalid or has expired." });

    user.password = newPassword; // pre('save') hook hashes this correctly
    user.passwordResetTokenHash = undefined;
    user.passwordResetExpiry = undefined;
    user.passwordResetCount = undefined;
    user.passwordResetCountResetAt = undefined;
    await user.save();

    await RefreshToken.deleteMany({ user: user._id });
    return res
      .status(200)
      .json({ message: "Password has been changed you can login now" });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const changePassword = async (req, res) => {
  try {
    const userId = req.userId;
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ message: "Invalid input" });
    const user = await User.findById(userId).select("+password");
    if (!user.password) {
      return res.status(400).json({
        message:
          "This account has no password set. Use 'Forgot Password' to set one first.",
      });
    }
    const isPasswordCorrect = await user.comparePassword(currentPassword);
    if (!isPasswordCorrect)
      return res.status(401).json({ message: "Current password is incorrect" });
    user.password = newPassword;
    await user.save();
    await RefreshToken.deleteMany({ user: user._id });
    return res
      .status(200)
      .json({ message: "Password has been changed you can login now" });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const setupTwoFactor = async (req, res) => {
  try {
    const userId = req.userId;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.twoFactorEnabled)
      return res.status(400).json({ message: "2FA is already enabled" });

    const secret = generateSecret();
    const otpauthUrl = generateURI({
      issuer: appName,
      label: user.email,
      secret,
    });
    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);
    user.twoFactorSecret = encrypt(secret);
    await user.save();

    return res.status(200).json({
      secret,
      qrCodeDataUrl,
    });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const verifyTwoFactorSetup = async (req, res) => {
  try {
    const userId = req.userId;
    const { token } = req.body;
    if (!token) return res.status(400).json({ message: "Invalid input" });
    const user = await User.findById(userId).select("+twoFactorSecret");
    
    if (!user.twoFactorSecret)
      return res.status(400).json({ message: "Please start 2FA setup first" });
    
    if (user.twoFactorEnabled) {return res.status(400).json({ message: "2FA is already enabled" });}
    const decryptSecret = decrypt(user.twoFactorSecret);
    const result = await verify({ secret: decryptSecret, token });
    if (!result.valid) return res.status(400).json({ message: "Invalid code" });
    let codeArr = [];
    let codeHashArr = [];
    for (let i = 0; i < 8; i++) {
      const backupCode = crypto.randomBytes(4).toString("hex");
      const hashedCode = hashToken(backupCode);
      codeArr.push(backupCode);
      codeHashArr.push(hashedCode);
    }
    user.twoFactorEnabled = true;
    user.backupCodesHashed = codeHashArr;
    await user.save();
    return res.status(200).json({
      backupCodes: codeArr,
      message: "Enabled two-step verification successfully",
    });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const verifyTwoFactorlogin = async (req, res) => {
  const { twoFactorToken, code } = req.body;

  if (!twoFactorToken || !code) {
    return res.status(400).json({ message: "Invalid input" });
  }

  let decoded;

  try {
    decoded = jwt.verify(twoFactorToken, twoFactorSecretCode);
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ message: "Access token expired", code: "TOKEN_EXPIRED" });
    }
    return res
      .status(401)
      .json({ message: "Invalid token", code: "INVALID_TOKEN" });
  }
  try {
    if (decoded.purpose !== "2fa"){ return res.status(400).json({ message: "Invalid Token" });}

    const user = await User.findById(decoded.sub).select(
      "+twoFactorSecret +backupCodesHashed",
    );
    if (!user) {return res.status(400).json({ message: "Invalid token" });}
    const decryptSecret = decrypt(user.twoFactorSecret);
    const result = await verify({ secret: decryptSecret, token: code });
    if (!result.valid) {
      const hashedCode = hashToken(code);
      const isMatched = user.backupCodesHashed.some(
        (backupCode) => backupCode === hashedCode,
      );
      if (!isMatched) {
        return res.status(400).json({ message: "Invalid token" });
      }
      const backupCodeLeft = user.backupCodesHashed.filter(
        (backupCode) => backupCode !== hashedCode,
      );
      user.backupCodesHashed = backupCodeLeft;
      await user.save();
    }
    const accessToken = generateAccessToken(user._id);
    const rawRefreshToken = await issueRefreshToken(
      user._id,
      null,
      req.ip,
      req.headers["user-agent"],
    );

    res.cookie("refreshToken", rawRefreshToken, {
      httpOnly: true,
      secure: nodeEnv === "production",
      sameSite: "strict",
      maxAge: ms(refreshExpiry),
    });
    return res.status(200).json({
      user,
      accessToken,
    });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const regenerateBackupCodes = async (req, res) => {
  try {
    const userId = req.userId;
    const { currentPassword } = req.body;
    if (!currentPassword)
      return res.status(400).json({ message: "Invalid input" });

    const user = await User.findById(userId).select("+password");
    if (!user.password) {
      return res.status(400).json({
        message:
          "This account has no password set. Use 'Forgot Password' to set one first.",
      });
    }
    if (!user.twoFactorEnabled) {
      return res.status(400).json({ message: "2FA is not enabled" });
    }
    const isPasswordCorrect = await user.comparePassword(currentPassword);
    if (!isPasswordCorrect)
      return res.status(401).json({ message: "Incorrect Password" });
    let codeArr = [];
    let codeHashArr = [];
    for (let i = 0; i < 8; i++) {
      const backupCode = crypto.randomBytes(4).toString("hex");
      const hashedCode = hashToken(backupCode);
      codeArr.push(backupCode);
      codeHashArr.push(hashedCode);
    }
    user.backupCodesHashed = codeHashArr;
    await user.save();
    return res.status(200).json({
      backupCodes: codeArr,
      message: "New backup code granted",
    });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const disableTwofactor = async (req, res) => {
  try {
    const userId = req.userId;
    const { currentPassword } = req.body;
    if (!currentPassword)
      return res.status(400).json({ message: "Invalid input" });

    const user = await User.findById(userId).select("+password");
    if (!user.password) {
      return res.status(400).json({
        message:
          "This account has no password set. Use 'Forgot Password' to set one first.",
      });
    }
    if (!user.twoFactorEnabled) {
      return res.status(400).json({ message: "2FA is not enabled" });
    }
    const isPasswordCorrect = await user.comparePassword(currentPassword);
    if (!isPasswordCorrect)
      return res.status(401).json({ message: "Incorrect Password" });
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    user.backupCodesHashed = [];
    await user.save();
    return res.status(200).json({ message: "2FA disabled" });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: "Internal server error" });
  }
};
//case 2 2fa using mail generate otp and send to mail with otp limit
//also otp resend limit same as link and forgot pass link
//verify otp endpoint all tree for later and must because you will not give everyone he top model
