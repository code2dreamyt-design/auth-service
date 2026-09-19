import ms from "ms";
import jwt from "jsonwebtoken";
import { accessExpiry, refreshExpiry, seceretKey } from "../config/env.js";
import crypto from "crypto";
import RefreshToken from "../models/RefreshToken.js";

export const generateAccessToken = (userId) => {
  return jwt.sign({ sub: userId.toString() }, seceretKey, {
    expiresIn: accessExpiry,
  });
};

export const generateRawToken = () => {
  return crypto.randomBytes(64).toString("hex");
};

export const hashToken = (rawToken) => {
  return crypto.createHash("sha256").update(rawToken).digest("hex");
};

export const issueRefreshToken = async (userId, family, ip, userAgent) => {
  try {
    const rawToken = generateRawToken();
    const hashedToken = hashToken(rawToken);
    if (!family || family.length === 0) family = crypto.randomUUID();
    await RefreshToken.create({
      tokenHash: hashedToken,
      user: userId,
      family,
      createdByIp: ip,
      userAgent,
      expiresAt: new Date(Date.now() + ms(refreshExpiry)),
    });
    return rawToken;
  } catch (error) {
    console.log(error);
    throw new Error(`Failed to issue token:${error.message}`);
  }
};

export const rotateRefreshToken = async (rawToken, ip, userAgent) => {
  try {
    const hashedToken = hashToken(rawToken);
    const oldTokenDoc = await RefreshToken.findOneAndUpdate(
      {
        tokenHash: hashedToken,
        revoked: false,
        expiresAt: { $gt: new Date() },
      },
      { revoked: true },
      { new: false },
    );
    if (!oldTokenDoc) {
      const mayBeStolen = await RefreshToken.findOne({
        tokenHash: hashedToken,
      });
      if (!mayBeStolen) {
        throw new Error("Invalid Refresh Token");
      }
      if(mayBeStolen.revoked){
        await RefreshToken.updateMany({family:mayBeStolen.family},{revoked:true});
        throw new Error("Session invalidated — please log in again")
      }
      // exists, not revoked, but still didn't match the atomic filter → must be expired
      throw new Error("Refresh Token Expired — please log in again");
    }

    const newRawToken = await issueRefreshToken(
      oldTokenDoc.user,
      oldTokenDoc.family,
      ip,
      userAgent,
    );
    return { rawToken: newRawToken, userId: oldTokenDoc.user };
  } catch (error) {
    console.log(error);
    throw new Error(`Failed to Refresh token:${error.message}`);
  }
};

export const verifyAccessToken = (token) => {
  const payload = jwt.verify(token, seceretKey);
  return payload;
};
