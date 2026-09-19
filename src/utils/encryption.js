import crypto from "crypto";
import { twoFactorEncryptionKey } from "../config/env.js";

const ALGORITHM = "aes-256-gcm";
const key = Buffer.from(twoFactorEncryptionKey,"hex");

export const encrypt = (plainText) =>{
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ALGORITHM,key,iv);
    const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted.toString("hex")}`;
}

export const decrypt = (encryptedString) => {
  const [ivHex, authTagHex, encryptedHex] = encryptedString.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString("utf8");
};