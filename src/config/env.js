import dotenv from "dotenv";
import {z} from "zod"
dotenv.config();
const envSchema = z.object({
   NODE_ENV:z.enum(["development", "production", "test"]).default("development"),
    PORT:z.string().default("5000"),
    MONGO_URI: z.string().min(1),
    JWT_ACCESS_SECRET:z.string().min(32),
    JWT_ACCESS_EXPIRY:z.string().default("15m"),
    JWT_REFRESH_EXPIRY: z.string().default("30d"),
    CLIENT_URL: z.string().url(),
    SMTP_HOST: z.string().min(1),
    SMTP_PORT: z.string().default("587"),
    SMTP_USER: z.string().min(1),
    SMTP_PASS: z.string().min(1),
    EMAIL_FROM: z.string().min(1),
    EMAIL_VERIFICATION_EXPIRY: z.string().default("24h"),
    PASSWORD_RESET_EXPIRY: z.string(),
    APP_NAME:z.string().default("MyAuthApp"),
    JWT_TWO_FACTOR_SECRET:z.string().min(32),
    GOOGLE_CLIENT_ID: z.string().min(1),
    GOOGLE_CLIENT_SECRET: z.string().min(1),
    GOOGLE_CALLBACK_URL: z.string().url(),
    TWO_FACTOR_ENCRYPTION_KEY:z.string().length(64)
});
const parsed = envSchema.safeParse(process.env);
if(!parsed.success){
    console.error("❌ Invalid environment variables:");
    console.error(parsed.error.format());
    process.exit(1);
}
export const nodeEnv = parsed.data.NODE_ENV;
export const port = parsed.data.PORT;
export const mongoUri = parsed.data.MONGO_URI;
export const seceretKey = parsed.data.JWT_ACCESS_SECRET;
export const accessExpiry = parsed.data.JWT_ACCESS_EXPIRY;
export const refreshExpiry = parsed.data.JWT_REFRESH_EXPIRY;
export const clientUrl = parsed.data.CLIENT_URL;
export const smtpHost = parsed.data.SMTP_HOST;
export const smtpPort = parsed.data.SMTP_PORT;
export const smtpUser = parsed.data.SMTP_USER;
export const smtpPass = parsed.data.SMTP_PASS;
export const emailFrom = parsed.data.EMAIL_FROM;
export const emailVerificationExpiry = parsed.data.EMAIL_VERIFICATION_EXPIRY;
export const passwordResetExpiryTime = parsed.data.PASSWORD_RESET_EXPIRY;
export const appName = parsed.data.APP_NAME;
export const twoFactorSecretCode = parsed.data.JWT_TWO_FACTOR_SECRET;
export const googleClientId = parsed.data.GOOGLE_CLIENT_ID;
export const googleClientSecret = parsed.data.GOOGLE_CLIENT_SECRET;
export const googleCallbackUrl = parsed.data.GOOGLE_CALLBACK_URL;
export const twoFactorEncryptionKey =parsed.data.TWO_FACTOR_ENCRYPTION_KEY;