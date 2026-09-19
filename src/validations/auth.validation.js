import { z } from "zod";

export const signUpSchema = z.object({
    name:z.string().min(1,"Name is required"),
    email:z.string().email("Invalid email address"),
    password:z.string().min(8,"Password must be at least 8 characters").max(72, "Password must be under 72 characters"),
    dob: z.string().optional()
});

export const loginSchema = z.object({
    email:z.string().email("Invalid email address"),
    password:z.string().min(1,"Password is required").max(72, "Password must be under 72 characters"),
});

export const resetPasswordSchema = z.object({
    newPassword:z.string().min(8,"Password must be at least 8 characters").max(72, "Password must be under 72 characters"),
});
export const forgetPasswordSchema = z.object({
    email:z.string().email("Invalid email address"),
});

export const changePasswordSchema = z.object({
    currentPassword:z.string().min(1,"Current Password required").max(72, "Password must be under 72 characters"),
    newPassword:z.string().min(8,"Password must be at least 8 characters").max(72, "Password must be under 72 characters"),
});

export const regenerateBackupCodeSchema = z.object({
    currentPassword:z.string().min(1,"Current Password required").max(72, "Password must be under 72 characters"),
});

export const disable2faSchema = z.object({
    currentPassword:z.string().min(1,"Current Password required").max(72, "Password must be under 72 characters"),
});

export const twoFactorCodeSchema = z.object({
  token: z.string().min(6, "Code must be 6 digits").max(6, "Code must be 6 digits"),
});

export const twoFactorLoginSchema = z.object({
  twoFactorToken: z.string().min(1, "Token is required"),
  code: z.string().min(6, "Code must be 6 digits").max(6, "Code must be 6 digits"),
});

