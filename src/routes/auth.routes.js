import express from "express";
import {
  signup,
  login,
  refresh,
  logout,
  getMe,
  resendEmail,
  forgetPassword,
  resetPassword,
  changePassword,
  setupTwoFactor,
  verifyTwoFactorSetup,
  verifyTwoFactorlogin,
  regenerateBackupCodes,
  disableTwofactor,
  verifyEmail,
} from "../controllers/auth.controller.js";
import { authMiddleware } from "../middlewares/auth.middleware.js";
import passport from "../config/passport.js";
import { clientUrl, nodeEnv, refreshExpiry } from "../config/env.js";
import {
  generateAccessToken,
  issueRefreshToken,
} from "../services/token.service.js";
import ms from "ms";
import { forgotPasswordLimiter, loginLimiter, resendLimiter, signupLimiter, twoFactorLimiter } from "../middlewares/rateLimiter.js";
import { validate } from "../middlewares/validate.js";
import { changePasswordSchema, disable2faSchema, forgetPasswordSchema, loginSchema, regenerateBackupCodeSchema, resetPasswordSchema, signUpSchema, twoFactorCodeSchema, twoFactorLoginSchema } from "../validations/auth.validation.js";
const authRoute = express.Router();

authRoute.post("/signup",signupLimiter,validate(signUpSchema), signup);
authRoute.post("/login",loginLimiter,validate(loginSchema), login);
authRoute.post("/refresh", refresh);
authRoute.post("/logout", logout);
authRoute.get("/getme", authMiddleware, getMe);
authRoute.post("/resend",resendLimiter, authMiddleware, resendEmail);
authRoute.post("/verify-email/:token", authMiddleware, verifyEmail);
authRoute.post("/forget-password" ,validate(forgetPasswordSchema),forgotPasswordLimiter, forgetPassword);
authRoute.post("/reset-password/:rawPassResetToken" ,validate(resetPasswordSchema), resetPassword);
authRoute.post("/change-password" ,validate(changePasswordSchema), authMiddleware, changePassword);
authRoute.post("/2fa/setup", authMiddleware, setupTwoFactor);
authRoute.post("/2fa/verify-setup" ,validate(twoFactorCodeSchema), authMiddleware, verifyTwoFactorSetup);
authRoute.post("/2fa/verify-login" ,validate(twoFactorLoginSchema),twoFactorLimiter, verifyTwoFactorlogin);
authRoute.post(
  "/2fa/regenerate-backup-codes",
  validate(regenerateBackupCodeSchema),
  authMiddleware,
  regenerateBackupCodes,
);
authRoute.post("/2fa/disable-2fa",validate(disable2faSchema) ,authMiddleware, disableTwofactor);
authRoute.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
  }),
);

authRoute.get(
  "/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: `${clientUrl}/login?error=oauth_failed`,
  }),
  async (req, res) => {
    try {
      const user = req.user;
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

      return res.redirect(`${clientUrl}/oauth/success`);
    } catch (error) {
      console.log(error.message);
      return res.redirect(`${clientUrl}/login?error=server_error`);
    }
  }
);
export default authRoute;
