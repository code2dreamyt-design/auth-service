import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: "Too many login attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

export const signupLimiter = rateLimit({
    windowMs:  60 * 60 * 1000,
    max:5,
    message:{message:"Too many signup attemptss, Please try again later"},
    standardHeaders:true,
    legacyHeaders:false
});

export const forgotPasswordLimiter = rateLimit({
    windowMs:  60 * 60 * 1000,
    max:5,
    message:{message:"Too many attemptss, Please try again later"},
    standardHeaders:true,
    legacyHeaders:false
});

export const resendLimiter = rateLimit({
    windowMs:  60 * 60 * 1000,
    max:5,
    message:{message:"Too many attemptss, Please try again later"},
    standardHeaders:true,
    legacyHeaders:false
});

export const twoFactorLimiter = rateLimit({
    windowMs:  15 * 60 * 1000,
    max:10,
    message:{message:"Too many attemptss, Please try again later"},
    standardHeaders:true,
    legacyHeaders:false
});