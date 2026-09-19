import User from "../models/User.js";
import { verifyAccessToken } from "../services/token.service.js";

export const authMiddleware = async (req, res, next) => {
  let accessToken = req.headers.authorization;
  accessToken = accessToken?.split(" ")[1];
  if (!accessToken) {
    return res.status(401).json({ message: "Not authenticated", code: "NO_TOKEN" });
  }

  let decoded;
  try {
    decoded = verifyAccessToken(accessToken);
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Access token expired", code: "TOKEN_EXPIRED" });
    }
    return res.status(401).json({ message: "Invalid token", code: "INVALID_TOKEN" });
  }

  try {
    const user = await User.findById(decoded.sub).select("passwordChangedAt");
    if (!user) {
      return res.status(401).json({ message: "User no longer exists", code: "INVALID_TOKEN" });
    }
    if (user.passwordChangedAt) {
      const changedTimestamp = Math.floor(user.passwordChangedAt.getTime() / 1000);
      if (changedTimestamp > decoded.iat) {
        return res.status(401).json({ message: "Password recently changed, please log in again", code: "INVALID_TOKEN" });
      }
    }
    req.userId = decoded.sub;
    next();
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};