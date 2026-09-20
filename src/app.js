import express from "express";
import cookieParser from "cookie-parser";
import authRoute from "./routes/auth.routes.js";
import passport from "./config/passport.js"
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import cors from "cors";
import hpp from "hpp";
import { clientUrl } from "./config/env.js";

const app = express();
if (nodeEnv === "production") {
  app.set("trust proxy", 1);
}
const globalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(helmet());
app.use(cors({ origin: clientUrl, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(hpp());
app.use(passport.initialize());
app.use("/api/auth", globalRateLimit);
app.use("/api/auth", authRoute);

export default app;
