import express from "express";
import cookieParser from "cookie-parser";
import authRoute from "./routes/auth.routes.js";
import passport from "./config/passport.js"
import rateLimit from "express-rate-limit";
const globalRateLimit = rateLimit({
    windowMs:15 * 60 * 1000,
    max:"100",
    standardHeaders:true,
    legacyHeaders:false
})
const app = express();


app.use(cookieParser())
app.use(express.json());
app.use(passport.initialize());
app.use("/api/auth", globalRateLimit);
app.use("/api/auth",authRoute)
export default app;
