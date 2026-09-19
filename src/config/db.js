import mongoose from "mongoose";
import { mongoUri } from "./env.js";
const connectDB = async ()=>{
    try {
       await mongoose.connect(mongoUri);
       console.log("✅ MongoDB connected"); 
    } catch (error) {
       console.error("❌ MongoDB connection failed:", error.message);
    process.exit(1); // same fail-fast philosophy as env.js — don't run half-broken 
    }
}

export default connectDB;