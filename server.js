import http from "http";
import express from "express";
import app from "./src/app.js";
import connectDB from "./src/config/db.js";

connectDB();
const server =  http.createServer(app);


server.listen(3000,()=>{
    console.log("Server is running at PORT : 3000")
})