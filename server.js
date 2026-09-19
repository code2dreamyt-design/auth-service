import http from "http";
import app from "./src/app.js";
import connectDB from "./src/config/db.js";
import { port } from "./src/config/env.js";

connectDB();
const server =  http.createServer(app);


server.listen(port,()=>{
    console.log(`Server is running at PORT : ${port}`)
})