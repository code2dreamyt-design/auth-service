import ms from "ms";
import jwt from "jsonwebtoken";
import { accessExpiry, refreshExpiry, seceretKey } from "../config/env.js";
import crypto from "crypto"
import RefreshToken from "../models/RefreshToken.js";


export const generateAccessToken = (userId)=>{
    return jwt.sign({ sub: userId.toString() },seceretKey,{expiresIn:accessExpiry})
}

export const generateRawToken = ()=>{
  return  crypto.randomBytes(64).toString("hex");
}

export const hashToken = (rawToken)=>{
   return crypto.createHash("sha256").update(rawToken).digest("hex");
}

export const issueRefreshToken = async (userId,family,ip,userAgent)=>{
    try {
        const rawToken = generateRawToken();
        const hashedToken = hashToken(rawToken);
        if(!family || family.length===0) family = crypto.randomUUID();
        await RefreshToken.create({
            tokenHash:hashedToken,
            user:userId,
            family,
            createdByIp:ip,
            userAgent,
            expiresAt:new Date(Date.now()+ms(refreshExpiry))
        });
        return rawToken;
    } catch (error) { 
        console.log(error);
        throw new Error(`Failed to issue token:${error.message}`);
    }
}

export const rotateRefreshToken = async (rawToken,ip,userAgent)=>{

    try {
        const hashedToken = hashToken(rawToken);
        const oldTokenDoc = await RefreshToken.findOne({tokenHash:hashedToken});
        if(!oldTokenDoc) throw new Error("Invalid Refresh Token");
        
        if(oldTokenDoc.revoked){
            await RefreshToken.updateMany({family:oldTokenDoc.family},{revoked:true});
            throw new Error("Session invalidated — please log in again");
        };
        if(oldTokenDoc.expiresAt<new Date()){
            throw new Error("Refresh Token Expired — please log in again");
        }
        oldTokenDoc.revoked=true;
        await oldTokenDoc.save();
        const newRawToken = issueRefreshToken(oldTokenDoc.user,oldTokenDoc.family,ip,userAgent);
        return { rawToken: newRawToken, userId: oldTokenDoc.user };
    } catch (error) {
        console.log(error);
        throw new Error(`Failed to Refresh token:${error.message}`);
    }
}

export const verifyAccessToken = (token)=>{
    const payload =  jwt.verify(token,seceretKey);
    return payload;
}