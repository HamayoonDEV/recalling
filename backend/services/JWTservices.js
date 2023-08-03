import jwt from "jsonwebtoken";
import { ACCESS_TOKEN_STRING, REFRESH_TOKEN_STRING } from "../config/index.js";
import RefreshToken from "../models/token.js";

class JWTservice {
  //signAccessToken
  static signAccessToken(payload, expiryTime) {
    return jwt.sign(payload, ACCESS_TOKEN_STRING, { expiresIn: expiryTime });
  }
  //signRefreshToken
  static signRefreshToken(payload, expiryTime) {
    return jwt.sign(payload, REFRESH_TOKEN_STRING, { expiresIn: expiryTime });
  }
  //verifyAccessToken
  static verifyAccessToken(token) {
    return jwt.verify(token, ACCESS_TOKEN_STRING);
  }
  //verifyRefreshToken
  static verifyRefreshToken(token) {
    return jwt.verify(Token, REFRESH_TOKEN_STRING);
  }
  //store Refresh Token
  static async storeRefreshToken(token, userId) {
    try {
      const newToken = await RefreshToken({
        token: token,
        userId: userId,
      });
      newToken.save();
    } catch (error) {
      console.log(error);
    }
  }
}

export default JWTservice;
