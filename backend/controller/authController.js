import Joi from "joi";
import bcrypt from "bcryptjs";
import User from "../models/user.js";
import JWTservice from "../Services/JWTservices.js";
import RefreshToken from "../models/token.js";
import UserDTO from "../dto/userDto.js";
const passwordPattren =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[ -/:-@\[-`{-~]).{6,64}$/;
const controller = {
  //Register API
  async register(req, res, next) {
    //validate user input using Joi
    const userRegisterSchema = Joi.object({
      username: Joi.string().min(5).max(30).required(),
      name: Joi.string().max(30).required(),
      email: Joi.string().email().required(),
      password: Joi.string().pattern(passwordPattren).required(),
      confirmpassword: Joi.ref("password"),
    });
    //validate the userSchema
    const { error } = userRegisterSchema.validate(req.body);
    //if error occurs the middleWare will handle it
    if (error) {
      return next(error);
    }
    const { username, name, email, password } = req.body;
    //password hashing
    const hashedPassword = await bcrypt.hash(password, 10);
    //verify if email and  username is already registerd
    try {
      const emailInUse = await User.exists({ email });
      const usernameInUse = await User.exists({ username });
      if (emailInUse) {
        const error = {
          status: 409,
          message: "email is alredy in use please use anOther!!",
        };
        return next(error);
      }
      if (usernameInUse) {
        const error = {
          status: 409,
          message: "user is not available please choose anOther!!",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }
    //store to database
    let user;
    let accessToken;
    let refreshToken;
    try {
      const userToRegiser = new User({
        username,
        name,
        email,
        password: hashedPassword,
      });
      user = await userToRegiser.save();

      //genrate tokens
      accessToken = JWTservice.signAccessToken(
        { _id: user._id, username: user.username },
        "30m"
      );
      refreshToken = JWTservice.signRefreshToken(
        { _id: user._id, username: email },
        "60m"
      );
    } catch (error) {
      return next(error);
    }

    //store refresh token in database
    await JWTservice.storeRefreshToken(refreshToken, user._id);
    //sending tokens in cookies
    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    res.cookie("refreshToken", refreshToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    //sending response
    res.status(201).json({ user, auth: true });
  },

  //login API
  async login(req, res, next) {
    //validate user input using joi

    const userLoginSchema = Joi.object({
      username: Joi.string().min(5).max(30).required(),
      password: Joi.string().pattern(passwordPattren).required(),
    });
    //validate userLoginSchema
    const { error } = userLoginSchema.validate(req.body);
    //if error occurs the middleware will handle it
    if (error) {
      return next(error);
    }
    const { username, password } = req.body;
    //matching username and password
    let user;
    try {
      user = await User.findOne({ username });
      if (!user) {
        const error = {
          status: 401,
          message: "invalid username!!",
        };
        return next(error);
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        const error = {
          status: 401,
          message: "invalid password!!",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }

    const accessToken = JWTservice.signAccessToken({ _id: user._id }, "30m");
    const refreshToken = JWTservice.signRefreshToken({ _id: user._id }, "60m");

    //update database
    try {
      await RefreshToken.updateOne(
        {
          _id: user._id,
        },
        {
          token: refreshToken,
        },
        {
          upsert: true,
        }
      );
    } catch (error) {}

    //sending tokens to cookies
    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    res.cookie("refreshToken", refreshToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    //sending response
    const userDto = new UserDTO(user);
    res.status(200).json({ user: userDto, auth: true });
  },
};

export default controller;
