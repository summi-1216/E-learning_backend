import { User } from "../models/user.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sendMail, { sendForgotMail } from "../middlewares/sendMail.js";
import TryCatch from "../middlewares/tryCatch.js";

//-------------------------------------register user----------------------------------------------
export const register = TryCatch(async (req, res) => {
  const { name, email, role, password } = req.body;

  let user = await User.findOne({ email });

  if (user)
    return res.status(400).json({
      message: "User Already Exists",
    });

  const hashpassword = await bcrypt.hash(password, 10);
  user = {
    name,
    email,
    role,
    password: hashpassword,
  };

  const otp = Math.floor(Math.random() * 1000000);

  const activationToken = jwt.sign(
    {
      user,
      otp,
    },
    process.env.ACTIVATION_SECRET,
    {
      expiresIn: "5m",
    }
  );

  const data = {
    name,
    otp,
  };

  await sendMail(email, "E Learning", data);

  res.status(200).json({
    message: "otp sent to your mail",
    activationToken,
  });
});

//-----------------------------------verify user-----------------------------------------------
export const verifyUser = TryCatch(async (req, res) => {
  const { otp, activationToken } = req.body;

  const verify = jwt.verify(activationToken, process.env.ACTIVATION_SECRET);

  if (!verify) {
    return res.status(400).json({
      message: "Otp Expired",
    });
  }
  if (verify.otp !== otp) {
    return res.status(400).json({
      message: "Wrong Otp",
    });
  }

  await User.create({
    name: verify.user.name,
    email: verify.user.email,
    password: verify.user.password,
    role : verify.user.role,
  });

  res.json({
    message: "User Registered.",
  });
});

//--------------------------login user-------------------------------------------------------------

export const loginUser = TryCatch(async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user)
    return res.status(400).json({
      message: "No user exists with this EmailId",
    });

  //---------------------------------------matching password---------------------------------------------
  const mathPassword = await bcrypt.compare(password, user.password);

  if (!mathPassword)
    return res.status(400).json({
      message: "Wrong Password",
    });

  const token = jwt.sign({ _id: user._id }, process.env.JWT_SEC, {
    expiresIn: "15d",
  });

  res.json({
    message: `Welcome back ${user.name}`,
    token,
    user,
  });
});

//-----------------------------------------------------profile---------------------------------------

export const myProfile = TryCatch(async (req, res) => {
  const user = await User.findById(req.user._id);

  res.json({ user });
});

//-----------------------------------------------forgot password--------------------------------------------

export const forgotPassword = TryCatch(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({
      message: " No user with this email ",
    });
  }
  const token = jwt.sign({ email }, process.env.FORGOT_SECRET);

  const data = { email, token };

  await sendForgotMail("SkillWave", data);

  user.resetPasswordExpire = Date.now() + 5 * 60 * 1000;

  await user.save();

  res.json({
    message: "Reset password link is send to your mail",
  });
});

export const resetPassword = TryCatch(async (req, res) => {
  const decodedData = jwt.verify(req.query.token, process.env.FORGOT_SECRET);

  const user = await User.findOne({ email: decodeddData.email });
  if (!user)
    return res.status(404).json({
      message: "No user with this email",
    });

  if (user.resetPasswordExpire === null)
    {return res.status(400).json({
      message: "Token Expired",
    });}

    if(user.resetPasswordExpire < Date.now())
     { return res.status(400).json({
        message: "Token Expired",
      });}

      const password = await bcrypt.hash(req.body.password, 10)

      user.password = password

      user.resetPasswordExpire = null;

      await user.save();

      res.json({
        message:"Password Reset"
      })
  
});
