const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("./models/User");

app.use(express.json());

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("DB Connected");
  })
  .catch((e) => {
    console.error("error", e);
  });

const signAccessToken = (userid) => {
  console.log("Signing Access Token for userId: ", userid);
  console.log("JWT", process.env.JWT_SECRET);
  console.log("JWT_EXPIRES_IN", process.env.JWT_EXPIRES_IN);
  const token =  jwt.sign({ sub: userid }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
  console.log("token generated", token);
  return token;
};

const requireAuth = (req, res, next) => {
    try{

        const token = req.headers.token;
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        const userid = payload.sub;
        req.userid = userid;
        return next();
    }
    catch(error)
    {
        
        return res.status(401).json({error: "Invalid Token"})
    }

}

app.post("/register", async (req, res) => {
  try {
    const { email, name, password } = req.body;
    if (!email || !name || !password) {
      return res
        .status(400)
        .json({ error: "email or password or name is missing" });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ error: "User already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 1);

    const user = await User.create({ email, name, passwordHash });
    if (user) {
      return res.status(201).json({ isReg: true });
    } else {
      return res.status(400).json({ error: "model validations failed" });
    }
  } catch (error) {
    return res.status(500).json({ error });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "email or password is missing" });
    }
    const user = await User.findOne({ email });

    if (!user) {
      res.status(400).json({ error: "email doesnt match our records" });
    }
    console.log("User found");
    console.log(user);

    const isPasswordMatch = await bcrypt.compare(password, user.passwordHash);
    if (isPasswordMatch) {
      // User is Authenticated
      console.log("User Authenticated");
      const token = signAccessToken(user._id);
      return res.json({ token });
    } else {
      return res.status(404).json({ error: "password wrong" });
    }
  } catch (error) {
    return res.status(500).json({ exp: error });
  }
});

app.get("/me", requireAuth, async (req, res)=>{
  const user = await User.findById(req.userid).select("id email name createdAt")

  return res.status(200).json({
    status: "ok",
    data: {user}
  })
})

app.listen(process.env.PORT,  () => {
  console.log("App is runnning in: ", process.env.PORT);
});
