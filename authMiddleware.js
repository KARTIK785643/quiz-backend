const jwt = require("jsonwebtoken");
const User = require("../models/User");
require("dotenv").config();

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header("Authorization");
    if (!token) {
      return res.status(401).json({ message: "Access Denied! No Token Provided." });
    }

    // Decode Token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Fetch user by email from database
    const user = await User.findOne({ email: decoded.email }).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User Not Found in Database!" });
    }

    req.user = user; // Store user data in request
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or Expired Token!" });
  }
};

module.exports = authMiddleware;
