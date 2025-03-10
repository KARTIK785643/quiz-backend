const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

require("dotenv").config();


const app = express();
// Initialize Express app
app.use(express.static(path.join(__dirname, "build")));


// Extract environment variables with defaults
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || "your-mongodb-atlas-connection-string";
const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

// Middleware setup
app.use(express.json());
app.use(bodyParser.json());
app.use(cors({ 
  origin: FRONTEND_URL, 
  credentials: true ,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));



// Quiz Schema (Move this to models/Quiz.js if needed)
const quizSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  questions: [{
    question: { type: String, required: true },
    options: { type: [String], required: true },
    correctAnswer: { type: String, required: true },
  }],
  createdAt: { type: Date, default: Date.now }
}, { collection: "quizzes" });

// Only create the model if it doesn't already exist
const Quiz = mongoose.models.Quiz || mongoose.model("Quiz", quizSchema);

// Auth Middleware (Move this to middleware/authMiddleware.js if needed)
const authMiddleware = (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
      return res.status(401).json({ error: "No token, authorization denied" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error("Auth middleware error:", error.message);
    res.status(401).json({ error: "Token is not valid" });
  }
};

// Root route to provide basic information
app.get("/", (req, res) => {
  res.json({
    message: "Quiz API server is running",
    endpoints: {
      auth: ["/register", "/login", "/profile"],
      quizzes: ["/api/quizzes", "/api/quizzes/:id", "/api/quizzes/:id/link"],
      system: ["/health"]
    }
  });
});

// Database Connection
console.log("Attempting to connect to MongoDB...");
mongoose.set("strictQuery", false);
mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000 // Increase timeout to 5 seconds

  })
  .then(() => {
    console.log("✅ MongoDB connected successfully");
    app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);
// Register Route
// Register Route
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required!" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered!" });
    }

    // Hash password before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save new user
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Error saving user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
  app.post("/login", async (req, res) => {
    try {
      const { email, password } = req.body;
      console.log("Login attempt:", email); // Debugging log
  
      const user = await User.findOne({ email });
      if (!user) {
        console.log("❌ User not found in DB");
        return res.status(400).json({ error: "Invalid Credentials!" });
      }
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        console.log("❌ Password does not match");
        return res.status(400).json({ error: "Invalid Credentials!" });
      }
  
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
      
      console.log("✅ Login Successful");
      res.json({ message: "✅ Login Successful!", token });
    } catch (error) {
      console.error("❌ Error logging in:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });
  

// PROFILE API
app.get("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("username email");
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ user });
  } catch (error) {
    console.error("Error fetching profile:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// QUIZ APIs
// Get all quizzes
app.get("/api/quizzes", async (req, res) => {
  try {
    const quizzes = await Quiz.find().sort({ createdAt: -1 });
    res.json(quizzes);
  } catch (error) {
    console.error("Error fetching quizzes:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Get quiz by ID
app.get("/api/quizzes/:id", async (req, res) => {
  try {
    const quiz = await Quiz.findById(req.params.id);
    if (!quiz) {
      return res.status(404).json({ message: "Quiz not found" });
    }
    res.json(quiz);
  } catch (error) {
    console.error("Error fetching quiz:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Create quiz - REMOVED authMiddleware for development
app.post("/api/quizzes", async (req, res) => {
  try {
    const newQuiz = new Quiz(req.body);
    const savedQuiz = await newQuiz.save();
    res.status(201).json(savedQuiz);
  } catch (error) {
    console.error("Error creating quiz:", error);
    res.status(400).json({ message: error.message });
  }
});

// Update quiz - REMOVED authMiddleware for development
app.put("/api/quizzes/:id", async (req, res) => {
  try {
    const updatedQuiz = await Quiz.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!updatedQuiz) {
      return res.status(404).json({ message: "Quiz not found" });
    }
    
    res.json(updatedQuiz);
  } catch (error) {
    console.error("Error updating quiz:", error);
    res.status(400).json({ message: error.message });
  }
});

// Delete quiz - REMOVED authMiddleware for development
app.delete("/api/quizzes/:id", async (req, res) => {
  try {
    const deletedQuiz = await Quiz.findByIdAndDelete(req.params.id);
    
    if (!deletedQuiz) {
      return res.status(404).json({ message: "Quiz not found" });
    }
    
    res.json({ message: "✅ Quiz deleted successfully" });
  } catch (error) {
    console.error("Error deleting quiz:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Generate Quiz Link
app.get("/api/quizzes/:id/link", (req, res) => {
  const quizId = req.params.id;
  res.json({ link: `${FRONTEND_URL}/quiz/${quizId}` });
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ 
    status: "UP", 
    db: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected"
  });
});

// Add debug endpoint to check if server is running
app.get("/api/health", (req, res) => {
  res.status(200).json({ 
    status: "UP", 
    db: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected",
    message: "Server is running correctly"
  });
});

// Server startup function
function startServer() {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 API available at http://localhost:${PORT}`);
    console.log(`🔍 Health check at http://localhost:${PORT}/health`);
  });
}

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
  console.error("❌ Uncaught Exception:", error);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
  console.error("❌ Unhandled Rejection at:", promise, "reason:", reason);
  process.exit(1);
});
// Authentication middleware with Bearer token support
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }
  
  // Handle both "Bearer {token}" format and plain token format
  const token = authHeader.startsWith('Bearer ') 
    ? authHeader.substring(7) // Remove "Bearer " prefix
    : authHeader;
  
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ message: 'Invalid token.' });
  }
};
// Get user profile (protected route)
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});
module.exports = app;