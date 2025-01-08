const bcrypt = require("bcryptjs");
const User = require("../models/user");
const tokenUtils = require("../utils/tokenUtils");
const { APIError } = require("../utils/errorHandler");

// Register User
exports.register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({
          message: "Validation failed",
          errors: { email: "Email is already registered" },
        });
      }
      if (existingUser.username === username) {
        return res.status(400).json({
          message: "Validation failed",
          errors: { username: "Username is already taken" },
        });
      }
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
    });

    await user.save();

    const tokens = await tokenUtils.generateTokens(user._id);

    res.status(201).json({
      message: "User registered successfully",
      ...tokens,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Login User
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      throw new APIError("All fields are required", 400, {
        email: !email ? "Email is required" : "",
        password: !password ? "Password is required" : "",
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      throw new APIError("Authentication failed", 401, {
        email: "Invalid email or password",
        password: "Invalid email or password",
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      throw new APIError("Authentication failed", 401, {
        email: "Invalid email or password",
        password: "Invalid email or password",
      });
    }

    const tokens = await tokenUtils.generateTokens(user._id);

    res.json({
      status: "success",
      message: "Login successful",
      data: {
        ...tokens,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
        },
      },
    });
  } catch (error) {
    next(error);
  }
};

// Refresh Token
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token is required" });
    }

    const decoded = await tokenUtils.verifyRefreshToken(refreshToken);
    if (!decoded) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    await tokenUtils.revokeRefreshToken(refreshToken);

    const tokens = await tokenUtils.generateTokens(decoded.userId);

    res.json({
      message: "Tokens refreshed successfully",
      ...tokens,
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Logout
exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      await tokenUtils.revokeRefreshToken(refreshToken);
    }
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Logout from all devices
exports.logoutAll = async (req, res) => {
  try {
    const userId = req.user?.id;
    await tokenUtils.revokeAllUserTokens(userId);
    res.json({ message: "Logged out from all devices" });
  } catch (error) {
    console.error("Logout all error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Verify Token
exports.verify = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      throw new APIError("User not found", 404);
    }

    res.json({
      status: "success",
      data: {
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
        },
      },
    });
  } catch (error) {
    next(error);
  }
};
