const bcrypt = require("bcryptjs");
const User = require("../models/User");
const tokenUtils = require("../utils/tokenUtils");
const { APIError } = require("../utils/errorHandler");

// Register User
exports.register = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    console.log('Registration attempt:', { username, email, hasPassword: !!password });

    if (!username || !email || !password) {
      return res.status(400).json({ 
        message: "All fields are required",
        errors: {
          username: !username ? "Username is required" : "",
          email: !email ? "Email is required" : "",
          password: !password ? "Password is required" : "",
        }
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username }],
    });

    if (existingUser) {
      if (existingUser.email === email.toLowerCase()) {
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

    // Create new user
    const user = new User({
      username,
      email: email.toLowerCase(),
      password, // Password will be hashed by the pre-save middleware
    });

    console.log('Saving user with password:', { hasPassword: !!user.password });
    await user.save();
    console.log('User saved successfully');

    // Generate tokens
    const tokens = await tokenUtils.generateTokens(user._id);

    res.status(201).json({
      status: "success",
      message: "User registered successfully",
      data: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
        }
      }
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ 
      status: "error",
      message: "Internal server error" 
    });
  }
};

// Login User
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    console.log('Login attempt for:', { email, hasPassword: !!password });

    if (!email || !password) {
      throw new APIError("All fields are required", 400, {
        email: !email ? "Email is required" : "",
        password: !password ? "Password is required" : "",
      });
    }

    // Find user with password field
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    console.log('User lookup result:', { 
      found: !!user, 
      hasPassword: !!user?.password,
      email 
    });

    if (!user) {
      throw new APIError("Authentication failed", 401, {
        email: "Invalid email or password",
      });
    }

    // Check password
    const isValidPassword = await user.comparePassword(password);
    console.log('Password validation:', { isValid: isValidPassword });

    if (!isValidPassword) {
      throw new APIError("Authentication failed", 401, {
        password: "Invalid email or password",
      });
    }

    // Generate tokens
    const tokens = await tokenUtils.generateTokens(user._id);

    const response = {
      status: "success",
      message: "Login successful",
      data: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
        }
      }
    };

    return res.json(response);
  } catch (error) {
    console.error('Login error:', {
      message: error.message,
      stack: error.stack,
      errors: error.errors
    });
    return next(error);
  }
};

// Refresh Token
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        status: "error",
        message: "Refresh token is required"
      });
    }

    const decoded = await tokenUtils.verifyRefreshToken(refreshToken);
    if (!decoded) {
      return res.status(401).json({
        status: "error",
        message: "Invalid refresh token"
      });
    }

    await tokenUtils.revokeRefreshToken(refreshToken);
    const tokens = await tokenUtils.generateTokens(decoded.userId);

    res.json({
      status: "success",
      message: "Tokens refreshed successfully",
      data: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken
      }
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(500).json({
      status: "error",
      message: "Failed to refresh token"
    });
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
