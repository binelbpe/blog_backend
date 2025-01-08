const tokenUtils = require("../utils/tokenUtils");

const auth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "No token provided",
        details: "Authorization header must start with Bearer",
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = tokenUtils.verifyAccessToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "Invalid or expired token",
        details: "Token verification failed",
      });
    }

    req.user = { id: decoded.userId };
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    res.status(401).json({
      message: "Authentication failed",
      details: error.message,
    });
  }
};

module.exports = auth;
