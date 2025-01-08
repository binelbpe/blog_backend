const helmet = require("helmet");
const xss = require("xss-clean");
const mongoSanitize = require("express-mongo-sanitize");
const hpp = require("hpp");
const rateLimit = require("express-rate-limit");
const cors = require("cors");

// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
});

// Auth routes limiter
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 105,
  message: "Too many login attempts, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
});

const securityMiddleware = {
  // Basic security headers
  helmet: helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: [
          "'self'",
          process.env.FRONTEND_URL || "http://localhost:3000",
        ],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),

  // Prevent XSS attacks
  xss: xss(),

  // Sanitize MongoDB queries
  mongoSanitize: mongoSanitize({
    allowDots: true,
    replaceWith: "_",
  }),

  // Prevent HTTP Parameter Pollution
  hpp: hpp({
    whitelist: ["sort", "page", "limit"],
  }),

  // Rate limiting
  limiter,
  authLimiter,

  // CORS configuration
  cors: cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),

  // Custom security middleware
  customSecurity: (req, res, next) => {
    // Remove sensitive headers
    res.removeHeader("X-Powered-By");

    // Add security headers
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");

    next();
  },
};

module.exports = securityMiddleware;
