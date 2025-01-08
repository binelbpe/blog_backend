// Custom error class for API errors
class APIError extends Error {
  constructor(message, statusCode, errors = {}) {
    super(message);
    this.statusCode = statusCode;
    this.errors = errors;
    this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
  }
}

// Error handler middleware
const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || "error";

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern)[0];
    err.statusCode = 400;
    err.message = "Duplicate field value";
    err.errors = {
      [field]: `This ${field} is already taken`,
    };
  }

  // Mongoose validation error
  if (err.name === "ValidationError") {
    err.statusCode = 400;
    err.message = "Invalid input data";
    err.errors = Object.keys(err.errors).reduce((acc, key) => {
      acc[key] = err.errors[key].message;
      return acc;
    }, {});
  }

  // JWT errors
  if (err.name === "JsonWebTokenError") {
    err.statusCode = 401;
    err.message = "Invalid token. Please log in again";
  }

  if (err.name === "TokenExpiredError") {
    err.statusCode = 401;
    err.message = "Your token has expired. Please log in again";
  }

  // Development error response
  if (process.env.NODE_ENV === "development") {
    return res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
      errors: err.errors,
      stack: err.stack,
      error: err,
    });
  }

  // Production error response
  return res.status(err.statusCode).json({
    status: err.status,
    message: err.message,
    errors: err.errors,
  });
};

module.exports = {
  APIError,
  errorHandler,
};
