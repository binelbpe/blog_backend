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
  console.error('Error details:', err);

  err.statusCode = err.statusCode || 500;
  err.status = err.status || "error";

  // Development error response
  if (process.env.NODE_ENV === "development") {
    return res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
      errors: err.errors,
      stack: err.stack,
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
