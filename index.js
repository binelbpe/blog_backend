const express = require("express");
const mongoose = require("mongoose");
const security = require("./middleware/security");
const { errorHandler } = require("./utils/errorHandler");
require("dotenv").config();

const app = express();

// Security Middleware
app.use(security.helmet);
app.use(security.customSecurity);
app.use(security.cors);
app.use(express.json({ limit: "10kb" }));
app.use(security.mongoSanitize);
app.use(security.xss);
app.use(security.hpp);
app.use("/api/", security.limiter);
app.use("/api/auth/", security.authLimiter);

// Routes
app.use("/api/auth", require("./routes/auth"));
app.use("/api/blogs", require("./routes/blog"));

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: "fail",
    message: "Route not found",
  });
});

// Error handler middleware
app.use(errorHandler);

// Enhanced MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    autoIndex: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

mongoose.connection.on("error", (err) => {
  console.error("MongoDB error:", err);
});

// Graceful shutdown handlers
process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

function gracefulShutdown() {
  console.log(
    "Received shutdown signal. Closing HTTP server and MongoDB connection..."
  );

  // Close MongoDB connection
  mongoose.connection.close(false, () => {
    console.log("MongoDB connection closed.");

    // Close HTTP server
    server.close(() => {
      console.log("HTTP server closed.");
      process.exit(0);
    });
  });

  // Force close after 10s
  setTimeout(() => {
    console.error(
      "Could not close connections in time, forcefully shutting down"
    );
    process.exit(1);
  }, 10000);
}

// Start server
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Unhandled promise rejections
process.on("unhandledRejection", (err) => {
  console.error("UNHANDLED REJECTION! 💥 Shutting down...");
  console.error(err);

  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT EXCEPTION! 💥 Shutting down...");
  console.error(err);
  process.exit(1);
});

module.exports = app;
