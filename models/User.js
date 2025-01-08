const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Username is required"],
      unique: true,
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: 6,
    },
  },
  {
    timestamps: true,
  }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    console.log('Comparing passwords:', {
      candidatePassword: candidatePassword.slice(0, 3) + '...',
      hashedPassword: this.password.slice(0, 10) + '...',
    });

    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    console.log('Password comparison result:', { isMatch });
    return isMatch;
  } catch (error) {
    console.error('Password comparison error:', error);
    throw error; // Let the error propagate to be handled by the controller
  }
};

module.exports = mongoose.model("User", userSchema);
