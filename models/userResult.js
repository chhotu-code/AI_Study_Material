// models/UserResult.js
const mongoose = require("mongoose");

const UserResultSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "user", // Ensure you have a User model defined
  },
  topic: {
    type: String,
    required: true,
  },
  score: {
    type: Number,
    required: true,
  },
  quizResults: [
    {
      question: { type: String, required: true },
      userAnswer: { type: String, required: true },
      isCorrect: { type: Boolean, required: true },
    },
  ],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Create and export the UserResult model
module.exports = mongoose.model("UserResult", UserResultSchema);
