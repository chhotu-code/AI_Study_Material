const { GoogleGenerativeAI } = require("@google/generative-ai");
const UserResult = require("../models/userResult"); // Import the UserResult model
const User = require("../models/userModel");

// Initialize Google Generative AI
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

const generateQuiz = async (req, res) => {
  const { topic, questionType, questionLevel } = req.body;

  // Ensure all necessary fields are provided
  if (!topic || !questionType || !questionLevel) {
    return res.status(400).json({
      message: "Topic, questionType, and questionLevel are required.",
    });
  }

  // Define the prompt with the difficulty level
  let prompt = `Generate 2 ${questionType} questions on the topic of "${topic}" with a difficulty level of "${questionLevel}". Each question should have 4 options and one correct answer and provide the answer key. Don't generate anything else except question, option, and answer. Generate this type of response: '**1. What is the capital of France?',
  '    1) Paris',
  '    2) London',
  '    3) Rome',
  '    4) Berlin',
  '    Answer: Paris',`;

  // Customize the prompt based on question type
  if (questionType === "MCQ") {
    prompt += " Each question should have 4 options and one correct answer.";
  } else if (questionType === "Short Answer") {
    prompt += " Each question should require a short answer response.";
  } else if (questionType === "One Word") {
    prompt += " Each question should require a one-word response.";
  }

  try {
    // Generate content from the AI model using the constructed prompt
    const result = await model.generateContent(prompt);
    const questions = result.response.text().split("\n"); // Adjust based on actual response format
    res.json({ questions });
  } catch (error) {
    console.error("Error generating quiz:", error.message);
    res.status(500).json({
      message: "An error occurred while generating the quiz.",
      error: error.message,
    });
  }
};

// Submit quiz results
const submitQuizResults = async (req, res) => {
  console.log(req.body); // Log the request body for debugging

  const { userId, topic, quizResults } = req.body;

  if (!userId || !topic || !quizResults) {
    return res
      .status(400)
      .json({ message: "User ID, topic, and quiz results are required." });
  }

  const score = quizResults.filter((result) => result.isCorrect).length;

  try {
    const newResult = new UserResult({ userId, topic, score, quizResults }); // Include topic here
    await newResult.save();
    res.status(201).json({ message: "Results saved successfully.", score });
  } catch (error) {
    console.error("Error saving results:", error.message);
    res.status(500).json({
      message: "An error occurred while saving results.",
      error: error.message,
    });
  }
};
// Get user progress
const getUserProgress = async (req, res) => {
  const { userId } = req.params;

  try {
    const results = await UserResult.find({ userId }).populate(
      "userId",
      "username"
    ); // Populate with user info
    res.json(results);
  } catch (error) {
    console.error("Error fetching user progress:", error.message);
    res.status(500).json({
      message: "An error occurred while fetching progress.",
      error: error.message,
    });
  }
};

// Exporting the functions
module.exports = {
  generateQuiz,
  submitQuizResults,
  getUserProgress,
};
