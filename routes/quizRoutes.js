const express = require('express');
const { generateQuiz,submitQuizResults, getUserProgress } = require('../controllers/quizController');

const router = express.Router();

router.post('/generate-quiz', generateQuiz);
router.post('/submit-results', submitQuizResults); // New route for submitting results
router.get('/progress/:userId', getUserProgress); // New route for getting user progress
// router.get('/user-progress/:userId', getUserProgress);

module.exports = router;
