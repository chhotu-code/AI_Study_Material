const express = require('express');
const router = express.Router();
const { userCreate, login } = require('../controllers/authController'); // Ensure this path is correct

// Register route
router.post('/register', userCreate);

// Login route
router.post('/login', login);

module.exports = router;
