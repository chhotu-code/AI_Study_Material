const User = require('../models/userModel'); // Import the User model
const bcrypt = require('bcrypt'); // Import bcrypt
const jwt = require('jsonwebtoken'); // Import jsonwebtoken

const SECRET_KEY = process.env.SECRET_KEY; // Ensure you have this set in your .env file

// Register new user
const userCreate = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = await User.create({
      email,
      password: hashedPassword
    });

    res.status(201).json({ success: true, user: newUser });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ success: false, message: 'An error occurred during registration.' });
  }
};

// Login user
const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (!existingUser) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    // Compare passwords
    const passwordMatch = await bcrypt.compare(password, existingUser.password);
    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: 'Invalid password.' });
    }

    // Generate token
    const token = jwt.sign(
      { email: existingUser.email, id: existingUser._id },
      SECRET_KEY,
      { expiresIn: '1h' } // Token expiration time
    );

    // Send response with user data and token
    res.status(200).json({ success: true, user: existingUser, token });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'An error occurred during login.' });
  }
};

module.exports = { userCreate, login };
