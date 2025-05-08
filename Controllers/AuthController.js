const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../Models/User');
const { validationResult } = require('express-validator');
const nodemailer = require("nodemailer");
require('dotenv').config();


// Register
const register = async (req, res) => {
  const { name, email, password } = req.body;

  // Validate inputs
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Check if the user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    // Generate token
    const payload = { userId: newUser._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Send response with safe user data
    res.status(201).json({
      token,
      user: {
        _id: newUser._id,
        name: newUser.name,
        email: newUser.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Login
const login = async (req, res) => {
  const { email, password } = req.body;

  // Validate inputs
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Generate token
    const payload = { userId: user._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Send response with safe user data
    res.status(200).json({
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Forgot Password
const forgotPassword = async (req, res) => {
  const { email } = req.body;

  // 1. Validate inputs
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // 2. Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "No user found with this email." });
    }

    // 3. Generate a JWT reset token (expires in 15 minutes)
    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    // 4. Save the token and expiry in DB
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 15 * 60 * 1000;
    await user.save();

    // 5. Create reset password link
    const resetLink = `${process.env.CLIENT_URL}reset_password/${resetToken}`;

    // 6. Setup email transport
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // 7. Send email
    const mailOptions = {
      from: `"Project Management Team" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset Request",
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2>Hi ${user.name || "User"},</h2>
          <p>You requested a password reset for your account.</p>
          <p><a href="${resetLink}" style="background:#007bff;color:white;padding:10px 15px;text-decoration:none;border-radius:5px;">Reset Password</a></p>
          <p>If the button doesn't work, copy and paste this URL in your browser:</p>
          <p><a href="${resetLink}">${resetLink}</a></p>
          <p>If you did not request this, please ignore this email.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    // 8. Respond success
    res.status(200).json({ message: "Password reset link sent to your email." });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ message: "Internal server error. Please try again later." });
  }
};

// Reset Password
const reset_password = async (req, res) => {
  const { token, password } = req.body;

  // Validate inputs
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Verify token
    console.log('Verifying token...');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    console.log("Decoded user ID:", decoded.id);

    const user = await User.findById(decoded.id);  // Find the user by ID

    if (!user) {
      console.log('User not found');
      return res.status(400).json({ error: "User not found." });
    }

    console.log("Provided token:", token);
    console.log("Stored resetToken:", user.resetToken);
    console.log("Stored expiry:", user.resetTokenExpiry);
    console.log("Current time:", Date.now());

    if (
      user.resetToken !== token ||
      !user.resetTokenExpiry ||
      user.resetTokenExpiry < Date.now()
    ) {
      console.log('Token is invalid or expired');
      return res.status(400).json({ error: "Invalid or expired token." });
    }

    // Hash and update password
    console.log('Hashing password...');
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    console.log('Password reset successful');
    res.status(200).json({ message: 'Password has been reset successfully. You can now log in.' });
  } catch (error) {
    console.error('Error during password reset:', error);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
};



// Verify Reset Token
const verify_reset_token = async (req, res) => {
  const { token } = req.params;

  try {
    if (!token) {
      return res.status(400).json({ error: "No token provided." });
    }

    // Decode the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    // Check user and token validity
    if (!user || user.resetToken !== token || user.resetTokenExpiry < Date.now()) {
      return res.status(400).json({ error: "Invalid or expired token." });
    }

    res.status(200).json({ valid: true, message: "Token is valid." });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ error: "Reset token has expired." });
    }
    console.error("Token verification failed:", error);
    res.status(400).json({ error: "Invalid or expired token." });
  }
};

const updateProfile = async (req, res) => {
  try {
    const userId = req.user; // Using req.user directly, as it contains the user ID
    const { name, email, avatar, password } = req.body;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (name) user.name = name;
    if (email) user.email = email;
    if (avatar) user.avatar = avatar;

    if (password) {
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
    }

    await user.save();

    const userResponse = user.toObject();
    delete userResponse.password;

    res.json(userResponse);
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};



module.exports = { register, login, forgotPassword, reset_password, verify_reset_token, updateProfile };
