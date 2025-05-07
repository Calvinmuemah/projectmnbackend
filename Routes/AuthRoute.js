const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const { register, login, forgotPassword, reset_password, verify_reset_token } = require('../Controllers/AuthController');


// Register
router.post(
  '/register',
  [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ],
  register
);

// Login
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ],
  login
);

// Forgot Password
router.post(
  '/forgotPassword',
  [
    body('email').isEmail().withMessage('Valid email is required'),
  ],
  forgotPassword
);

// Reset Password
// Reset Password
router.post(
  '/reset_password',
  [
    body('token').notEmpty().withMessage('Reset token is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ],
  reset_password
);
// Verify Reset Token
router.get('/verify-reset-token/:token', verify_reset_token);


module.exports = router;
