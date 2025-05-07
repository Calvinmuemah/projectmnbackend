const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    default: 'user',
  },
  avatar: {
    type: String,
    default: 'https://i.pravatar.cc/150',
  },
  resetToken: String,
  resetTokenExpiry: Date, // or Number, depending on how you're storing time
});

const User = mongoose.model('User', userSchema);

module.exports = User;
