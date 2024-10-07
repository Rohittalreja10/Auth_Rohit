const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  dob: {
    type: Date,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    validate: {
      validator: function (v) {
        return /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(v);
      },
      message: props => `${props.value} is not a valid email address!`,
    },
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    validate: {
      validator: function (v) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/.test(v);
      },
      message: props => 'Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one digit, and one special character!',
    },
  },
  profile: {
    type: String,
    default: "",
  },
  phone: {
    type: String, 
    validate: {
      validator: function (v) {
        return /^\d{10}$/.test(v); 
      },
      message: props => `${props.value} is not a valid phone number! It must be a 10-digit number.`,
    },
  }
}, {
  timestamps: true, 
});

const User = mongoose.model('User', userSchema, 'Auth_rohit');

module.exports = User;
