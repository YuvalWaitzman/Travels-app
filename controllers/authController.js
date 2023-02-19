const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const AppError = require('./../utils/appError');
const catchAsync = require('../utils/catchAsync');

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create(
    // name: req.body.name,
    // email: req.body.email,
    // password: req.body.password,
    // passwordConfirm: req.body.passwordConfirm,
    // passwordChangedAt: req.body.passwordChangedAt,
    // role: 'user' || req.body.role,
    req.body
  );
  const token = signToken(newUser._id);
  res.status(201).json({
    status: 'success',
    token,
    data: {
      user: newUser,
    },
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  //check if email and password exist

  if (!email || !password) {
    const error = new AppError('Please provide email and password', 400);
    return next(error);
  }

  //check if the user exist && password is correct
  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    const error = new AppError('Incorrect email or password', 401);
    return next(error);
  }

  // send the token to the client
  const token = signToken(user._id);
  res.status(200).json({
    stauts: 'success',
    token,
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  let token;

  // Getting the token and check if it's exist
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    const error = new AppError(
      'You are not logged in! Please log in to get access '
    );
    return next(error, 401);
  }

  //Verification token

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  //Check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    const error = new AppError(
      'The user belonging to this token does not longer exist',
      401
    );
    return next(error);
  }

  //Check if user changed passwords after token was issued
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    const error = new AppError(
      'User recently changed password! Please log in again',
      401
    );
    return next(error);
  }

  //Grant access to protected route
  console.log(currentUser);
  req.user = currentUser;
  next();
});

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      const error = new AppError(
        "You don't have permission to perform this action",
        403
      );
      return next(error);
    }
    next();
  };
};
