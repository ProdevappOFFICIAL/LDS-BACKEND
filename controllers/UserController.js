import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import UserModel from "../models/UserModel.js";

export const register = async (req, res) => {
  const { name, email, password, organization } = req.body;

  // Validate required fields
  if (!name || !email || !password || !organization) {
    return res.status(400).json({ 
      success: false, 
      message: "All fields are required",
      error: "Missing details" 
    });
  }

  // Basic email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      success: false,
      message: "Please enter a valid email address",
      error: "Invalid email format"
    });
  }

  // Password length validation
  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      message: "Password must be at least 6 characters long",
      error: "Password too short"
    });
  }

  try {
    // Check if user already exists using schema static method
    const existingUser = await UserModel.findByEmail(email);

    if (existingUser) {
      return res.status(409).json({ 
        success: false, 
        message: "An account with this email already exists. Please sign in instead.",
        error: "User already exists" 
      });
    }

    // Create new user - password will be hashed automatically by pre-save middleware
    const user = new UserModel({ 
      name: name.trim(), 
      email: email.toLowerCase().trim(), 
      password: password, // Will be hashed by pre-save middleware
      organization: organization.trim()
    });
    
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user._id,
        email: user.email,
        name: user.name
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    // Set HTTP-only cookie
    res.cookie("token", token, {
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Send success response with token (for frontend localStorage)
    res.status(201).json({ 
      success: true,
      message: "Account created successfully",
      token: token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        organization: user.organization,
        subscription: user.subscription,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    
    // Handle mongoose validation errors
    if (error.name === 'ValidationError') {
      const validationErrors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        error: validationErrors.join(', ')
      });
    }

    // Handle duplicate key error
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists",
        error: "Duplicate email"
      });
    }

    res.status(500).json({ 
      success: false, 
      message: "Server error during registration. Please try again.",
      error: error.message 
    });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  // Validate required fields
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Email and password are required",
      error: "Missing credentials"
    });
  }

  try {
    // Find user by email - explicitly select password field
    const user = await UserModel.findOne({ email: email.toLowerCase() }).select('+password');

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found. Please check your email or sign up.",
        error: "User not found"
      });
    }

    // Check if account is locked
    if (user.isLocked) {
      return res.status(423).json({
        success: false,
        message: "Account is temporarily locked due to too many failed login attempts. Please try again later.",
        error: "Account locked"
      });
    }

    // Check if account is active
    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: "Account is deactivated. Please contact support.",
        error: "Account deactivated"
      });
    }

    // Use the schema's built-in comparePassword method
    const isMatchedPassword = await user.comparePassword(password);

    if (!isMatchedPassword) {
      // Increment login attempts for failed password
      await user.incLoginAttempts();
      
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials. Please check your email and password.",
        error: "Password mismatch"
      });
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();

    // Update last login time
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    // Set HTTP-only cookie
    res.cookie("token", token, {
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Send success response with token (for frontend localStorage)
    res.status(200).json({ 
      success: true,
      message: "Login successful",
      token: token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        organization: user.organization,
        subscription: user.subscription,
        role: user.role,
        lastLogin: user.lastLogin
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: "Server error during login. Please try again.",
      error: error.message 
    });
  }
};

export const logout = async (req, res) => {
  try {
    // Clear the HTTP-only cookie
    res.clearCookie("token", {
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
    });

    return res.status(200).json({ 
      success: true, 
      message: "User logged out successfully" 
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ 
      success: false, 
      message: "Error during logout",
      error: error.message 
    });
  }
};

// Middleware to verify JWT token
export const verifyToken = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Access denied. No token provided.",
        error: "No token"
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await UserModel.findById(decoded.id);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid token. User not found.",
        error: "Invalid token"
      });
    }

    // Check if user is still active
    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: "Account is deactivated",
        error: "Account inactive"
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: "Invalid token format",
        error: "Invalid token"
      });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: "Token has expired",
        error: "Token expired"
      });
    }
    res.status(401).json({
      success: false,
      message: "Token verification failed",
      error: error.message
    });
  }
};

// Get current user info (protected route)
export const getCurrentUser = async (req, res) => {
  try {
    // req.user is set by verifyToken middleware
    const user = await UserModel.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
        error: "User not found"
      });
    }

    res.status(200).json({
      success: true,
      message: "User data retrieved successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        organization: user.organization,
        subscription: user.subscription,
        role: user.role,
        department: user.department,
        location: user.location,
        phone: user.phone,
        emailVerified: user.emailVerified,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      message: "Server error while retrieving user data",
      error: error.message
    });
  }
};

// Verify token endpoint
export const verifyAuth = async (req, res) => {
  try {
    // req.user is set by verifyToken middleware
    const user = await UserModel.findById(req.user.id);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found",
        error: "Invalid token"
      });
    }

    res.status(200).json({
      success: true,
      message: "Token is valid",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        organization: user.organization,
        subscription: user.subscription,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Verify auth error:', error);
    res.status(401).json({
      success: false,
      message: "Token verification failed",
      error: error.message
    });
  }
};

// Refresh token function
export const refreshToken = async (req, res) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "No token provided for refresh",
        error: "No token"
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await UserModel.findById(decoded.id);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found",
        error: "Invalid token"
      });
    }

    // Check if user is still active
    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: "Account is deactivated",
        error: "Account inactive"
      });
    }

    // Generate new token
    const newToken = jwt.sign(
      { 
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    // Set new HTTP-only cookie
    res.cookie("token", newToken, {
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      success: true,
      message: "Token refreshed successfully",
      token: newToken
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({
      success: false,
      message: "Token refresh failed",
      error: error.message
    });
  }
};

// Check subscription access middleware
export const checkSubscriptionAccess = (requiredLevel) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
        error: "No user"
      });
    }

    if (!req.user.hasSubscriptionAccess(requiredLevel)) {
      return res.status(403).json({
        success: false,
        message: `This feature requires ${requiredLevel} subscription or higher`,
        error: "Insufficient subscription level"
      });
    }

    next();
  };
};

// Change password function
export const changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      message: "Current password and new password are required",
      error: "Missing passwords"
    });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({
      success: false,
      message: "New password must be at least 6 characters long",
      error: "Password too short"
    });
  }

  try {
    // Get user with password field
    const user = await UserModel.findById(req.user.id).select('+password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
        error: "User not found"
      });
    }

    // Verify current password
    const isCurrentPasswordValid = await user.comparePassword(currentPassword);

    if (!isCurrentPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Current password is incorrect",
        error: "Invalid current password"
      });
    }

    // Update password (pre-save middleware will hash it)
    user.password = newPassword;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Password changed successfully"
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: "Server error while changing password",
      error: error.message
    });
  }
};