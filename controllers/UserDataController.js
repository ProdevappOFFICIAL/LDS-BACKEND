import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import UserModel from "../models/UserModel.js";

const getCurrentUser = async (req, res) => {
  try {
    console.log('getCurrentUser called');
    console.log('req.user:', req.user);
    
    // Check if user is authenticated
    if (!req.user) {
      console.log('No user found in request');
      return res.status(401).json({ 
        error: 'Authentication required',
        message: 'Please provide a valid authentication token' 
      });
    }

    // Check if user ID exists
    if (!req.user.id && !req.user._id && !req.user.userId) {
      console.log('No user ID found in req.user:', req.user);
      return res.status(401).json({ 
        error: 'Invalid user data',
        message: 'User ID not found in authentication token' 
      });
    }

    // Get user ID (handle different field names)
    const userId = req.user.id || req.user._id || req.user.userId;
    console.log('User ID:', userId);

    // Fetch complete user data from database
    let user;
    
    try {
      // For MongoDB with Mongoose
      user = await UserModel.findById(userId).select('-password -__v');
      
      // For SQL databases, you would use something like:
      // const query = 'SELECT id, email, name, organization, role, created_at as createdAt, updated_at as updatedAt, is_active as isActive FROM users WHERE id = ?';
      // const result = await db.query(query, [userId]);
      // user = result[0];
      
    } catch (dbError) {
      console.error('Database query error:', dbError);
      return res.status(500).json({ 
        error: 'Database error',
        message: 'Failed to fetch user data from database' 
      });
    }

    if (!user) {
      console.log('User not found in database for ID:', userId);
      return res.status(404).json({ 
        error: 'User not found',
        message: 'User account no longer exists' 
      });
    }

    console.log('User found in database:', {
      id: user.id || user._id,
      email: user.email,
      name: user.name,
      organization: user.organization,
      hasOrganization: !!user.organization
    });

    // Prepare response data
    const userData = {
      id: user.id || user._id,
      email: user.email,
      name: user.name,
      organization: user.organization,
      subscription: user.subscription,
      role: user.role || 'user',
      createdAt: user.createdAt || user.created_at,
      updatedAt: user.updatedAt || user.updated_at,
      isActive: user.isActive !== false && user.is_active !== false,
      // Include any additional fields your User model has
      phone: user.phone,
      department: user.department,
      location: user.location
    };

    // Debug log to see what we're sending
    console.log('Sending user data:', userData);

    // Return user data
    res.status(200).json({
      success: true,
      user: userData
    });

  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to retrieve user information',
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
  }
};

export { getCurrentUser };