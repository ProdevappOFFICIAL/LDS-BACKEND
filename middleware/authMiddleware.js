// middleware/authMiddleware.js

import jwt from 'jsonwebtoken';

const authenticateToken = (req, res, next) => {
  try {
    console.log('Auth middleware called');
    
    // Get token from header
    const authHeader = req.headers['authorization'];
    console.log('Auth header:', authHeader);
    
    if (!authHeader) {
      return res.status(401).json({ 
        error: 'Access denied',
        message: 'No authorization header provided' 
      });
    }

    // Extract token from "Bearer TOKEN" format
    const token = authHeader.startsWith('Bearer ') 
      ? authHeader.slice(7) 
      : authHeader;
    
    if (!token) {
      return res.status(401).json({ 
        error: 'Access denied',
        message: 'No token provided' 
      });
    }

    console.log('Token found:', token.substring(0, 20) + '...');

    // Verify token
    const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        console.log('Token verification error:', err.message);
        
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({ 
            error: 'Token expired',
            message: 'Please sign in again' 
          });
        }
        
        if (err.name === 'JsonWebTokenError') {
          return res.status(401).json({ 
            error: 'Invalid token',
            message: 'Please sign in again' 
          });
        }
        
        return res.status(401).json({ 
          error: 'Token verification failed',
          message: 'Please sign in again' 
        });
      }

      console.log('Token decoded successfully:', decoded);
      
      // Set user data on request object
      req.user = decoded;
      
      // Ensure user has an ID field
      if (!req.user.id && req.user._id) {
        req.user.id = req.user._id;
      }
      
      console.log('req.user set to:', req.user);
      next();
    });

  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Authentication failed' 
    });
  }
};

// Optional: Middleware for optional authentication (doesn't fail if no token)
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  
  if (!authHeader) {
    req.user = null;
    return next();
  }

  authenticateToken(req, res, next);
};

export { authenticateToken, optionalAuth };