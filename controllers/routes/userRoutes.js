import express from 'express'
import { authenticateToken } from '../../middleware/authMiddleware.js';
import { getCurrentUser } from '../UserDataController.js';
import { changePassword } from '../UserController.js';

const userRouter = express.Router();

userRouter.get('/user',authenticateToken, getCurrentUser)
userRouter.get('/user/change-password',authenticateToken, changePassword)

export default userRouter