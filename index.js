import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import 'dotenv/config'
import ConnectDB from './config/mongodb.js'
import authRouter from './controllers/routes/authRoutes.js'
import userRouter from './controllers/routes/userRoutes.js'


const app =  express()
const port = process.env.PORT || 4000
ConnectDB();
app.use(
  cors({
    origin: "http://localhost:5173", // your Electron frontend URL
    credentials: true, // allow cookies and credentials
  })
);
app.use(cookieParser())
app.use(express.json())

app.get('/', (req , res)=> res.send('Api is working'))
app.use('/api/auth', authRouter);
app.use('/api/data', userRouter);
app.listen(port, ()=> console.log(`Server is running at ${port}`))


