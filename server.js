import express from 'express'
import dotenv from 'dotenv'
import morgan from 'morgan'
import cors from 'cors'
import helmet from 'helmet'
import { authenticateUser, asyncHandler, loginLimiter } from './middleware.js'
import {
	createUser,
	login,
	getUser,
	updateUser,
	deleteUser,
	refreshTokenHandler,
} from './route.js'

const app = express()
dotenv.config()
app.use(express.json({limit: '10kb'}))
app.use(morgan('dev'))
app.use(cors())
app.use(helmet())

// Public routes
app.post('/login', loginLimiter, asyncHandler(login))
app.post('/signup', asyncHandler(createUser))
app.post('/refresh', asyncHandler(refreshTokenHandler))

// Protected user routes
app.get('/users/:id', authenticateUser, asyncHandler(getUser))
app.put('/users/:id', authenticateUser, asyncHandler(updateUser))
app.delete('/users/:id', authenticateUser, asyncHandler(deleteUser))

const port = process.env.PORT || 3000
app.listen(port, () => console.log(`Server listening on ${port}`))