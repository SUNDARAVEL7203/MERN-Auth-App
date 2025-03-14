import express from "express"
import cors from "cors";
import 'dotenv/config'
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";





const app = express();

const port = process.env.PORT || 5000

connectDB()

const allowedOrigins = ['http://localhost:5173']

app.use(express.json()) // All the requst will be sent in the expres

app.use(cookieParser());

app.use(cors({ origin: allowedOrigins, credentials: true}))// credintials true is give to send the cookies in response

app.get("/" , (req, res) => res.send("Welcome to MERN Auth Application"))
app.use("/api/auth", authRouter)
app.use("/api/user", userRouter)
app.listen(port, () => console.log(`Server started on PORT ${port}`))