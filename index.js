import express from "express";
import dotenv from "dotenv";
// import cors from "cors";
import mongoose from "mongoose";
import router from "./routes/user.js";
import taskRouter from "./routes/task.js";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import path from "path";

dotenv.config();

async function main() {
  await mongoose.connect(process.env.MONGO_URL);
  console.log("database connected");
}

main().catch((error) => console.log(error));

const server = express();

// const corsOptions = {
//   origin: "http://localhost:3000", // Replace with your frontend URL
//   credentials: true, // Allow cookies to be sent and received
// };

server.use(express.static(path.resolve('build')));
// Add Helmet for security
server.use(helmet());
// server.use(cors(corsOptions));
// server.use(cors());
server.use(cookieParser());
server.use(express.json());
server.use("/auth", router);
server.use("/tasks", taskRouter);

server.listen(process.env.PORT, () => {
  console.log("server started");
});
