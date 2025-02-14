import express from "express";
import limiter from "../config/rateLimit.js";
import {
  createTask,
  fetchTasks,
  deleteTask,
  updateTask,
} from "../controller/task.js";
import checkUserAuth from "../middleware/auth.js";

const router = express.Router();

router
  // Private route
  .post("/create", checkUserAuth, limiter, createTask)
  .get("/", checkUserAuth, limiter, fetchTasks)
  .delete("/delete/:id", checkUserAuth, limiter, deleteTask)
  .patch("/update/:id", checkUserAuth, limiter, updateTask);

export default router;
