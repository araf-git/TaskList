import Joi from "joi";
import Task from "../model/task.js"; // Import Task model

// Create task
export const createTask = async (req, res) => {
  const taskSchema = Joi.object({
    title: Joi.string().min(3).required(),
    description: Joi.string().required(),
    completed: Joi.boolean().required(),
  });

  const { error } = taskSchema.validate(req.body);
  if (error) {
    return res
      .status(400)
      .json({ type: "error", message: error.details[0].message });
  }

  try {
    const { title, description, completed } = req.body;
    const userId = req.user.userID; // Use the full user object from JWT
    console.log(userId);
    const newTask = new Task({
      title,
      description,
      completed,
      userId, // Associate the task with the user
    });

    const savedTask = await newTask.save();

    return res.status(201).json({
      type: "success",
      message: "Task created successfully",
      task: savedTask,
    });
  } catch (error) {
    return res
      .status(500)
      .json({ type: "error", message: "Unable to create task" });
  }
};

export const fetchTasks = async (req, res) => {
  try {
    const userId = req.user.userID;
    const tasks = await Task.find({ userId }).exec();

    return res
      .status(200)
      .json({ type: "success", message: "Task's fetched successfully", tasks });
  } catch (error) {
    return res
      .status(500)
      .json({ type: "error", message: "Unable to fetch tasks" });
  }
};

// Delete task
export const deleteTask = async (req, res) => {
  const { id } = req.params;
  try {
    // const task = await Task.findOneAndDelete({ _id: id, userId: 1}); # this will give error cause the task id not owned by this 1 userId
    const task = await Task.findOneAndDelete({
      _id: id,
      userId: req.user.userID,
    });

    if (!task) {
      return res.status(404).json({ type: "error", message: "Task not found" });
    }

    return res
      .status(200)
      .json({ type: "success", message: "Task deleted successfully", id });
  } catch (error) {
    return res
      .status(500)
      .json({ type: "error", message: "Unable to delete task" });
  }
};

// Update task
export const updateTask = async (req, res) => {
  const { id } = req.params;
  const { title, description, completed } = req.body;

  try {
    const updatedTask = await Task.findOneAndUpdate(
      // { _id: id, userId: 1 },
      { _id: id, userId: req.user.userID },
      { title, description, completed },
      { new: true }
    );

    if (!updatedTask) {
      return res.status(404).json({ type: "error", message: "Task not found" });
    }

    return res.status(200).json({
      type: "success",
      message: "Task updated successfully",
      task: updatedTask,
    });
  } catch (error) {
    return res
      .status(500)
      .json({ type: "error", message: "Unable to update task" });
  }
};
