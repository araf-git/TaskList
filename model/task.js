import mongoose from "mongoose";
const { Schema } = mongoose;

const taskSchema = new Schema(
  {
    title: { type: String, required: true, minlength: 3 },
    description: { type: String, required: true },
    completed: { type: Boolean, required: true },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    }, // Add user reference
  },
  { timestamps: true }
);

const virtual = taskSchema.virtual("id");
virtual.get(function () {
  return this._id;
});

taskSchema.set("toJSON", {
  virtuals: true,
  versionKey: false,
  transform: function (doc, ret) {
    delete ret._id;
    delete ret.updatedAt;
    delete ret.userId;
  },
});

const Task = mongoose.model("Task", taskSchema);
export default Task;
