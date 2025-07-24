import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    tokenHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: "7d" },
});

export default mongoose.model("Session", sessionSchema);
