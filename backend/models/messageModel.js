const mongoose = require("mongoose");
const messageSchema = mongoose.Schema(
  {
    sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    content: { type: String, trim: true, required: true },
    iv: { type: String, required: true },
    encryptedSessionKey: { type: String, required: true },
    chat: { type: mongoose.Schema.Types.ObjectId, ref: "Chat", required: true },
    readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  },
  { timestamps: true });
const Message = mongoose.model("Message", messageSchema);
module.exports = Message;