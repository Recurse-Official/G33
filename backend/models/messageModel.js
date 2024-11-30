const mongoose = require("mongoose");

const messageSchema = mongoose.Schema(
  {
    sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    content: { type: String, trim: true, required: true }, // Encrypted message content
    iv: { type: String, required: true }, // Initialization vector for AES
    encryptedSessionKey: { type: String, required: true }, // Encrypted AES session key
    chat: { type: mongoose.Schema.Types.ObjectId, ref: "Chat", required: true },
    readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // Users who have read this message
  },
  { timestamps: true } // Automatically manage createdAt and updatedAt fields
);

const Message = mongoose.model("Message", messageSchema);
module.exports = Message;
