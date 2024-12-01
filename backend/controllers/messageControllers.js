const asyncHandler = require("express-async-handler");
const Message = require("../models/messageModel");
const User = require("../models/userModel");
const Chat = require("../models/chatModel");
const { encryptMessage, decryptMessage } = require("../utils/encryption");

// Get all Messages
const allMessages = asyncHandler(async (req, res) => {
  try {
    const messages = await Message.find({ chat: req.params.chatId })
      .populate("sender", "name pic email")
      .populate("chat");

    // Decrypt each message
    const decryptedMessages = messages.map((message) => {
      const encryptedData = {
        ciphertext: message.content,
        iv: message.iv,
        encryptedSessionKey: message.encryptedSessionKey,
      };
      const decryptedContent = decryptMessage(encryptedData);
      return { ...message._doc, content: decryptedContent };
    });

    res.json(decryptedMessages);
  } catch (error) {
    res.status(400);
    throw new Error("Failed to retrieve messages");
  }
});

// Create New Message
const sendMessage = asyncHandler(async (req, res) => {
  const { content, chatId } = req.body;

  if (!content || !chatId) {
    console.error("Invalid data passed into request");
    return res.sendStatus(400);
  }

  try {
    // Encrypt the message content
    const encryptedData = encryptMessage(content);

    const newMessage = {
      sender: req.user._id,
      content: encryptedData.ciphertext,
      iv: encryptedData.iv,
      encryptedSessionKey: encryptedData.encryptedSessionKey,
      chat: chatId,
    };

    let message = await Message.create(newMessage);

    message = await message.populate("sender", "name pic").execPopulate();
    message = await message.populate("chat").execPopulate();
    message = await User.populate(message, {
      path: "chat.users",
      select: "name pic email",
    });

    await Chat.findByIdAndUpdate(chatId, { latestMessage: message });

    res.json(message);
  } catch (error) {
    res.status(400);
    throw new Error("Failed to send message");
  }
});

module.exports = { allMessages, sendMessage };
