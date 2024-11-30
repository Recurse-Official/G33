const crypto = require("crypto");

// Generate RSA keys (pre-generated for production)
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

// Encrypt message
function encryptMessage(message) {
  try {
    // Generate AES session key and IV
    const sessionKey = crypto.randomBytes(32); // AES-256 requires 32 bytes
    const iv = crypto.randomBytes(16); // AES-CBC IV size

    // Encrypt the message with AES
    const cipher = crypto.createCipheriv("aes-256-cbc", sessionKey, iv);
    let encryptedMessage = cipher.update(message, "utf8", "base64");
    encryptedMessage += cipher.final("base64");

    // Encrypt the session key with RSA
    const encryptedSessionKey = crypto.publicEncrypt(publicKey, sessionKey);

    return {
      ciphertext: encryptedMessage,
      iv: iv.toString("base64"),
      encryptedSessionKey: encryptedSessionKey.toString("base64"),
    };
  } catch (error) {
    console.error("Encryption failed:", error.message);
    throw new Error("Encryption failed");
  }
}

// Decrypt message
function decryptMessage(encryptedData) {
  try {
    const { ciphertext, iv, encryptedSessionKey } = encryptedData;

    // Decrypt the session key using RSA
    const sessionKey = crypto.privateDecrypt(
      privateKey,
      Buffer.from(encryptedSessionKey, "base64")
    );

    // Decrypt the message using AES
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      sessionKey,
      Buffer.from(iv, "base64")
    );
    let decryptedMessage = decipher.update(ciphertext, "base64", "utf8");
    decryptedMessage += decipher.final("utf8");

    return decryptedMessage;
  } catch (error) {
    console.error("Decryption failed:", error.message);
    throw new Error("Decryption failed");
  }
}

module.exports = { encryptMessage, decryptMessage };
