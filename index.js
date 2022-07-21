const RSAEncryption = require("./rsa");
const AESEncryption = require("./aes");
const HybridEncryption = require("./hybrid");
const data = require("./data.json");
const fs = require("fs");

const RSAKeysGenerated = RSAEncryption.generateKeys();
fs.writeFileSync("./keys/public.key", RSAKeysGenerated.publicKey);
fs.writeFileSync("./keys/private.key", RSAKeysGenerated.privateKey);

const publicKey = fs.readFileSync("./keys/public.key");
const privateKey = fs.readFileSync("./keys/private.key");

const settings = {
  publicKey,
  privateKey,
};

const RSAEncryptionInstance = new RSAEncryption(settings);

const AESEncryptionInstance = new AESEncryption();
const text = JSON.stringify(data);

const encryptedRequest = HybridEncryption.encrypt(
  text,
  RSAEncryptionInstance,
  AESEncryptionInstance
);

console.log("Encrypted data:", encryptedRequest);

const decryptedRequest = HybridEncryption.decrypt(
  encryptedRequest,
  RSAEncryptionInstance,
  AESEncryptionInstance
);

console.log("Decrypted data:", decryptedRequest);
