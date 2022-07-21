const crypto = require("crypto");

class RSAEncryption {
  constructor(settings, env) {
    this.env = env || "local";
    const [publicKey, privateKey] = this.loadKeys(settings);
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  static generateKeys() {
    // The `generateKeyPairSync` method accepts two arguments:
    // 1. The type ok keys we want, which in this case is "rsa"
    // 2. An object with the properties of the key
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 530,
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: "",
      },
    });

    return {
      publicKey,
      privateKey,
    };
  }

  loadKeys(settings = {}) {
    const defaultSettings = {
      publicKeyProvider: null,
      privateKeyProvider: null,
    };
    settings = { ...defaultSettings, ...settings };

    const keys = ["publicKey", "privateKey"].map((path) => {
      return settings?.[path];
    });

    return keys;
  }

  encrypt(data) {
    if (!this.publicKey) throw new Error("No public key");

    if (typeof data !== "string") {
      data = JSON.stringify(data);
    }

    const encryptedData = crypto.publicEncrypt(
      this.publicKey,
      // We convert the data string to a buffer using `Buffer.from`
      Buffer.from(data)
    );

    // The encrypted data is in the form of bytes, so we print it in base64 format
    // so that it's displayed in a more readable form
    return encryptedData.toString("base64");
  }

  decrypt(data) {
    if (!this.privateKey) throw new Error("No private key");

    const encryptedData = Buffer.from(data, "base64");
    const decryptedData = crypto.privateDecrypt(
      { key: this.privateKey, passphrase: "" },
      encryptedData
    );

    // The decrypted data is of the Buffer type, which we can convert to a
    // string to reveal the original data
    const decrypted = decryptedData.toString();
    try {
      return JSON.parse(decrypted);
    } catch (error) {
      return decrypted;
    }
  }
}

module.exports = RSAEncryption;
