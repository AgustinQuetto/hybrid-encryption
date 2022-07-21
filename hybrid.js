function encrypt(data, RSAEncryption, AESEncryption) {
  const pass = AESEncryption.generateRandomPassword();
  const encText = AESEncryption.encrypt(data, pass);
  const passwordEncryptedWithRSA = RSAEncryption.encrypt(pass);
  return `${passwordEncryptedWithRSA};${encText}`;
}

function decrypt(request, RSAEncryption, AESEncryption) {
  const [AESPassword, data] = request.split(";");
  const decryptedPassword = RSAEncryption.decrypt(AESPassword);
  const dataDecrypted = AESEncryption.decrypt(data, decryptedPassword);
  return dataDecrypted;
}

module.exports = { encrypt, decrypt };
