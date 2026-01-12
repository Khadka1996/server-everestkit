import crypto from 'crypto';

export class EncryptionService {
  static algorithm = 'aes-256-gcm';
  
  static deriveKey(secret) {
    return crypto.scryptSync(secret, 'salt', 32);
  }
  
  static encrypt(text, documentId) {
    const key = this.deriveKey(process.env.ENCRYPTION_KEY);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipher(this.algorithm, key);
    cipher.setAAD(Buffer.from(documentId));
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      iv: iv.toString('hex'),
      content: encrypted,
      authTag: authTag.toString('hex')
    };
  }
  
  static decrypt(encryptedData, documentId) {
    try {
      const key = this.deriveKey(process.env.ENCRYPTION_KEY);
      const decipher = crypto.createDecipher(this.algorithm, key);
      
      decipher.setAAD(Buffer.from(documentId));
      decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
      
      let decrypted = decipher.update(encryptedData.content, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }
  
  static encryptForStorage(text, documentId) {
    const encrypted = this.encrypt(text, documentId);
    return `${encrypted.iv}:${encrypted.content}:${encrypted.authTag}`;
  }
  
  static decryptFromStorage(encryptedText, documentId) {
    const parts = encryptedText.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted text format');
    }
    
    return this.decrypt({
      iv: parts[0],
      content: parts[1],
      authTag: parts[2]
    }, documentId);
  }
}