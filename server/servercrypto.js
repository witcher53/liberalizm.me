// /servercrypto.js (Düzeltilmiş)
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const KEY_LENGTH = 32;

let SERVER_SECRET_KEY = null;
let FPE_MASTER_KEY = null;

function setServerSecretKey(keyBuffer) {
    if (keyBuffer && keyBuffer.length === KEY_LENGTH) {
        SERVER_SECRET_KEY = keyBuffer;
    } else {
        throw new Error("Geçersiz SERVER_SECRET_KEY uzunluğu.");
    }
}

function setFPEMasterKey(key) {
    FPE_MASTER_KEY = key;
}

function getFPEMasterKey() {
    return FPE_MASTER_KEY;
}

function createMasterKey(keyInput) { 
    return crypto.createHash('sha256').update(keyInput).digest(); 
}

function encryptPointer(publicKey) {
    if (!SERVER_SECRET_KEY) { console.error("!!! encryptPointer: SERVER_SECRET_KEY hazır değil!"); return null; }
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, SERVER_SECRET_KEY, iv);
    let encrypted = cipher.update(publicKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `v1$${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

function decryptPointer(encryptedPointer) {
    if (!SERVER_SECRET_KEY) { console.error("!!! decryptPointer: SERVER_SECRET_KEY hazır değil!"); return null; }
    try {
        if (!encryptedPointer.startsWith('v1$')) throw new Error('Unknown pointer version');
        const parts = encryptedPointer.slice(3).split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encryptedText = parts[2];
        const decipher = crypto.createDecipheriv(ALGORITHM, SERVER_SECRET_KEY, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) { console.error("İşaretçi çözülürken hata:", error); return null; }
}

function pointerFingerprint(publicKey) {
    if (!SERVER_SECRET_KEY) { console.error("!!! pointerFingerprint: SERVER_SECRET_KEY hazır değil!"); return null; }
    return crypto.createHmac('sha256', SERVER_SECRET_KEY).update(publicKey).digest('hex');
}

module.exports = {
    setServerSecretKey,
    setFPEMasterKey,
    getFPEMasterKey,
    createMasterKey,
    encryptPointer,
    decryptPointer,
    pointerFingerprint,
};
