// /servercrypto.js (Daha Sağlam Hata Kontrolü ile Güncellendi)
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

function getServerSecretKey() {
    if (!SERVER_SECRET_KEY) {
        throw new Error("SERVER_SECRET_KEY henüz ayarlanmadı. Vault'un önce başlatıldığından emin olun.");
    }
    return SERVER_SECRET_KEY;
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
    // ✅ GÜNCELLEME: Girişin null, undefined veya geçerli bir string olup olmadığını kontrol et
    if (!encryptedPointer || typeof encryptedPointer !== 'string') {
        // Bu bir hata değil, beklenen bir durum olabilir, bu yüzden sessizce null dön.
        return null;
    }
    
    if (!SERVER_SECRET_KEY) { 
        console.error("!!! decryptPointer: SERVER_SECRET_KEY hazır değil!"); 
        return null; 
    }

    try {
        // Bu kontrol artık güvenli çünkü encryptedPointer'ın bir string olduğunu biliyoruz.
        if (!encryptedPointer.startsWith('v1$')) {
            // Hatalı formatlı veriyi logla ama çökme.
            console.warn(`[Crypto] Bilinmeyen işaretçi versiyonu, atlanıyor: ${encryptedPointer.substring(0, 10)}...`);
            return null;
        }
        
        const parts = encryptedPointer.slice(3).split(':');
        if (parts.length !== 3) {
            console.warn(`[Crypto] Hatalı işaretçi yapısı, atlanıyor.`);
            return null;
        }

        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encryptedText = parts[2];
        const decipher = crypto.createDecipheriv(ALGORITHM, SERVER_SECRET_KEY, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) { 
        console.error("İşaretçi çözülürken kritik hata:", error.message); 
        return null; 
    }
}

function pointerFingerprint(publicKey) {
    if (!SERVER_SECRET_KEY) { console.error("!!! pointerFingerprint: SERVER_SECRET_KEY hazır değil!"); return null; }
    return crypto.createHmac('sha256', SERVER_SECRET_KEY).update(publicKey).digest('hex');
}

module.exports = {
    setServerSecretKey,
    getServerSecretKey,
    setFPEMasterKey,
    getFPEMasterKey,
    createMasterKey,
    encryptPointer,
    decryptPointer,
    pointerFingerprint,
};
