// /public/crypto.js (NİHAİ SÜRÜM - Shared Secret Hata Düzeltmesi)
export async function deriveKey(password, salt) {
    if (password.length < 8) throw new Error('En az 8 karakterli bir şifre gerekli.');
    if (sodium && typeof sodium.crypto_pwhash === 'function') {
        return sodium.crypto_pwhash(32, password, salt, sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE, sodium.crypto_pwhash_ALG_DEFAULT);
    }
    console.warn("Fallback KDF: PBKDF2 (WebCrypto)");
    const enc = new TextEncoder();
    const pwKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: 150000 }, pwKey, 256);
    return new Uint8Array(derivedBits);
}

export async function encryptKey(keyBase64, password, salt) {
    const derivedKey = await deriveKey(password, salt);
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const keyBuffer = sodium.from_base64(keyBase64);
    const encryptedKey = sodium.crypto_secretbox_easy(keyBuffer, nonce, derivedKey);
    return sodium.to_base64(nonce) + '::' + sodium.to_base64(encryptedKey);
}

export async function decryptKey(encryptedString, password, salt) {
    const derivedKey = await deriveKey(password, salt);
    const parts = (typeof encryptedString === 'string' ? encryptedString : '').split('::');
    if (parts.length !== 2) throw new Error("Anahtar formatı bozuk.");
    try {
        const nonceBytes = sodium.from_base64(parts[0]);
        const encryptedBytes = sodium.from_base64(parts[1]);
        const decryptedKeyBuffer = sodium.crypto_secretbox_open_easy(encryptedBytes, nonceBytes, derivedKey);
        return sodium.to_base64(decryptedKeyBuffer);
    } catch (e) {
        console.error('Anahtar şifresi çözülemedi. Lütfen şifrenizi kontrol edin.'); // Genel hata mesajı
        throw new Error("Şifre çözme başarısız — yanlış şifre veya bozuk veri.");
    }
}

/**
 * İki kullanıcının anahtarlarını kullanarak her iki tarafta da aynı olacak Ortak Gizli Kodu (Shared Secret) hesaplar.
 * @param {string} keyA_base64 - Kullanıcı A'nın Genel Anahtarı (Base64).
 * @param {string} keyB_base64 - Kullanıcı B'nin Genel Anahtarı (Base64).
 * @returns {string} Okunabilir Ortak Gizli Kod (Örn: XX:XX:XX:XX:...)
 */
export function generateSharedSecret(keyA_base64, keyB_base64) {
    // 1. Anahtarları Base64 dizesi olarak karşılaştırıp sıralayarak deterministik (aynı) sırayı sağla.
    const sortedKeys = [keyA_base64, keyB_base64].sort();
    const combinedKeyString = sortedKeys[0] + sortedKeys[1];
    
    // 2. Birleştirilmiş anahtar dizesini Uint8Array'e dönüştür.
    const combinedKeyBytes = new TextEncoder().encode(combinedKeyString);

    // 3. SHA-256 hash'ini hesapla.
    const hashBytes = sodium.crypto_hash_sha256(combinedKeyBytes);

    // 4. Hash'i HEX dizesine dönüştür.
    const hashHex = sodium.to_hex(hashBytes);

    // 5. Okunabilirlik için 4 karakterde bir iki nokta üst üste ekle.
    const fingerprint = hashHex.match(/.{1,4}/g).join(':').toUpperCase();

    // İlk 8 bloğu (39 karakter) kullanıyoruz.
    return fingerprint.substring(0, 39); 
}