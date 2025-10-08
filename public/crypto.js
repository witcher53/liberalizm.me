// Bu dosya, tüm istemci taraflı şifreleme mantığını içerir.

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
        console.error('decryptKey failed:', e.message);
        throw new Error("Şifre çözme başarısız — yanlış şifre veya bozuk veri.");
    }
}
