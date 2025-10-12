// /public/signal-client.js (YENİ DOSYA)
// Bu dosya, libsignal-protocol kütüphanesi ile ilgili tüm karmaşık işlemleri yönetir.

// libsignal-protocol kütüphanesini import ediyoruz. Bu, HTML dosyasında script olarak eklenmeli.
const { KeyHelper, SignalProtocolAddress, SessionBuilder, SessionCipher } = libsignal;

// ArrayBuffer'ı Base64 string'e çeviren yardımcı fonksiyon
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Base64 string'i ArrayBuffer'a çeviren yardımcı fonksiyon
function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// libsignal'in ihtiyaç duyduğu depolama arayüzünü localStorage kullanarak oluşturuyoruz.
// Bu, kütüphanenin anahtarları ve oturumları tarayıcıda güvenli bir şekilde saklamasını sağlar.
class SignalProtocolStore {
    constructor() {
        this.store = window.localStorage;
    }
    put(key, value) {
        if (key === undefined || value === undefined || key === null || value === null)
            throw new Error("Invalid key or value");
        this.store.setItem(key, JSON.stringify(value));
    }
    get(key, defaultValue) {
        if (key === null || key === undefined)
            throw new Error("Invalid key");
        const value = this.store.getItem(key);
        if (value === null) {
            return defaultValue;
        }
        return JSON.parse(value);
    }
    remove(key) {
        if (key === null || key === undefined)
            throw new Error("Invalid key");
        this.store.removeItem(key);
    }
    async getIdentityKeyPair() {
        const kp = this.get('identityKey');
        if (kp) {
            return {
                pubKey: base64ToArrayBuffer(kp.pubKey),
                privKey: base64ToArrayBuffer(kp.privKey),
            };
        }
        return null;
    }
    async getLocalRegistrationId() {
        return this.get('registrationId');
    }
    async isTrustedIdentity(identifier, identityKey, _direction) {
        if (identifier === null || identifier === undefined) {
            throw new Error("identifier is null or undefined");
        }
        if (!(identityKey instanceof ArrayBuffer)) {
            throw new Error("identityKey is not an ArrayBuffer");
        }
        const trusted = this.get('identityKey' + identifier);
        if (trusted === undefined) {
            return true;
        }
        return arrayBufferToBase64(identityKey) === trusted;
    }
    async loadPreKey(keyId) {
        let res = this.get('25519KeypreKey' + keyId);
        if (res) {
            res = {
                pubKey: base64ToArrayBuffer(res.pubKey),
                privKey: base64ToArrayBuffer(res.privKey),
            };
        }
        return res;
    }
    async loadSession(identifier) {
        const session = this.get('session' + identifier);
        if (session) return session;
        return undefined;
    }
    async loadSignedPreKey(keyId) {
        let res = this.get('25519KeysignedKey' + keyId);
        if (res) {
            res = {
                pubKey: base64ToArrayBuffer(res.pubKey),
                privKey: base64ToArrayBuffer(res.privKey),
            };
        }
        return res;
    }
    async removePreKey(keyId) { this.remove('25519KeypreKey' + keyId); }
    async removeSession(identifier) { this.remove('session' + identifier); }
    async removeSignedPreKey(keyId) { this.remove('25519KeysignedKey' + keyId); }
    async saveIdentity(identifier, identityKey) {
        if (identifier === null || identifier === undefined)
            throw new Error("identifier is null or undefined");
        const address = new SignalProtocolAddress.fromString(identifier);
        const existing = this.get('identityKey' + address.getName());
        this.put('identityKey' + address.getName(), arrayBufferToBase64(identityKey));
        return existing && arrayBufferToBase64(identityKey) !== existing;
    }
    async storePreKey(keyId, keyPair) { this.put('25519KeypreKey' + keyId, { pubKey: arrayBufferToBase64(keyPair.pubKey), privKey: arrayBufferToBase64(keyPair.privKey) }); }
    async storeSession(identifier, record) { return this.put('session' + identifier, record); }
    async storeSignedPreKey(keyId, keyPair) { this.put('25519KeysignedKey' + keyId, { pubKey: arrayBufferToBase64(keyPair.pubKey), privKey: arrayBufferToBase64(keyPair.privKey) }); }
    async getOurIdentity() {
        const identityKeyPair = await this.getIdentityKeyPair();
        return identityKeyPair.pubKey;
    }
}

// Yeni bir Signal kimliği ve anahtar demeti oluşturur.
export async function generateIdentity() {
    const store = new SignalProtocolStore();
    const registrationId = KeyHelper.generateRegistrationId();
    store.put('registrationId', registrationId);

    const identityKeyPair = await KeyHelper.generateIdentityKeyPair();
    store.put('identityKey', {
        pubKey: arrayBufferToBase64(identityKeyPair.pubKey),
        privKey: arrayBufferToBase64(identityKeyPair.privKey),
    });

    const preKey = await KeyHelper.generatePreKey(1);
    store.storePreKey(1, preKey.keyPair);

    const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, 1);
    store.storeSignedPreKey(1, signedPreKey.keyPair);
    
    // Sunucuya gönderilecek anahtar demetini oluştur
    const publicSignedPreKey = {
        keyId: 1,
        publicKey: arrayBufferToBase64(signedPreKey.keyPair.pubKey),
        signature: arrayBufferToBase64(signedPreKey.signature),
    };

    const publicPreKey = {
        keyId: 1,
        publicKey: arrayBufferToBase64(preKey.keyPair.pubKey),
    };

    return {
        registrationId: registrationId,
        identityKey: arrayBufferToBase64(identityKeyPair.pubKey),
        signedPreKey: publicSignedPreKey,
        preKey: publicPreKey,
    };
}
