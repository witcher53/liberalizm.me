// /server/mlmp-onion.js (Her Mesaja Özel Anahtar Düzeltmesi)

const crypto = require('crypto');
const sodium = require('libsodium-wrappers');
const EventEmitter = require('events');
const Crypto = require('./servercrypto.js');

// ============================================
// LAYER 1: NESTED ONION ENCRYPTION
// ============================================
class OnionMetadataProtection {
    constructor() {
        this.currentEpoch = 0;
        this.ephemeralKeys = new Map();
        this.keyRotationTimer = null;
    }

    generateEpochKey(epoch) {
        if (this.ephemeralKeys.has(epoch)) {
            return this.ephemeralKeys.get(epoch);
        }
        const key = crypto.randomBytes(32);
        this.ephemeralKeys.set(epoch, key);
        if (this.ephemeralKeys.size > 2) {
            const oldestEpoch = Math.min(...this.ephemeralKeys.keys());
            this.ephemeralKeys.delete(oldestEpoch);
            console.log(`🔥 [Onion] Epoch ${oldestEpoch} key'i RAM'den silindi (forward secrecy)`);
        }
        return key;
    }

    // ✅ YENİ: Her mesaja özel anahtar türeten fonksiyon
    // Ana epoch anahtarını ve mesajın benzersiz nonce'unu kullanarak tek kullanımlık bir anahtar üretir.
    deriveMessageKey(epochKey, nonce) {
        return crypto.createHmac('sha256', epochKey)
            .update(nonce)
            .digest();
    }

    getCurrentEpoch() {
        const KEY_ROTATION_INTERVAL = 3600000;
        return Math.floor(Date.now() / KEY_ROTATION_INTERVAL);
    }

    async encryptMetadata(metadata, clientKey) {
        await sodium.ready;

        const epoch = this.getCurrentEpoch();
        let ciphertext = metadata;

        // Layer 1: Client-side encryption
        const layer1Nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
        const layer1Key = clientKey ? sodium.crypto_hash_sha256(clientKey) : this.deriveRoutingKey(epoch);
        ciphertext = sodium.to_base64(
            sodium.crypto_secretbox_easy(ciphertext, layer1Nonce, layer1Key)
        );
        const layer1 = `${sodium.to_base64(layer1Nonce)}:${ciphertext}`;

        // ✅ GÜNCELLEME: Layer 2 artık her mesaj için özel türetilmiş anahtar kullanıyor
        const epochKey = this.generateEpochKey(epoch); // Ana "fabrika" anahtarını al
        const layer2Nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES); // Mesaj için benzersiz nonce üret
        const layer2MessageKey = this.deriveMessageKey(epochKey, layer2Nonce); // Nonce'u kullanarak tek kullanımlık mini anahtar üret
        
        ciphertext = sodium.to_base64(
            sodium.crypto_secretbox_easy(layer1, layer2Nonce, layer2MessageKey) // Mini anahtarla şifrele
        );
        const layer2 = `${sodium.to_base64(layer2Nonce)}:${ciphertext}`;

        // Layer 3: Routing key (sunucu sadece bunu açabilir)
        const routingKey = this.deriveRoutingKey(epoch);
        const layer3Nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
        ciphertext = sodium.to_base64(
            sodium.crypto_secretbox_easy(layer2, layer3Nonce, routingKey)
        );
        const layer3 = `${sodium.to_base64(layer3Nonce)}:${ciphertext}`;

        return {
            onion: layer3,
            epoch: epoch,
            layers: 3
        };
    }

    async serverDecryptRouting(onionData) {
        await sodium.ready;
        const { onion, epoch } = onionData;
        const routingKey = this.deriveRoutingKey(epoch);
        try {
            const [nonceB64, cipherB64] = onion.split(':');
            const nonce = sodium.from_base64(nonceB64);
            const cipher = sodium.from_base64(cipherB64);
            const layer2 = sodium.to_string(
                sodium.crypto_secretbox_open_easy(cipher, nonce, routingKey)
            );
            return {
                routingInfo: this.extractRoutingInfo(layer2),
                encryptedPayload: layer2,
                epoch: epoch
            };
        } catch (e) {
            console.error('❌ [Onion] Routing decryption failed:', e.message);
            return null;
        }
    }

    deriveRoutingKey(epoch) {
        const SERVER_SECRET_KEY = Crypto.getServerSecretKey();
        const epochBytes = Buffer.from(epoch.toString());
        return crypto.createHmac('sha512', SERVER_SECRET_KEY)
            .update(epochBytes)
            .digest()
            .slice(0, 32);
    }

    extractRoutingInfo(encryptedPayload) {
        return crypto.createHash('sha256')
            .update(encryptedPayload)
            .digest('hex')
            .substring(0, 16);
    }

    startKeyRotation() {
        const KEY_ROTATION_INTERVAL = 3600000;
        this.keyRotationTimer = setInterval(() => {
            this.currentEpoch = this.getCurrentEpoch();
            console.log(`🔄 [Onion] Key rotation: New Epoch is ${this.currentEpoch}`);
            this.generateEpochKey(this.currentEpoch);
        }, KEY_ROTATION_INTERVAL);
        this.generateEpochKey(this.getCurrentEpoch());
    }

    stopKeyRotation() {
        if (this.keyRotationTimer) {
            clearInterval(this.keyRotationTimer);
        }
    }
}

// ... EphemeralKeyManager sınıfı ve module.exports kısmı aynı kalacak ...
// Not: EphemeralKeyManager sınıfı bu dosyada kalabilir, bir zararı yok. 
// OnionMetadataProtection sınıfı ondan bağımsız çalışıyor.

class EphemeralKeyManager extends EventEmitter {
    constructor(config = {}) {
        super();
        this.ROTATION_INTERVAL = config.rotationInterval || 3600000;
        this.MAX_KEY_AGE = config.maxKeyAge || 7200000;
        this.KEY_HISTORY_SIZE = config.keyHistorySize || 2;
        this.currentEpoch = this.calculateEpoch();
        this.keys = new Map();
        this.rotationTimer = null;
        this.cleanupTimer = null;
    }
    calculateEpoch(timestamp = Date.now()) { return Math.floor(timestamp / this.ROTATION_INTERVAL); }
    generateKey(epoch) {
        const now = Date.now();
        const key = crypto.randomBytes(32);
        this.keys.set(epoch, { key: key, createdAt: now, expiresAt: now + this.MAX_KEY_AGE, });
        console.log(`🔑 [Ephemeral] New key generated for epoch ${epoch}`);
        this.emit('keyGenerated', { epoch, timestamp: now });
        return key;
    }
    getKey(epoch = null) {
        const targetEpoch = epoch || this.currentEpoch;
        if (this.keys.has(targetEpoch)) {
            const keyData = this.keys.get(targetEpoch);
            if (Date.now() > keyData.expiresAt) {
                this.keys.delete(targetEpoch); return null;
            }
            return keyData.key;
        }
        return this.generateKey(targetEpoch);
    }
    rotate() {
        const oldEpoch = this.currentEpoch;
        this.currentEpoch = this.calculateEpoch();
        if (oldEpoch === this.currentEpoch) return;
        this.generateKey(this.currentEpoch);
        this.cleanup();
        this.emit('keyRotated', { oldEpoch, newEpoch: this.currentEpoch });
    }
    cleanup() {
        const now = Date.now();
        const minEpoch = this.currentEpoch - this.KEY_HISTORY_SIZE;
        for (const [epoch, keyData] of this.keys.entries()) {
            if (epoch < minEpoch || now > keyData.expiresAt) {
                keyData.key.fill(0);
                this.keys.delete(epoch);
            }
        }
    }
    start() {
        if (this.rotationTimer) return;
        this.generateKey(this.currentEpoch);
        this.rotationTimer = setInterval(() => this.rotate(), this.ROTATION_INTERVAL);
        this.cleanupTimer = setInterval(() => this.cleanup(), 600000);
        this.emit('started');
    }
    stop() {
        if (this.rotationTimer) clearInterval(this.rotationTimer);
        if (this.cleanupTimer) clearInterval(this.cleanupTimer);
        this.rotationTimer = null; this.cleanupTimer = null;
        for (const [, keyData] of this.keys.entries()) { keyData.key.fill(0); }
        this.keys.clear();
        this.emit('stopped');
    }
}


module.exports = { OnionMetadataProtection, EphemeralKeyManager };
