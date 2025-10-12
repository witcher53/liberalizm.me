// /server/mlmp-manager.js

const { OnionMetadataProtection, EphemeralKeyManager } = require('./mlmp-onion.js');
const { MetadataTimingProtection } = require('./mlmp-timing.js');

class MLMPManager {
    constructor() {
        this.onion = new OnionMetadataProtection();
        this.ephemeralKeys = new EphemeralKeyManager({
            rotationInterval: 3600000, // 1 saat
            maxKeyAge: 7200000,
            keyHistorySize: 2
        });
        this.timing = new MetadataTimingProtection({
            timeBucketing: {
                bucketSize: 300000,  // 5 dakika
            },
            decoyTraffic: {
                decoyProbability: 0.2, // %20
                decoyIntervalMin: 60000,
                decoyIntervalMax: 300000
            }
        });
    }

    async initialize(io) {
        // Ephemeral key rotation başlat
        this.ephemeralKeys.start();
        
        // Onion encryption için key rotation
        this.onion.startKeyRotation();
        
        // Timing protection başlat
        this.timing.start((decoyMessage) => {
            // Decoy mesajları genel bir kanala veya rastgele kullanıcılara gönderilebilir.
            // Şimdilik sadece logluyoruz.
            // io.emit('_mlmp_decoy', decoyMessage);
        });
        
        console.log('✅ [MLMP] All layers initialized');
    }

    // Client-side'da çağrılacak metodun sunucu versiyonu
    async encryptMetadata(publicKey) {
        // Sunucu tarafında client'ın özel anahtarı olmadığı için `clientKey` null geçilir.
        return await this.onion.encryptMetadata(publicKey, null);
    }

    // Sunucu tarafı routing için
    async serverDecryptRouting(onionData) {
        return await this.onion.serverDecryptRouting(onionData);
    }

    // Timing protection ile mesaj gönder
    queueMessage(message, callback) {
        this.timing.queueMessage(message, callback);
    }

    shutdown() {
        this.ephemeralKeys.stop();
        this.onion.stopKeyRotation();
        this.timing.stop();
        console.log('🛑 [MLMP] System shutdown');
    }
}

module.exports = MLMPManager;
