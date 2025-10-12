// /server/mlmp-timing.js

const crypto = require('crypto');
const EventEmitter = require('events');

// ============================================
// LAYER 3: TIME BUCKETING SYSTEM
// LAYER 4: DECOY TRAFFIC INJECTION
// ============================================

class TimeBucketingSystem {
    constructor(config = {}) {
        this.BUCKET_SIZE = config.bucketSize || 300000; // 5 dakika
    }

    bucketizeTimestamp(timestamp = Date.now()) {
        const bucketId = Math.floor(timestamp / this.BUCKET_SIZE);
        const bucketStart = bucketId * this.BUCKET_SIZE;
        return {
            bucketId: bucketId,
            bucketStart: bucketStart,
        };
    }
}

class DecoyTrafficSystem extends EventEmitter {
    constructor(config = {}) {
        super();
        this.DECOY_PROBABILITY = config.decoyProbability || 0.2;
        this.DECOY_INTERVAL_MIN = config.decoyIntervalMin || 60000;
        this.DECOY_INTERVAL_MAX = config.decoyIntervalMax || 300000;
        this.isActive = false;
        this.decoyTimer = null;
    }

    generateDecoyMessage() {
        return {
            type: 'decoy',
            data: crypto.randomBytes(256).toString('base64'),
            timestamp: Date.now(),
        };
    }

    start(emitCallback) {
        if (this.isActive) return;
        this.isActive = true;
        this.scheduleNextDecoy(emitCallback);
        console.log('✅ [Decoy] Traffic injection started');
        this.emit('started');
    }

    scheduleNextDecoy(emitCallback) {
        if (!this.isActive) return;
        
        const interval = Math.random() * (this.DECOY_INTERVAL_MAX - this.DECOY_INTERVAL_MIN) + this.DECOY_INTERVAL_MIN;
        
        this.decoyTimer = setTimeout(() => {
            if (Math.random() < this.DECOY_PROBABILITY) {
                const decoy = this.generateDecoyMessage();
                if (typeof emitCallback === 'function') {
                    emitCallback(decoy);
                    console.log(`🎭 [Decoy] Sent fake message.`);
                }
            }
            this.scheduleNextDecoy(emitCallback);
        }, interval);
    }

    stop() {
        if (this.decoyTimer) clearTimeout(this.decoyTimer);
        this.isActive = false;
        console.log('🛑 [Decoy] Traffic injection stopped');
        this.emit('stopped');
    }
}

class MetadataTimingProtection {
    constructor(config = {}) {
        this.timeBucketing = new TimeBucketingSystem(config.timeBucketing);
        this.decoyTraffic = new DecoyTrafficSystem(config.decoyTraffic);
        this.messageQueue = [];
        this.queueTimer = null;
    }

    queueMessage(message, callback) {
        this.messageQueue.push({ message, callback });
        // Gerçek uygulamada, bu mesajlar bir bucket dolana kadar bekletilebilir.
        // Şimdilik basitleştirilmiş bir flush mekanizması kullanıyoruz.
        this.flushQueue(); 
    }

    flushQueue() {
        if (this.messageQueue.length === 0) return;

        const currentBucket = this.timeBucketing.bucketizeTimestamp();
        
        this.messageQueue.forEach(item => {
            const messageWithTiming = {
                ...item.message,
                // timestamp alanını bucket başlangıcı ile değiştiriyoruz
                timestamp: new Date(currentBucket.bucketStart),
            };
            if (typeof item.callback === 'function') {
                item.callback(messageWithTiming);
            }
        });
        
        this.messageQueue = [];
    }

    start(decoyEmitCallback) {
        this.decoyTraffic.start(decoyEmitCallback);
        console.log('✅ [Metadata Timing Protection] System started');
    }

    stop() {
        this.decoyTraffic.stop();
        if (this.messageQueue.length > 0) {
            console.log('⚠️  Flushing remaining messages before shutdown');
            this.flushQueue();
        }
        console.log('🛑 [Metadata Timing Protection] System stopped');
    }
}

module.exports = { MetadataTimingProtection };
