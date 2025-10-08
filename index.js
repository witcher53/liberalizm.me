// /var/www/liberalizm.me/index.js

//require('dotenv').config();
const axios = require('axios');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const express = require('express');
const http = require('http');
const path = require('path');
const socketIo = require('socket.io');
const { MongoClient } = require('mongodb');
const { createClient } = require('redis');
const crypto = require('crypto');
const cors = require('cors');
const { createAdapter } = require('@socket.io/redis-adapter');
const nacl = require('tweetnacl');

let FPE_MASTER_KEY = null;
let SERVER_SECRET_KEY = null;

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;


// --- KRİPTO FONKSİYONLARI ---
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
function createMasterKey(keyInput) { return crypto.createHash('sha256').update(keyInput).digest(); }
// ----------------------------------------------------------------------


const app = express();
const server = http.createServer(app);
const PORT = 3000;
const redisClient = createClient({ url: 'redis://localhost:6379' });
redisClient.on('error', (err) => console.error('!!! [Sunucu] Redis Client Hatası:', err));
const pubClient = redisClient.duplicate();
const subClient = redisClient.duplicate();
const io = new socketIo.Server(server, { cors: { origin: "https://liberalizm.me", methods: ["GET", "POST"] } });

app.use(express.static('public'));

if (!process.env.MONGODB_URI) { console.error("❌ KRİTİK HATA: MONGODB_URI ortam değişkeni bulunamadı!"); process.exit(1); }
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);
let dmMessagesCollection, generalMessagesCollection, usersCollection;

// --- DİĞER FONKSİYONLAR ---
function initializeFPEKey() { const keyInput = process.env.MANUAL_FPE_KEY; const hashCheck = process.env.FPE_KEY_HASH_CHECK; if (!keyInput || !hashCheck) { console.error("❌ KRİTİK GÜVENLİK HATASI: FPE anahtarları ortam değişkenlerinde tanımlanmamış!"); process.exit(1); } const inputHash = crypto.createHash('sha256').update(keyInput).digest('hex'); if (inputHash !== hashCheck) { console.error("❌ GÜVENLİK HATASI: MANUAL_FPE_KEY, HASH ile uyuşmuyor!"); process.exit(1); } FPE_MASTER_KEY = createMasterKey(keyInput); console.log("✅ [Sunucu] FPE MASTER KEY ortam değişkeninden doğrulandı ve RAM'e Yüklendi!"); }
async function verifyTTLIndex(db) { const COLLECTION_NAME = 'general_messages'; const EXPIRE_AFTER_SECONDS = 86400; const INDEX_KEY = 'expireAt'; const INDEX_NAME = 'general_chat_expire_at'; try { const collection = db.collection(COLLECTION_NAME); const indexes = await collection.indexes(); const ttlIndexCorrect = indexes.find(i => i.name === INDEX_NAME && i.expireAfterSeconds === EXPIRE_AFTER_SECONDS && i.key.hasOwnProperty(INDEX_KEY) && !i.partialFilterExpression); if (ttlIndexCorrect) { console.log(`✅ [Sunucu] TTL Index '${INDEX_NAME}' doğru ayarlanmış.`); return; } const oldIndex = indexes.find(i => i.name === INDEX_NAME || i.key.hasOwnProperty(INDEX_KEY)); if (oldIndex) { console.warn(`⚠️ [Sunucu] Eski/Bozuk TTL Index '${oldIndex.name}' bulundu, siliniyor...`); await collection.dropIndex(oldIndex.name); } console.log(`🔨 [Sunucu] Yeni TTL Index '${INDEX_NAME}' kuruluyor...`); await collection.createIndex({ [INDEX_KEY]: 1 }, { name: INDEX_NAME, expireAfterSeconds: EXPIRE_AFTER_SECONDS, background: true }); console.log(`✅ [Sunucu] TTL Index başarıyla kuruldu ve doğrulandı!`); } catch (err) { console.error(`!!! [Sunucu] KRİTİK HATA: TTL Index kontrolü/kurulumu BAŞARISIZ OLDU. Hata: ${err.message}`); process.exit(1); } }


// --- DEĞİŞİKLİK BURADA BAŞLIYOR: BÜTÜN SOCKET.IO MANTIĞI BU FONKSİYONUN İÇİNE TAŞINDI ---
function initializeSocketListeners() {
    const GENERAL_CHAT_ROOM = 'general_chat_room';

    const rateLimiter = new RateLimiterMemory({ points: 10, duration: 1 });
    const messageLimiter = new RateLimiterMemory({ points: 5, duration: 2 });
    const privateMessageLimiter = new RateLimiterMemory({ points: 10, duration: 2 });

    io.use((socket, next) => {
        rateLimiter.consume(socket.handshake.address)
            .then(() => {
                const { publicKey, signature, nonce } = socket.handshake.auth;
                if (!publicKey || !signature || !nonce) { return next(new Error('Kimlik doğrulama hatası: Bilgiler eksik.')); }
                try {
                    const signPublicKeyBytes = Buffer.from(publicKey, 'base64');
                    const nonceBuffer = Buffer.from(nonce, 'hex');
                    const signatureBuffer = Buffer.from(signature, 'base64');
                    const isVerified = nacl.sign.detached.verify(nonceBuffer, signatureBuffer, signPublicKeyBytes);
                    if (!isVerified) { return next(new Error('Kimlik doğrulama hatası: İmza geçersiz.')); }
                    socket.signPublicKey = publicKey;
                    next();
                } catch (e) { console.error("Auth hatası (server):", e.message); return next(new Error('Kimlik doğrulama hatası: Hatalı format.')); }
            })
            .catch(() => { next(new Error('Çok fazla istek gönderdiniz. Lütfen yavaşlayın.')); });
    });

    io.on('connection', async (socket) => {
        socket.on('user authenticated', async (userData) => {
            try {
                if (!userData.boxPublicKey || !userData.username || !/^.{3,15}$/.test(userData.username)) {
                    console.error(`Geçersiz kullanıcı adı veya eksik bilgi: ${userData.username}`);
                    return;
                }
                socket.username = userData.username;
                socket.publicKey = userData.boxPublicKey;
                socket.join(socket.publicKey);
                socket.join(GENERAL_CHAT_ROOM);
                await usersCollection.updateOne({ publicKey: socket.publicKey }, { $set: { username: userData.username } }, { upsert: true });
                await redisClient.sAdd('online_users_set', socket.publicKey);
                const onlineKeys = await redisClient.sMembers('online_users_set');
                const onlineUsers = await usersCollection.find({ publicKey: { $in: onlineKeys } }, { projection: { username: 1, publicKey: 1, _id: 0 } }).toArray();
                socket.emit('initial user list', onlineUsers);
                socket.broadcast.emit('user connected', { username: userData.username, publicKey: socket.publicKey });
            } catch (error) {
                console.error('[HATA] "user authenticated":', error);
            }
        });

        socket.on('get conversations', async () => {
            try {
                if (!socket.publicKey) return;
                const myFingerprint = pointerFingerprint(socket.publicKey);
                if (!myFingerprint) return;
                const recentMessages = await dmMessagesCollection.find({ $or: [{ senderFingerprint: myFingerprint }, { recipientFingerprint: myFingerprint }] }, { projection: { senderPointer: 1, recipientPointer: 1, _id: 0 } }).sort({ timestamp: -1 }).limit(100).toArray();
                const partnerPublicKeys = new Set();
                recentMessages.forEach(msg => {
                    const senderPK = decryptPointer(msg.senderPointer);
                    const recipientPK = decryptPointer(msg.recipientPointer);
                    if (senderPK && senderPK !== socket.publicKey) partnerPublicKeys.add(senderPK);
                    if (recipientPK && recipientPK !== socket.publicKey) partnerPublicKeys.add(recipientPK);
                });
                const partners = await usersCollection.find({ publicKey: { $in: Array.from(partnerPublicKeys) } }, { projection: { username: 1, publicKey: 1, _id: 0 } }).toArray();
                socket.emit('conversations list', partners);
            } catch (err) {
                console.error('[HATA] "get conversations" event\'inde:', err);
            }
        });

        socket.on('chat message', async (msg, callback) => {
            try {
                await messageLimiter.consume(socket.publicKey);
                if (!socket.username || !msg || typeof msg.message !== 'string') return;
                const message = msg.message.trim();
                if (message.length === 0 || message.length > 5000) {
                    if (typeof callback === 'function') callback({ status: 'error', message: 'Geçersiz mesaj.' });
                    return;
                }
                const expireDate = new Date(Date.now() + 86400 * 1000);
                const data = { username: socket.username, message: message, timestamp: new Date(), expireAt: expireDate };
                await generalMessagesCollection.insertOne(data);
                socket.broadcast.to(GENERAL_CHAT_ROOM).emit('chat message', data);
                if (typeof callback === 'function') callback({ status: 'ok' });
            } catch (rejRes) {
                console.log(`Rate limit aşıldı: ${socket.username}`);
                if (typeof callback === 'function') callback({ status: 'error', message: 'Çok hızlı mesaj gönderiyorsun.' });
            }
        });

        socket.on('private message', async (data) => {
            try {
                await privateMessageLimiter.consume(socket.publicKey);
                if (!socket.publicKey || !data.recipientPublicKey) return;
                const dbData = { senderPointer: encryptPointer(socket.publicKey), recipientPointer: encryptPointer(data.recipientPublicKey), senderFingerprint: pointerFingerprint(socket.publicKey), recipientFingerprint: pointerFingerprint(data.recipientPublicKey), ciphertext_for_recipient: data.ciphertext_for_recipient, ciphertext_for_sender: data.ciphertext_for_sender, timestamp: new Date() };
                await dmMessagesCollection.insertOne(dbData);
                if (data.recipientPublicKey !== socket.publicKey) {
                    io.to(data.recipientPublicKey).emit('private message', { ciphertext: data.ciphertext_for_recipient, senderPublicKey: socket.publicKey });
                }
                const recipientUser = await usersCollection.findOne({ publicKey: data.recipientPublicKey }, { projection: { username: 1, publicKey: 1, _id: 0 } });
                if (recipientUser) {
                    socket.emit('new_conversation_partner', recipientUser);
                }
            } catch (rejRes) {
                console.log(`Rate limit (DM) aşıldı: ${socket.username}`);
            }
        });

        socket.on('get conversation history', async (otherUserPublicKey) => {
            if (!socket.publicKey) return;
            let history;
            if (otherUserPublicKey === null) {
                history = await generalMessagesCollection.find({}).sort({ _id: -1 }).limit(100).toArray();
            } else {
                const myFingerprint = pointerFingerprint(socket.publicKey);
                const otherFingerprint = pointerFingerprint(otherUserPublicKey);
                history = await dmMessagesCollection.find({ $or: [{ senderFingerprint: myFingerprint, recipientFingerprint: otherFingerprint }, { senderFingerprint: otherFingerprint, recipientFingerprint: myFingerprint }] }).sort({ timestamp: -1 }).limit(100).toArray();
            }
            history.reverse();
            socket.emit('conversation history', { history: history, partnerPublicKey: otherUserPublicKey });
        });

        socket.on('disconnect', async () => {
            if (socket.publicKey) {
                const removedCount = await redisClient.sRem('online_users_set', socket.publicKey);
                if (removedCount > 0) {
                    io.emit('user disconnected', { publicKey: socket.publicKey });
                }
            }
        });
    });
}
// --- DEĞİŞİKLİK BURADA BİTİYOR ---


async function startServer() {
    try {
        const vaultAddr = process.env.VAULT_ADDR;
        const vaultToken = process.env.VAULT_TOKEN;
        const secretPath = process.env.SECRET_PATH;
        if (!vaultAddr || !vaultToken || !secretPath) { throw new Error("VAULT_ADDR, VAULT_TOKEN veya SECRET_PATH ortam değişkenleri bulunamadı!"); }
        console.log("⏳ [Sunucu] HashiCorp Vault'tan SERVER_SECRET_KEY çekiliyor...");
        const response = await axios.get(`${vaultAddr}/v1/${secretPath}`, { headers: { 'X-Vault-Token': vaultToken } });
        const secretData = response.data.data.data;
        if (!secretData || !secretData.SERVER_SECRET_KEY) { throw new Error("Vault'tan SERVER_SECRET_KEY değeri alınamadı veya yol hatalı."); }
        const keyFromVault = Buffer.from(secretData.SERVER_SECRET_KEY, 'hex');
        if (keyFromVault.length !== 32) { throw new Error(`Anahtar uzunluğu 32 byte değil.`); }
        SERVER_SECRET_KEY = keyFromVault;
        console.log("✅ [Sunucu] SERVER_SECRET_KEY başarıyla RAM'e yüklendi.");
    } catch (error) {
        console.error("❌ KRİTİK GÜVENLİK HATASI: HashiCorp Vault'tan anahtar alınamadı!");
        console.error("Detay:", error.message || error.response?.data || error);
        return process.exit(1);
    }

    try {
        initializeFPEKey();
        await client.connect();
        const database = client.db('chat_app');
        dmMessagesCollection = database.collection('dm_messages');
        generalMessagesCollection = database.collection('general_messages');
        usersCollection = database.collection('users');
        console.log("✅ [Sunucu] MongoDB Atlas'a başarıyla bağlanıldı!");
        await verifyTTLIndex(database);

     try {
    await dmMessagesCollection.createIndex({ senderFingerprint: 1 });
    await dmMessagesCollection.createIndex({ recipientFingerprint: 1 });
    await usersCollection.createIndex({ "publicKey": 1 }, { unique: true });
    console.log("✅ [Sunucu] Koleksiyon İndeksleri başarıyla oluşturuldu/doğrulandı.");
} catch (err) {
    if (err.code === 85 || err.codeName === 'IndexOptionsConflict') {
        console.log("✅ [Sunucu] Koleksiyon İndeksleri zaten mevcut, devam ediliyor.");
    } else {
        // Beklenmedik başka bir hata varsa programı durdur
        throw err;
    }
}

        // --- DEĞİŞİKLİK: SOCKET DINLEYICILERI ANCAK HER ŞEY HAZIR OLDUĞUNDA BAŞLATILIYOR ---
        initializeSocketListeners();
        console.log("✅ [Sunucu] Socket.IO dinleyicileri başlatıldı.");

        server.listen(PORT, '127.0.0.1', () => {
            console.log(`✅ [Sunucu] Sunucu ${PORT} portunda dinlemede. Müşteri kabulüne hazır.`);
        });
    } catch (err) {
        console.error("!!! [Sunucu] Veritabanına bağlanırken veya sunucu başlatılırken KRİTİK HATA:", err);
        process.exit(1);
    }
}

// BAŞLANGIÇ AKIŞI
console.log('[Sunucu] Redis Adapter kurulumu deneniyor...');
Promise.all([redisClient.connect(), pubClient.connect(), subClient.connect()])
    .then(() => {
        io.adapter(createAdapter(pubClient, subClient));
        console.log("✅ [Sunucu] Socket.IO Redis Adapter'a bağlandı.");
        startServer();
    })
    .catch(err => {
        console.error("!!! [Sunucu] Redis Adapter'a bağlanırken KRİTİK HATA:", err);
        process.exit(1);
    });
