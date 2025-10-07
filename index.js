// /var/www/liberalizm.me/index.js (DEBUG MODU AKTİF)

require('dotenv').config();

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
const { RateLimiterMemory } = require('rate-limiter-flexible');

console.log('--- [Sunucu] Kod başlangıcı ---');

let FPE_MASTER_KEY = null;
const SERVER_SECRET_KEY = process.env.SERVER_SECRET_KEY ? Buffer.from(process.env.SERVER_SECRET_KEY, 'hex') : null;
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; 
const AUTH_TAG_LENGTH = 16;
if (!SERVER_SECRET_KEY || SERVER_SECRET_KEY.length !== 32) { console.error("❌ KRİTİK GÜVENLİK HATASI: .env dosyasında 32 byte'lık (64 hex karakter) bir SERVER_SECRET_KEY tanımlanmalı!"); process.exit(1); }

function encryptPointer(publicKey) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, SERVER_SECRET_KEY, iv);
    let encrypted = cipher.update(publicKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `v1$${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

function decryptPointer(encryptedPointer) {
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
function pointerFingerprint(publicKey) { return crypto.createHmac('sha256', SERVER_SECRET_KEY).update(publicKey).digest('hex'); }
function createMasterKey(keyInput) { return crypto.createHash('sha256').update(keyInput).digest(); }

const app = express();
const server = http.createServer(app);
const PORT = 3000;
const redisClient = createClient({ url: 'redis://localhost:6379' });
redisClient.on('error', (err) => console.error('!!! [Sunucu] Redis Client Hatası:', err));
const pubClient = redisClient.duplicate();
const subClient = redisClient.duplicate();
const io = new socketIo.Server(server, { cors: { origin: "https://liberalizm.me", methods: ["GET", "POST"] } });

console.log('[Sunucu] Redis Adapter kurulumu deneniyor...');
Promise.all([redisClient.connect(), pubClient.connect(), subClient.connect()]).then(() => { io.adapter(createAdapter(pubClient, subClient)); console.log("✅ [Sunucu] Socket.IO Redis Adapter'a bağlandı."); }).catch(err => { console.error("!!! [Sunucu] Redis Adapter'a bağlanırken KRİTİK HATA:", err); process.exit(1); });

app.use(express.static(__dirname));
if (!process.env.MONGODB_URI) { console.error("❌ KRİTİK HATA: .env dosyasında MONGODB_URI tanımlı değil!"); process.exit(1); }
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);
let dmMessagesCollection, generalMessagesCollection, usersCollection;

async function updateAndBroadcastOnlineUsers() {
    try {
        console.log('[Sunucu] Online kullanıcı listesi güncelleniyor ve yayınlanıyor...');
        const onlineKeys = await redisClient.sMembers('online_users_set');
        if (onlineKeys.length === 0) {
            await redisClient.set('online_users_cache', '[]');
            io.emit('initial user list', []);
            return;
        }

        const users = await usersCollection.find({ publicKey: { $in: onlineKeys } }, { projection: { username: 1, publicKey: 1, _id: 0 } }).toArray();
        
        const userListJSON = JSON.stringify(users);
        await redisClient.set('online_users_cache', userListJSON);
        
        io.emit('initial user list', users); 
        console.log(`✅ [Sunucu] ${users.length} kullanıcılık güncel liste herkese gönderildi.`);
    } catch (error) {
        console.error('!!! [Sunucu] Online kullanıcı listesi güncellenirken KRİTİK HATA:', error);
    }
}

function initializeFPEKey() { const keyInput = process.env.MANUAL_FPE_KEY; const hashCheck = process.env.FPE_KEY_HASH_CHECK; if (!keyInput || !hashCheck) { console.error("❌ KRİTİK GÜVENLİK HATASI: FPE anahtarları .env dosyasında tanımlanmamış!"); process.exit(1); } const inputHash = crypto.createHash('sha256').update(keyInput).digest('hex'); if (inputHash !== hashCheck) { console.error("❌ GÜVENLİK HATASI: .env KEY A, HASH ile uyuşmuyor!"); process.exit(1); } FPE_MASTER_KEY = createMasterKey(keyInput); console.log("✅ [Sunucu] FPE MASTER KEY .env dosyasından doğrulandı ve RAM'e Yüklendi!"); }
async function verifyTTLIndex(db) { const COLLECTION_NAME = 'general_messages'; const EXPIRE_AFTER_SECONDS = 86400; const INDEX_KEY = 'expireAt'; const INDEX_NAME = 'general_chat_expire_at'; try { const collection = db.collection(COLLECTION_NAME); const indexes = await collection.indexes(); const ttlIndexCorrect = indexes.find(i => i.name === INDEX_NAME && i.expireAfterSeconds === EXPIRE_AFTER_SECONDS && i.key.hasOwnProperty(INDEX_KEY) && !i.partialFilterExpression); if (ttlIndexCorrect) { console.log(`✅ [Sunucu] TTL Index '${INDEX_NAME}' doğru ayarlanmış.`); return; } const oldIndex = indexes.find(i => i.name === INDEX_NAME || i.key.hasOwnProperty(INDEX_KEY)); if (oldIndex) { console.warn(`⚠️ [Sunucu] Eski/Bozuk TTL Index '${oldIndex.name}' bulundu, siliniyor...`); await collection.dropIndex(oldIndex.name); } console.log(`🔨 [Sunucu] Yeni TTL Index '${INDEX_NAME}' kuruluyor...`); await collection.createIndex({ [INDEX_KEY]: 1 }, { name: INDEX_NAME, expireAfterSeconds: EXPIRE_AFTER_SECONDS, background: true }); console.log(`✅ [Sunucu] TTL Index başarıyla kuruldu ve doğrulandı!`); } catch (err) { console.error(`!!! [Sunucu] KRİTİK HATA: TTL Index kontrolü/kurulumu BAŞARISIZ OLDU. Hata: ${err.message}`); process.exit(1); } }
async function run() { try { initializeFPEKey(); await client.connect(); const database = client.db('chat_app'); dmMessagesCollection = database.collection('dm_messages'); generalMessagesCollection = database.collection('general_messages'); usersCollection = database.collection('users'); console.log("✅ [Sunucu] MongoDB Atlas'a başarıyla bağlanıldı!"); await verifyTTLIndex(database); try { await dmMessagesCollection.createIndex({ senderFingerprint: 1 }); await dmMessagesCollection.createIndex({ recipientFingerprint: 1 }); await usersCollection.createIndex({ "publicKey": 1 }, { name: "user_publicKey_lookup", unique: true }); console.log("✅ [Sunucu] Koleksiyon İndeksleri başarıyla doğrulandı."); } catch (err) { if (err.codeName === 'IndexKeySpecsConflict' || err.code === 85 || err.codeName === 'IndexOptionsConflict') { console.log("[Sunucu] İndeksler zaten mevcut."); } else { console.error("!!! [Sunucu] İndeks oluşturulurken KRİTİK HATA:", err); } } server.listen(PORT, '127.0.0.1', () => { console.log(`✅ [Sunucu] Sunucu ${PORT} portunda dinlemede.`); }); } catch (err) { console.error("!!! [Sunucu] Veritabanına bağlanırken KRİTİK HATA:", err); process.exit(1); } }
run();

const GENERAL_CHAT_ROOM = 'general_chat_room';

const rateLimiter = new RateLimiterMemory({ points: 10, duration: 1 });

io.use((socket, next) => {
    console.log(`[Sunucu] Yeni bir bağlantı denemesi... Adres: ${socket.handshake.address}`);
    rateLimiter.consume(socket.handshake.address)
        .then(() => {
            const { publicKey, signature, nonce } = socket.handshake.auth;
            if (!publicKey || !signature || !nonce) { console.log('!!! [Sunucu] Kimlik doğrulama reddedildi: Bilgiler eksik.'); return next(new Error('Kimlik doğrulama hatası: Bilgiler eksik.')); }
            try {
                const signPublicKeyBytes = Buffer.from(publicKey, 'base64');
                const nonceBuffer = Buffer.from(nonce, 'hex');
                const signatureBuffer = Buffer.from(signature, 'base64');
                const isVerified = nacl.sign.detached.verify(nonceBuffer, signatureBuffer, signPublicKeyBytes);
                if (!isVerified) { console.log('!!! [Sunucu] Kimlik doğrulama reddedildi: İmza geçersiz.'); return next(new Error('Kimlik doğrulama hatası: İmza geçersiz.')); }
                socket.signPublicKey = publicKey;
                console.log('✅ [Sunucu] Bir kullanıcı kimliğini doğruladı ve bağlantıya izin verildi.');
                next();
            } catch (e) { console.error("!!! [Sunucu] Auth hatası:", e.message); return next(new Error('Kimlik doğrulama hatası: Hatalı format.')); }
        })
        .catch(() => { console.log(`!!! [Sunucu] Rate limit aşıldı: ${socket.handshake.address}`); next(new Error('Çok fazla istek gönderdiniz. Lütfen yavaşlayın.')); });
});

io.on('connection', async (socket) => {
    console.log(`✅ [Sunucu] Bir client bağlandı! Socket ID: ${socket.id}`);

    socket.on('user authenticated', async (userData) => {
        console.log(`[Sunucu] 'user authenticated' eventi alındı. Kullanıcı: ${userData.username}`);
        try {
            if (!userData || typeof userData.username !== 'string' || !userData.boxPublicKey) { console.log("!!! [Sunucu] 'user authenticated' eventi geçersiz veri nedeniyle reddedildi."); return; }
            const username = userData.username.trim();
            if (username.length < 2 || username.length > 20) { console.log("!!! [Sunucu] 'user authenticated' eventi geçersiz kullanıcı adı uzunluğu nedeniyle reddedildi."); return; }
            socket.username = username;
            socket.publicKey = userData.boxPublicKey;
            socket.join(socket.publicKey);
            socket.join(GENERAL_CHAT_ROOM);
            
            console.log(`[Sunucu] ${username} veritabanına ve Redis'e kaydediliyor...`);
            await redisClient.sAdd('online_users_set', socket.publicKey);
            await usersCollection.updateOne({ publicKey: socket.publicKey }, { $set: { username: socket.username } }, { upsert: true });
            const userKey = `user:${socket.publicKey}`;
            await redisClient.hSet(userKey, { username: socket.username, publicKey: socket.publicKey, socketId: socket.id });
            await redisClient.expire(userKey, 300);
            
            await updateAndBroadcastOnlineUsers();
            
        } catch (error) {
            console.error('!!! [Sunucu] "user authenticated" eventinde KRİTİK HATA:', error);
        }
    });
    
    socket.on('get conversations', async () => { 
        console.log(`[Sunucu] '${socket.username}' kullanıcısından 'get conversations' isteği alındı.`);
        if (!socket.publicKey) return; 
        try { 
            const myFingerprint = pointerFingerprint(socket.publicKey); 
            const messages = await dmMessagesCollection.find({ $or: [{ senderFingerprint: myFingerprint }, { recipientFingerprint: myFingerprint }] }).toArray(); 
            const partnerPointers = new Set(); 
            messages.forEach(msg => { partnerPointers.add(msg.senderPointer); partnerPointers.add(msg.recipientPointer); }); 
            const partnerPublicKeys = Array.from(partnerPointers).map(decryptPointer).filter(Boolean); 
            let partners = []; 
            if (partnerPublicKeys.length > 0) { 
                partners = await usersCollection.find({ publicKey: { $in: partnerPublicKeys } }, { projection: { username: 1, publicKey: 1, _id: 0 } }).toArray(); 
            } 
            console.log(`[Sunucu] '${socket.username}' kullanıcısına ${partners.length} adet sohbet gönderiliyor.`);
            socket.emit('conversations list', partners); 
        } catch(err) { 
            console.error("!!! [Sunucu] Sohbet listesi çekilirken hata:", err); 
            socket.emit('conversations list', []); 
        } 
    });

    socket.on('get conversation history', async (otherUserPublicKey) => { 
        console.log(`[Sunucu] '${socket.username}' için sohbet geçmişi isteği alındı. Partner: ${otherUserPublicKey || 'Genel Sohbet'}`);
        if (!socket.publicKey) return; 
        let history; 
        if (otherUserPublicKey === null) { 
            history = await generalMessagesCollection.find({}).sort({ _id: -1 }).limit(100).toArray(); 
            history.reverse(); 
        } else { 
            const myFingerprint = pointerFingerprint(socket.publicKey); 
            const otherFingerprint = pointerFingerprint(otherUserPublicKey); 
            history = await dmMessagesCollection.find({ $or: [{ senderFingerprint: myFingerprint, recipientFingerprint: otherFingerprint }, { senderFingerprint: otherFingerprint, recipientFingerprint: myFingerprint }] }).sort({ timestamp: -1 }).limit(100).toArray(); 
            history.reverse(); 
        } 
        console.log(`[Sunucu] '${socket.username}' kullanıcısına ${history.length} adet mesaj geçmişi gönderiliyor.`);
        socket.emit('conversation history', { history: history, partnerPublicKey: otherUserPublicKey }); 
    });

    socket.on('get user info', async (publicKey, callback) => {
        if (typeof callback !== 'function') return;
        try {
            const user = await usersCollection.findOne(
                { publicKey: publicKey },
                { projection: { username: 1, publicKey: 1, _id: 0 } }
            );
            if (user) {
                callback({ user: user });
            } else {
                callback({ error: 'Kullanıcı bulunamadı.' });
            }
        } catch (error) {
            console.error("!!! [Sunucu] 'get user info' hatası:", error);
            callback({ error: 'Sunucu hatası.' });
        }
    });

    socket.on('disconnect', async () => { 
        console.log(`[Sunucu] Bir client ayrıldı: ${socket.username || socket.id}`);
        if (socket.publicKey) { 
            await redisClient.del(`user:${socket.publicKey}`); 
            await redisClient.sRem('online_users_set', socket.publicKey); 
            await updateAndBroadcastOnlineUsers();
        } 
    });
    
    socket.on('chat message', async (msg, callback) => { if (!socket.username || !msg || typeof msg.message !== 'string') return; const message = msg.message.trim(); if (message.length === 0 || message.length > 5000) { if (typeof callback === 'function') callback({ status: 'error', message: 'Geçersiz mesaj.' }); return; } const expireDate = new Date(Date.now() + 86400 * 1000); const data = { username: socket.username, message: message, timestamp: new Date(), expireAt: expireDate }; try { await generalMessagesCollection.insertOne(data); socket.broadcast.to(GENERAL_CHAT_ROOM).emit('chat message', data); if (typeof callback === 'function') callback({ status: 'ok' }); } catch (err) { if (typeof callback === 'function') callback({ status: 'error' }); } });
    socket.on('private message', async (data) => { if (!socket.publicKey || !data.recipientPublicKey) return; const dbData = { senderPointer: encryptPointer(socket.publicKey), recipientPointer: encryptPointer(data.recipientPublicKey), senderFingerprint: pointerFingerprint(socket.publicKey), recipientFingerprint: pointerFingerprint(data.recipientPublicKey), ciphertext_for_recipient: data.ciphertext_for_recipient, ciphertext_for_sender: data.ciphertext_for_sender, timestamp: new Date() }; try { await dmMessagesCollection.insertOne(dbData); if (data.recipientPublicKey !== socket.publicKey) { io.to(data.recipientPublicKey).emit('private message', { ciphertext: data.ciphertext_for_recipient, senderPublicKey: socket.publicKey }); } } catch (err) { console.error("Özel mesaj gönderilirken hata:", err); } });
    socket.onAny(async () => { if (socket.publicKey) { await redisClient.expire(`user:${socket.publicKey}`, 300); } });
});
