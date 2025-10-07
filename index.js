// /var/www/liberalizm.me/index.js (FİNAL SÜRÜM v2.3: Önce Yayınla, Sonra Kaydet Optimizasyonu)

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

// Güvenlik ve yardımcı fonksiyonlar
let FPE_MASTER_KEY = null;
const SERVER_SECRET_KEY = process.env.SERVER_SECRET_KEY ? Buffer.from(process.env.SERVER_SECRET_KEY, 'hex') : null;
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
if (!SERVER_SECRET_KEY || SERVER_SECRET_KEY.length !== 32) { console.error("❌ KRİTİK GÜVENLİK HATASI: .env dosyasında 32 byte'lık (64 hex karakter) bir SERVER_SECRET_KEY tanımlanmalı!"); process.exit(1); }
function encryptPointer(publicKey) { const iv = crypto.randomBytes(IV_LENGTH); const cipher = crypto.createCipheriv(ALGORITHM, SERVER_SECRET_KEY, iv); let encrypted = cipher.update(publicKey, 'utf8', 'hex'); encrypted += cipher.final('hex'); const authTag = cipher.getAuthTag(); return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`; }
function decryptPointer(encryptedPointer) { try { const parts = encryptedPointer.split(':'); const iv = Buffer.from(parts[0], 'hex'); const authTag = Buffer.from(parts[1], 'hex'); const encryptedText = parts[2]; const decipher = crypto.createDecipheriv(ALGORITHM, SERVER_SECRET_KEY, iv); decipher.setAuthTag(authTag); let decrypted = decipher.update(encryptedText, 'hex', 'utf8'); decrypted += decipher.final('utf8'); return decrypted; } catch (error) { console.error("İşaretçi çözülürken hata:", error); return null; } }
function pointerFingerprint(publicKey) { return crypto.createHmac('sha256', SERVER_SECRET_KEY).update(publicKey).digest('hex'); }
function createMasterKey(keyInput) { return crypto.createHash('sha256').update(keyInput).digest(); }

// Uygulama kurulumu
const app = express();
const server = http.createServer(app);
const PORT = 3000;
const redisClient = createClient({ url: 'redis://localhost:6379' });
redisClient.on('error', (err) => console.error('Redis Client Error', err));
const pubClient = redisClient.duplicate();
const subClient = redisClient.duplicate();
const io = new socketIo.Server(server, { cors: { origin: "https://liberalizm.me", methods: ["GET", "POST"] } });
Promise.all([redisClient.connect(), pubClient.connect(), subClient.connect()]).then(() => { io.adapter(createAdapter(pubClient, subClient)); console.log("Socket.IO Redis Adapter'a bağlandı."); }).catch(err => { console.error("Redis Adapter'a bağlanırken KRİTİK HATA:", err); process.exit(1); });
app.use(express.static(__dirname));
if (!process.env.MONGODB_URI) { console.error("❌ KRİTİK HATA: .env dosyasında MONGODB_URI tanımlı değil!"); process.exit(1); }
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);
let dmMessagesCollection, generalMessagesCollection, usersCollection;
function initializeFPEKey() { const keyInput = process.env.MANUAL_FPE_KEY; const hashCheck = process.env.FPE_KEY_HASH_CHECK; if (!keyInput || !hashCheck) { console.error("❌ KRİTİK GÜVENLİK HATASI: FPE anahtarları .env dosyasında tanımlanmamış!"); process.exit(1); } const inputHash = crypto.createHash('sha256').update(keyInput).digest('hex'); if (inputHash !== hashCheck) { console.error("❌ GÜVENLİK HATASI: .env KEY A, HASH ile uyuşmuyor!"); process.exit(1); } FPE_MASTER_KEY = createMasterKey(keyInput); console.log("✅ FPE MASTER KEY .env dosyasından doğrulandı ve RAM'e Yüklendi!"); }
async function verifyTTLIndex(db) { const COLLECTION_NAME = 'general_messages'; const EXPIRE_AFTER_SECONDS = 86400; const INDEX_KEY = 'expireAt'; const INDEX_NAME = 'general_chat_expire_at'; try { const collection = db.collection(COLLECTION_NAME); const indexes = await collection.indexes(); const ttlIndexCorrect = indexes.find(i => i.name === INDEX_NAME && i.expireAfterSeconds === EXPIRE_AFTER_SECONDS && i.key.hasOwnProperty(INDEX_KEY) && !i.partialFilterExpression); if (ttlIndexCorrect) { console.log(`✅ TTL Index '${INDEX_NAME}' doğru ayarlanmış.`); return; } const oldIndex = indexes.find(i => i.name === INDEX_NAME || i.key.hasOwnProperty(INDEX_KEY)); if (oldIndex) { console.warn(`⚠️ Eski/Bozuk TTL Index '${oldIndex.name}' bulundu, siliniyor...`); await collection.dropIndex(oldIndex.name); } console.log(`🔨 Yeni TTL Index '${INDEX_NAME}' kuruluyor...`); await collection.createIndex({ [INDEX_KEY]: 1 }, { name: INDEX_NAME, expireAfterSeconds: EXPIRE_AFTER_SECONDS, background: true }); console.log(`✅ TTL Index başarıyla kuruldu ve doğrulandı!`); } catch (err) { console.error(`❌ KRİTİK HATA: TTL Index kontrolü/kurulumu BAŞARISIZ OLDU. Hata: ${err.message}`); process.exit(1); } }
async function run() { try { initializeFPEKey(); await client.connect(); const database = client.db('chat_app'); dmMessagesCollection = database.collection('dm_messages'); generalMessagesCollection = database.collection('general_messages'); usersCollection = database.collection('users'); console.log("MongoDB Atlas'a başarıyla bağlanıldı!"); await verifyTTLIndex(database); try { await dmMessagesCollection.createIndex({ senderFingerprint: 1 }); await dmMessagesCollection.createIndex({ recipientFingerprint: 1 }); await usersCollection.createIndex({ "publicKey": 1 }, { name: "user_publicKey_lookup", unique: true }); console.log("Koleksiyon İndeksleri başarıyla doğrulandı."); } catch (err) { if (err.codeName === 'IndexKeySpecsConflict' || err.code === 85 || err.codeName === 'IndexOptionsConflict') { console.log("İndeksler zaten mevcut."); } else { console.error("İndeks oluşturulurken KRİTİK HATA:", err); } } server.listen(PORT, '127.0.0.1', () => { console.log(`Sunucu ${PORT} portunda dinlemede.`); }); } catch (err) { console.error("Veritabanına bağlanırken KRİTİK HATA:", err); process.exit(1); } }
run();

const GENERAL_CHAT_ROOM = 'general_chat_room';

async function updateOnlineUsersCache() { if (!redisClient.isReady) return; try { const onlineKeys = await redisClient.sMembers('online_users_set'); if (onlineKeys.length === 0) { await redisClient.set('online_users_cache', '[]', { EX: 15 }); return; } const multi = redisClient.multi(); for (const key of onlineKeys) { multi.hGetAll(`user:${key}`); } const onlineUsersDataRaw = await multi.exec(); const finalOnlineList = onlineUsersDataRaw.filter(user => user && user.publicKey).map(user => ({ username: user.username, publicKey: user.publicKey })); await redisClient.set('online_users_cache', JSON.stringify(finalOnlineList), { EX: 15 }); } catch (error) { console.error("Online kullanıcı önbelleği güncellenirken hata:", error); } }

io.on('connection', async (socket) => {
    socket.on('add user', async (userData) => { try { if (!userData.publicKey || !userData.username) return; socket.username = userData.username; socket.publicKey = userData.publicKey; socket.join(userData.publicKey); socket.join(GENERAL_CHAT_ROOM); await redisClient.sAdd('online_users_set', userData.publicKey); await usersCollection.updateOne({ publicKey: userData.publicKey }, { $set: { username: userData.username } }, { upsert: true }); const userKey = `user:${socket.publicKey}`; await redisClient.hSet(userKey, { username: userData.username, publicKey: userData.publicKey, socketId: socket.id }); await redisClient.expire(userKey, 300); const cachedList = await redisClient.get('online_users_cache'); socket.emit('initial user list', cachedList ? JSON.parse(cachedList) : []); socket.to(GENERAL_CHAT_ROOM).emit('user connected', { username: userData.username, publicKey: userData.publicKey }); updateOnlineUsersCache(); } catch (error) { console.error('[HATA] "add user":', error); } });
    socket.on('disconnect', async () => { if (socket.publicKey) { await redisClient.del(`user:${socket.publicKey}`); await redisClient.sRem('online_users_set', socket.publicKey); io.to(GENERAL_CHAT_ROOM).emit('user disconnected', { publicKey: socket.publicKey }); updateOnlineUsersCache(); } });
    
    socket.on('chat message', (msg, callback) => {
        if (!socket.username || !msg.message) return;

        const data = { 
            username: socket.username, 
            message: msg.message, 
            timestamp: new Date()
        }; 

        // 1. ÖNCE YAYINLA (gönderen hariç)
        socket.broadcast.to(GENERAL_CHAT_ROOM).emit('chat message', data);

        // 2. SONRA (arka planda) kaydet.
        const expireDate = new Date();
        expireDate.setSeconds(expireDate.getSeconds() + 86400);
        data.expireAt = expireDate;

        generalMessagesCollection.insertOne(data)
            .then(() => {
                if (typeof callback === 'function') callback({ status: 'ok' });
            })
            .catch(err => {
                console.error("Genel mesaj kaydedilirken hata:", err);
                if (typeof callback === 'function') callback({ status: 'error' });
            });
    });

    socket.on('get conversations', async () => { if (!socket.publicKey) return; try { const myFingerprint = pointerFingerprint(socket.publicKey); const messages = await dmMessagesCollection.find({ $or: [{ senderFingerprint: myFingerprint }, { recipientFingerprint: myFingerprint }] }).toArray(); const partnerPointers = new Set(); messages.forEach(msg => { partnerPointers.add(msg.senderPointer); partnerPointers.add(msg.recipientPointer); }); const partnerPublicKeys = Array.from(partnerPointers).map(decryptPointer).filter(Boolean); let partners = []; if (partnerPublicKeys.length > 0) { partners = await usersCollection.find({ publicKey: { $in: partnerPublicKeys } }, { projection: { username: 1, publicKey: 1, _id: 0 } }).toArray(); } socket.emit('conversations list', partners); } catch(err) { console.error("Sohbet listesi çekilirken hata:", err); socket.emit('conversations list', []); } });
    socket.on('private message', async (data) => { if (!socket.publicKey || !data.recipientPublicKey) return; const dbData = { senderPointer: encryptPointer(socket.publicKey), recipientPointer: encryptPointer(data.recipientPublicKey), senderFingerprint: pointerFingerprint(socket.publicKey), recipientFingerprint: pointerFingerprint(data.recipientPublicKey), ciphertext_for_recipient: data.ciphertext_for_recipient, ciphertext_for_sender: data.ciphertext_for_sender, timestamp: new Date() }; try { await dmMessagesCollection.insertOne(dbData); if (data.recipientPublicKey !== socket.publicKey) { io.to(data.recipientPublicKey).emit('private message', { ciphertext: data.ciphertext_for_recipient, senderPublicKey: socket.publicKey }); } } catch (err) { console.error("Özel mesaj gönderilirken hata:", err); } });
    socket.onAny(async () => { if (socket.publicKey) { await redisClient.expire(`user:${socket.publicKey}`, 300); } });
    socket.on('get conversation history', async (otherUserPublicKey) => { if (!socket.publicKey) return; let history; if (otherUserPublicKey === null) { history = await generalMessagesCollection.find({}).sort({ _id: -1 }).limit(100).toArray(); history.reverse(); } else { const myFingerprint = pointerFingerprint(socket.publicKey); const otherFingerprint = pointerFingerprint(otherUserPublicKey); history = await dmMessagesCollection.find({ $or: [{ senderFingerprint: myFingerprint, recipientFingerprint: otherFingerprint }, { senderFingerprint: otherFingerprint, recipientFingerprint: myFingerprint }] }).sort({ timestamp: -1 }).limit(100).toArray(); history.reverse(); } socket.emit('conversation history', { history: history, partnerPublicKey: otherUserPublicKey }); });
});

setInterval(updateOnlineUsersCache, 5000);
