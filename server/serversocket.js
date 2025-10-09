// /server/serversocket.js (GÜNCEL SÜRÜM - decryptPointer Hatası Düzeltildi)
const { RateLimiterMemory } = require('rate-limiter-flexible');
const nacl = require('tweetnacl');
const { createAdapter } = require('@socket.io/redis-adapter');
const { ObjectId } = require('mongodb');

const Crypto = require('./servercrypto.js');
const Mongo = require('./servermongo.js');

const GENERAL_CHAT_ROOM = 'general_chat_room';

// ... (setupRedisAdapter fonksiyonu aynı kalıyor)
async function setupRedisAdapter(io) {
    const redis = require('redis');
    const redisClient = redis.createClient({ url: 'redis://localhost:6379' });
    redisClient.on('error', (err) => console.error('!!! [Sunucu] Redis Client Hatası:', err));
    const pubClient = redisClient.duplicate();
    const subClient = redisClient.duplicate();
    console.log('[Sunucu] Redis Adapter kurulumu deneniyor...');
    await Promise.all([redisClient.connect(), pubClient.connect(), subClient.connect()]);
    io.adapter(createAdapter(pubClient, subClient));
    console.log("✅ [Sunucu] Socket.IO Redis Adapter'a bağlandı.");
    return redisClient;
}


function initializeSocketListeners(io, redisClient) {
    const { dmMessagesCollection, generalMessagesCollection, usersCollection } = Mongo.getCollections();
    const rateLimiter = new RateLimiterMemory({ points: 10, duration: 1 });
    const messageLimiter = new RateLimiterMemory({ points: 5, duration: 2 });
    const privateMessageLimiter = new RateLimiterMemory({ points: 10, duration: 2 });
    const NONCE_EXPIRE_SECONDS = 300;

    // ... (io.use middleware fonksiyonu aynı kalıyor)
    io.use(async (socket, next) => {
        try {
            await rateLimiter.consume(socket.handshake.address);
            const { publicKey, signature, nonce } = socket.handshake.auth;
            if (!publicKey || !signature || !nonce) return next(new Error('Kimlik doğrulama hatası: Bilgiler eksik.'));
            const nonceKey = `nonce:${nonce}`;
            if (await redisClient.get(nonceKey)) return next(new Error('Tekrar saldırısı tespit edildi.'));
            const nonceTimestampHex = nonce.substring(0, 16);
            const nonceTimestamp = parseInt(nonceTimestampHex, 16);
            if (isNaN(nonceTimestamp) || Math.abs(Date.now() - nonceTimestamp) > NONCE_EXPIRE_SECONDS * 1000) return next(new Error('Anahtarın süresi dolmuş.'));
            const signPublicKeyBytes = Buffer.from(publicKey, 'base64');
            const nonceBuffer = Buffer.from(nonce, 'hex');
            const signatureBuffer = Buffer.from(signature, 'base64');
            if (!nacl.sign.detached.verify(nonceBuffer, signatureBuffer, signPublicKeyBytes)) return next(new Error('İmza geçersiz.'));
            await redisClient.setEx(nonceKey, NONCE_EXPIRE_SECONDS, '1');
            socket.signPublicKey = publicKey;
            next();
        } catch (e) {
            if (e.msBeforeNext) return next(new Error('Çok fazla istek.'));
            console.error("Auth hatası (server):", e.message);
            return next(new Error('Hatalı format veya sunucu hatası.'));
        }
    });

    io.on('connection', (socket) => {
        // ... (Diğer listener'lar aynı)
        console.log(`[Bağlantı] Yeni istemci: ${socket.id}`);
        socket.isAuthenticated = false;

        socket.on('user authenticated', async (userData) => {
            if (socket.isAuthenticated) return;
            try {
                if (!userData.boxPublicKey || !userData.username || !/^.{3,15}$/.test(userData.username)) {
                    socket.disconnect();
                    return;
                }
                
                const existingUserByUsername = await usersCollection.findOne({ username: userData.username });

                if (existingUserByUsername && existingUserByUsername.publicKey !== userData.boxPublicKey) {
                    console.log(`[Kimlik Doğrulama] Başarısız: '${userData.username}' adı zaten alınmış.`);
                    socket.emit('auth_error', { message: 'Bu kullanıcı adı zaten başkası tarafından kullanılıyor.' });
                    socket.disconnect();
                    return;
                }
                
                socket.username = userData.username;
                socket.publicKey = userData.boxPublicKey;
                socket.isAuthenticated = true;
                console.log(`[Kimlik Doğrulama] Başarılı: ${socket.username} (${socket.id})`);
                socket.join(socket.publicKey);
                socket.join(GENERAL_CHAT_ROOM);
                await usersCollection.updateOne({ publicKey: socket.publicKey }, { $set: { username: userData.username } }, { upsert: true });
                await redisClient.sAdd('online_users_set', socket.publicKey);
                const onlineKeys = await redisClient.sMembers('online_users_set');
                const onlineUsers = await usersCollection.find({ publicKey: { $in: onlineKeys } }, { projection: { username: 1, publicKey: 1, _id: 0 } }).toArray();
                socket.emit('initial user list', onlineUsers);
                socket.broadcast.emit('user connected', { username: userData.username, publicKey: socket.publicKey });
            } catch (error) {
                console.error(`[HATA] 'user authenticated': ${error.message}`, error);
                socket.disconnect();
            }
        });

        socket.on('get conversations', async () => {
            if (!socket.isAuthenticated) return;
            try {
                if (!socket.publicKey) return;
                const myFingerprint = Crypto.pointerFingerprint(socket.publicKey);
                if (!myFingerprint) return;
                const recentMessages = await dmMessagesCollection.find({ $or: [{ senderFingerprint: myFingerprint }, { recipientFingerprint: myFingerprint }] }, { projection: { senderPointer: 1, recipientPointer: 1, _id: 0 } }).sort({ timestamp: -1 }).limit(100).toArray();
                const partnerPublicKeys = new Set();
                recentMessages.forEach(msg => {
                    const senderPK = Crypto.decryptPointer(msg.senderPointer);
                    const recipientPK = Crypto.decryptPointer(msg.recipientPointer);

                    if (senderPK && senderPK !== socket.publicKey) partnerPublicKeys.add(senderPK);
                    if (recipientPK && recipientPK !== socket.publicKey) partnerPublicKeys.add(recipientPK);
                    
                    if (senderPK && recipientPK && senderPK === socket.publicKey && recipientPK === socket.publicKey) {
                        partnerPublicKeys.add(socket.publicKey);
                    }
                });
                const partners = await usersCollection.find({ publicKey: { $in: Array.from(partnerPublicKeys) } }, { projection: { username: 1, publicKey: 1, _id: 0 } }).toArray();
                socket.emit('conversations list', partners);
            } catch (err) {
                console.error(`[HATA] 'get conversations': ${err.message}`, err);
            }
        });

        socket.on('chat message', async (msg, callback) => {
            if (!socket.isAuthenticated) return;
            try {
                await messageLimiter.consume(socket.publicKey);
                if (!socket.username || !msg || typeof msg.message !== 'string') return;
                const message = msg.message.trim();
                if (message.length === 0 || message.length > 5000) {
                    if (typeof callback === 'function') callback({ status: 'error', message: 'Geçersiz mesaj.' });
                    return;
                }
                const expireDate = new Date(Date.now() + 86400 * 1000);
                
                const dbData = { 
                    username: socket.username, 
                    message: message, 
                    timestamp: new Date(), 
                    expireAt: expireDate,
                    senderPointer: Crypto.encryptPointer(socket.publicKey)
                };
                await generalMessagesCollection.insertOne(dbData);

                const broadcastData = {
                    ...dbData,
                    publicKey: socket.publicKey
                };
                delete broadcastData.senderPointer;

                socket.broadcast.to(GENERAL_CHAT_ROOM).emit('chat message', broadcastData);
                if (typeof callback === 'function') callback({ status: 'ok' });
            } catch (rejRes) {
                if (typeof callback === 'function') callback({ status: 'error', message: 'Çok hızlı mesaj gönderiyorsun.' });
            }
        });

        // --- BAŞLANGIÇ: 'private message' DÜZELTMESİ ---
        socket.on('private message', async (data) => {
            if (!socket.isAuthenticated) return;
            try {
                await privateMessageLimiter.consume(socket.publicKey);
                if (!socket.publicKey || !data.recipientPublicKey) return;
                const dbData = { 
                    senderPointer: Crypto.encryptPointer(socket.publicKey), 
                    recipientPointer: Crypto.encryptPointer(data.recipientPublicKey), 
                    senderFingerprint: Crypto.pointerFingerprint(socket.publicKey), 
                    recipientFingerprint: Crypto.pointerFingerprint(data.recipientPublicKey), 
                    ciphertext_for_recipient: data.ciphertext_for_recipient, 
                    timestamp: new Date() 
                };
                if(data.ciphertext_for_sender) {
                    dbData.ciphertext_for_sender = data.ciphertext_for_sender;
                }
                const result = await dmMessagesCollection.insertOne(dbData);
                
                // İstemciye gönderilecek obje (şifreli pointer'lar yerine açık public key'ler)
                const messageForClient = { 
                    ...dbData, 
                    _id: result.insertedId,
                    senderPublicKey: socket.publicKey,
                    recipientPublicKey: data.recipientPublicKey
                };
                delete messageForClient.senderPointer;
                delete messageForClient.recipientPointer;

                if (data.recipientPublicKey !== socket.publicKey) {
                    io.to(data.recipientPublicKey).emit('private message', messageForClient);
                }
                socket.emit('private message', messageForClient);

                const recipientUser = await usersCollection.findOne({ publicKey: data.recipientPublicKey }, { projection: { username: 1, publicKey: 1, _id: 0 } });
                if (recipientUser) {
                    socket.emit('new_conversation_partner', recipientUser);
                }
            } catch (error) {
                 if (error.msBeforeNext) {
                    console.log(`Rate limit (DM) aşıldı: ${socket.username}`);
                } else {
                    console.error(`[HATA] 'private message': ${error.message}`, error);
                }
            }
        });
        // --- BİTİŞ: 'private message' DÜZELTMESİ ---

        socket.on('delete private message', async (messageId) => {
            if (!socket.isAuthenticated || !messageId) return;
            
            try {
                const msgToDelete = await dmMessagesCollection.findOne({ _id: new ObjectId(messageId) });

                if (!msgToDelete) {
                    console.warn(`[GÜVENLİK] Silinmek istenen mesaj bulunamadı: ${messageId}`);
                    return;
                }

                const senderPK = Crypto.decryptPointer(msgToDelete.senderPointer);
                
                if (senderPK !== socket.publicKey) {
                    console.warn(`[GÜVENLİK] Yetkisiz silme denemesi! Kullanıcı: ${socket.publicKey}, Mesaj Sahibi: ${senderPK}`);
                    return;
                }

                const recipientPK = Crypto.decryptPointer(msgToDelete.recipientPointer);

                await dmMessagesCollection.deleteOne({ _id: new ObjectId(messageId) });
                
                io.to(senderPK).to(recipientPK).emit('private message deleted', messageId);
                console.log(`[Mesaj Silme] ${senderPK} kullanıcısı mesajını (${messageId}) sildi.`);

            } catch (error) {
                console.error(`[HATA] 'delete private message': ${error.message}`, error);
            }
        });
        
        // --- BAŞLANGIÇ: 'get conversation history' DÜZELTMESİ ---
        socket.on('get conversation history', async (otherUserPublicKey) => {
            if (!socket.isAuthenticated) return;
            try {
                let history;
                if (otherUserPublicKey === null) {
                    history = await generalMessagesCollection.find({}).sort({ _id: -1 }).limit(100).toArray();
                    history.forEach(msg => {
                        if (msg.senderPointer) {
                            msg.publicKey = Crypto.decryptPointer(msg.senderPointer);
                            delete msg.senderPointer;
                        }
                    });
                } else {
                    const expectedKeyLength = 43;
                    const base64UrlRegex = /^[A-Za-z0-9\-_]+$/;
                    if (typeof otherUserPublicKey !== 'string' || otherUserPublicKey.length !== expectedKeyLength || !base64UrlRegex.test(otherUserPublicKey)) {
                        console.warn(`[GÜVENLİK] Geçersiz publicKey formatı: ${otherUserPublicKey}`);
                        return;
                    }
                    const myFingerprint = Crypto.pointerFingerprint(socket.publicKey);
                    const otherFingerprint = Crypto.pointerFingerprint(otherUserPublicKey);
                    history = await dmMessagesCollection.find({ 
                        $or: [
                            { senderFingerprint: myFingerprint, recipientFingerprint: otherFingerprint }, 
                            { senderFingerprint: otherFingerprint, recipientFingerprint: myFingerprint }
                        ] 
                    }).sort({ timestamp: -1 }).limit(100).toArray();

                    // DM geçmişi için de şifreli pointer'ları çöz
                    history.forEach(msg => {
                        if (msg.senderPointer) msg.senderPublicKey = Crypto.decryptPointer(msg.senderPointer);
                        if (msg.recipientPointer) msg.recipientPublicKey = Crypto.decryptPointer(msg.recipientPointer);
                        delete msg.senderPointer;
                        delete msg.recipientPointer;
                    });
                }
                history.reverse();
                socket.emit('conversation history', { history: history, partnerPublicKey: otherUserPublicKey });
            } catch (err) {
                 console.error(`[HATA] 'get conversation history': ${err.message}`, err);
            }
        });
        // --- BİTİŞ: 'get conversation history' DÜZELTMESİ ---

        // ... (heartbeat ve disconnect aynı)
        socket.on('heartbeat', async () => {
            if (!socket.isAuthenticated) return;
            if (socket.publicKey) await redisClient.setEx(`user:${socket.publicKey}:heartbeat`, 45, '1');
        });

        socket.on('disconnect', async () => {
            console.log(`[Bağlantı Kesildi] ${socket.username || socket.id}`);
            if (socket.publicKey) {
                const removedCount = await redisClient.sRem('online_users_set', socket.publicKey);
                if (removedCount > 0) {
                    io.emit('user disconnected', { publicKey: socket.publicKey });
                }
            }
        });

    });

    const CLEANUP_INTERVAL = 15000;
    setInterval(async () => {
        try {
            const onlineKeys = await redisClient.sMembers('online_users_set');
            for (const publicKey of onlineKeys) {
                const heartbeatExists = await redisClient.exists(`user:${publicKey}:heartbeat`);
                if (!heartbeatExists) {
                    console.log(`[Temizlik] Hayalet kullanıcı siliniyor: ${publicKey}`);
                    await redisClient.sRem('online_users_set', publicKey);
                    io.emit('user disconnected', { publicKey: publicKey });
                }
            }
        } catch (error) {
            console.error('[Temizlik] Hata:', error);
        }
    }, CLEANUP_INTERVAL);
}

module.exports = {
    setupRedisAdapter,
    initializeSocketListeners
};
