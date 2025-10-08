// /serversocket.js (Düzeltilmiş ve Tam Hali)
const { RateLimiterMemory } = require('rate-limiter-flexible');
const nacl = require('tweetnacl');
const { createAdapter } = require('@socket.io/redis-adapter');

// ✅ Not: Aşağıdaki require yolları, dosya yapına göre zaten doğru.
// 'servercrypto.js' ve 'servermongo.js' dosyaları 'serversocket.js' ile aynı dizinde bulunuyor.
const Crypto = require('./servercrypto.js');
const Mongo = require('./servermongo.js');

const GENERAL_CHAT_ROOM = 'general_chat_room';

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

    const NONCE_EXPIRE_SECONDS = 300; // Nonce'lar için 5 dakikalık son kullanma tarihi

    io.use(async (socket, next) => {
        try {
            await rateLimiter.consume(socket.handshake.address);

            const { publicKey, signature, nonce } = socket.handshake.auth;
            if (!publicKey || !signature || !nonce) {
                return next(new Error('Kimlik doğrulama hatası: Bilgiler eksik.'));
            }

            // --- REPLAY ATTACK KORUMASI ---
            const nonceKey = `nonce:${nonce}`;
            const nonceUsed = await redisClient.get(nonceKey);
            if (nonceUsed) {
                return next(new Error('Tekrar saldırısı tespit edildi: Bu anahtar daha önce kullanılmış.'));
            }

            const nonceTimestampHex = nonce.substring(0, 16);
            const nonceTimestamp = parseInt(nonceTimestampHex, 16);
            if (isNaN(nonceTimestamp) || Math.abs(Date.now() - nonceTimestamp) > NONCE_EXPIRE_SECONDS * 1000) {
                return next(new Error('Kimlik doğrulama hatası: Anahtarın süresi dolmuş.'));
            }
            
            const signPublicKeyBytes = Buffer.from(publicKey, 'base64');
            const nonceBuffer = Buffer.from(nonce, 'hex');
            const signatureBuffer = Buffer.from(signature, 'base64');
            const isVerified = nacl.sign.detached.verify(nonceBuffer, signatureBuffer, signPublicKeyBytes);

            if (!isVerified) {
                return next(new Error('Kimlik doğrulama hatası: İmza geçersiz.'));
            }

            await redisClient.setEx(nonceKey, NONCE_EXPIRE_SECONDS, '1');

            socket.signPublicKey = publicKey;
            next();

        } catch (e) {
            if (e.msBeforeNext) {
                return next(new Error('Çok fazla istek gönderdiniz. Lütfen yavaşlayın.'));
            }
            console.error("Auth hatası (server):", e.message);
            return next(new Error('Kimlik doğrulama hatası: Hatalı format veya sunucu hatası.'));
        }
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
                const myFingerprint = Crypto.pointerFingerprint(socket.publicKey);
                if (!myFingerprint) return;
                const recentMessages = await dmMessagesCollection.find({ $or: [{ senderFingerprint: myFingerprint }, { recipientFingerprint: myFingerprint }] }, { projection: { senderPointer: 1, recipientPointer: 1, _id: 0 } }).sort({ timestamp: -1 }).limit(100).toArray();
                const partnerPublicKeys = new Set();
                recentMessages.forEach(msg => {
                    const senderPK = Crypto.decryptPointer(msg.senderPointer);
                    const recipientPK = Crypto.decryptPointer(msg.recipientPointer);
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
                
                const dbData = { 
                    senderPointer: Crypto.encryptPointer(socket.publicKey), 
                    recipientPointer: Crypto.encryptPointer(data.recipientPublicKey), 
                    senderFingerprint: Crypto.pointerFingerprint(socket.publicKey), 
                    recipientFingerprint: Crypto.pointerFingerprint(data.recipientPublicKey), 
                    ciphertext_for_recipient: data.ciphertext_for_recipient, 
                    timestamp: new Date() 
                };
                
                // client.js'den ciphertext_for_sender geliyorsa onu da kaydet
                if(data.ciphertext_for_sender) {
                    dbData.ciphertext_for_sender = data.ciphertext_for_sender;
                }
                
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
                const myFingerprint = Crypto.pointerFingerprint(socket.publicKey);
                const otherFingerprint = Crypto.pointerFingerprint(otherUserPublicKey);
                history = await dmMessagesCollection.find({ 
                    $or: [
                        { senderFingerprint: myFingerprint, recipientFingerprint: otherFingerprint }, 
                        { senderFingerprint: otherFingerprint, recipientFingerprint: myFingerprint }
                    ] 
                }).sort({ timestamp: -1 }).limit(100).toArray();
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

module.exports = {
    setupRedisAdapter,
    initializeSocketListeners
};
