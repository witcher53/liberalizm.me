// /server/serversocket.js (MongoDB Injection Koruması Eklenmiş Tam Sürüm)

const { RateLimiterRedis } = require('rate-limiter-flexible');
const nacl = require('tweetnacl');
const { createAdapter } = require('@socket.io/redis-adapter');
const { ObjectId } = require('mongodb');
const Redis = require('ioredis');

const Crypto = require('./servercrypto.js');
const Mongo = require('./servermongo.js');
const MLMPManager = require('./mlmp-manager.js');

const GENERAL_CHAT_ROOM = 'general_chat_room';

async function setupRedisAdapter(io) {
    console.log('[Sunucu] ioredis Adapter kurulumu deneniyor...');
    const redisClient = new Redis();
    const pubClient = redisClient.duplicate();
    const subClient = redisClient.duplicate();

    io.adapter(createAdapter(pubClient, subClient));
    console.log("✅ [Sunucu] Socket.IO ioredis Adapter'a bağlandı.");
    return redisClient;
}

function initializeSocketListeners(io, redisClient) {
    const { dmMessagesCollection, usersCollection } = Mongo.getCollections();
    const mlmpManager = new MLMPManager();
    mlmpManager.initialize(io);

    const limiterOptions = {
        storeClient: redisClient,
        keyPrefix: 'limit',
        points: 10,
        duration: 1,
    };

    const rateLimiter = new RateLimiterRedis({ ...limiterOptions, keyPrefix: 'limit_conn', points: 15, duration: 5 });
    const messageLimiter = new RateLimiterRedis({ ...limiterOptions, keyPrefix: 'limit_msg_gen', points: 5, duration: 3 });
    const privateMessageLimiter = new RateLimiterRedis({ ...limiterOptions, keyPrefix: 'limit_msg_priv', points: 10, duration: 3 });
    const searchLimiter = new RateLimiterRedis({ ...limiterOptions, keyPrefix: 'limit_search', points: 5, duration: 20, blockDuration: 300 });

    const NONCE_EXPIRE_SECONDS = 300;
    const GENERAL_CHAT_REDIS_KEY = 'general_chat_history';
    const MAX_GENERAL_MESSAGES = 50;

    io.use(async (socket, next) => {
        try {
            await rateLimiter.consume(socket.handshake.address);
            const { publicKey, signature, nonce } = socket.handshake.auth;
            if (!publicKey || !signature || !nonce) return next(new Error('Kimlik doğrulama hatası: Bilgiler eksik.'));
            const nonceKey = `nonce:${nonce}`;
            const nonceExists = await redisClient.get(nonceKey);
            if (nonceExists) return next(new Error('Tekrar saldırısı tespit edildi.'));
            const nonceTimestampHex = nonce.substring(0, 16);
            const nonceTimestamp = parseInt(nonceTimestampHex, 16);
            if (isNaN(nonceTimestamp) || Math.abs(Date.now() - nonceTimestamp) > NONCE_EXPIRE_SECONDS * 1000) return next(new Error('Anahtarın süresi dolmuş.'));
            const signPublicKeyBytes = Buffer.from(publicKey, 'base64');
            const nonceBuffer = Buffer.from(nonce, 'hex');
            const signatureBuffer = Buffer.from(signature, 'base64');
            if (!nacl.sign.detached.verify(nonceBuffer, signatureBuffer, signPublicKeyBytes)) return next(new Error('İmza geçersiz.'));
            await redisClient.setex(nonceKey, NONCE_EXPIRE_SECONDS, '1');
            socket.signPublicKey = publicKey;
            next();
        } catch (e) {
            if (e instanceof Error && e.msBeforeNext) {
                console.warn(`[RATE LIMIT] IP Engellendi: ${socket.handshake.address}`);
                return next(new Error('Çok fazla istek.'));
            }
            console.error("!!! KRİTİK AUTH MIDDLEWARE HATASI !!!", { message: e.message, ip: socket.handshake.address });
            return next(new Error('Sunucu yapılandırma hatası. Lütfen tekrar deneyin.'));
        }
    });

    io.on('connection', (socket) => {
        console.log(`[Bağlantı] Yeni istemci: ${socket.id}`);
        socket.isAuthenticated = false;

        socket.on('user authenticated', async (userData) => {
            if (socket.isAuthenticated) return;
            try {
                if (!userData.boxPublicKey || !userData.username || !/^.{3,15}$/.test(userData.username)) {
                    socket.disconnect(); return;
                }
                const onionPointer = await mlmpManager.encryptMetadata(userData.boxPublicKey);
                const existingUserByUsername = await usersCollection.findOne({ username: userData.username });
                if (existingUserByUsername && existingUserByUsername.publicKey !== userData.boxPublicKey) {
                    socket.emit('auth_error', { message: 'Bu kullanıcı adı zaten başkası tarafından kullanılıyor.' });
                    socket.disconnect(); return;
                }
                socket.username = userData.username;
                socket.publicKey = userData.boxPublicKey;
                socket.isAuthenticated = true;
                console.log(`[Kimlik Doğrulama] Başarılı: ${socket.username} (${socket.id})`);
                socket.join(socket.publicKey);
                socket.join(GENERAL_CHAT_ROOM);
                await usersCollection.updateOne(
                    { publicKey: socket.publicKey },
                    { 
                        $set: { 
                            username: userData.username,
                            mlmp: {
                                onionPointer: onionPointer.onion,
                                epoch: onionPointer.epoch,
                                lastSeen: new Date()
                            }
                        } 
                    }, 
                    { upsert: true }
                );
                await redisClient.sadd('online_users_set', socket.publicKey);
                const onlineKeys = await redisClient.smembers('online_users_set');
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

        // ✅ GÜNCELLEME: 'search users' fonksiyonu NoSQL Injection'a karşı güçlendirildi.
        socket.on('search users', async (query) => {
            if (!socket.isAuthenticated) return;
            try {
                await searchLimiter.consume(socket.publicKey);
                const searchQuery = String(query || '').trim();

                if (searchQuery.length < 3 || searchQuery.length > 15) {
                    socket.emit('search results', []);
                    return;
                }
                
                // ❌ ESKİ RİSKLİ YÖNTEM
                // const escapedQuery = searchQuery.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                // const users = await usersCollection.find({
                //     username: { $regex: `^${escapedQuery}`, $options: 'i' }, ...

                // ✅ YENİ GÜVENLİ YÖNTEM (RegEx kullanmadan)
                const users = await usersCollection.find({
                    username: {
                        $gte: searchQuery,
                        $lt: searchQuery + 'z' // 'wit' ile başlayanları bulmak için 'wit' ile 'witz' arasındakileri ara
                    },
                    publicKey: { $ne: socket.publicKey }
                })
                .collation({ locale: 'en', strength: 2 }) // Büyük/küçük harf duyarsız arama için
                .limit(5)
                .project({ username: 1, publicKey: 1, _id: 0 }).toArray();
                
                socket.emit('search results', users);
            } catch (err) {
                if (!err.msBeforeNext) console.error(`[HATA] 'search users': ${err.message}`, err);
                socket.emit('search results', []);
            }
        });

        socket.on('chat message', async (msg, callback) => {
            if (!socket.isAuthenticated) return;
            try {
                await messageLimiter.consume(socket.publicKey);
                const message = (msg && typeof msg.message === 'string') ? msg.message.trim() : '';
                if (!socket.username || message.length === 0 || message.length > 5000) return;
                const redisData = { username: socket.username, message, timestamp: new Date(), publicKey: socket.publicKey };
                await redisClient.lpush(GENERAL_CHAT_REDIS_KEY, JSON.stringify(redisData));
                await redisClient.ltrim(GENERAL_CHAT_REDIS_KEY, 0, MAX_GENERAL_MESSAGES - 1);
                socket.broadcast.to(GENERAL_CHAT_ROOM).emit('chat message', redisData);
                if (typeof callback === 'function') callback({ status: 'ok' });
            } catch (rejRes) {
                 if (typeof callback === 'function') callback({ status: 'error', message: 'Çok hızlı mesaj gönderiyorsun.' });
            }
        });

        socket.on('private message', async (data) => {
            if (!socket.isAuthenticated) return;
            try {
                await privateMessageLimiter.consume(socket.publicKey);
                if (!socket.publicKey || !data.recipientPublicKey) return;

                const senderOnion = await mlmpManager.encryptMetadata(socket.publicKey);
                const recipientOnion = await mlmpManager.encryptMetadata(data.recipientPublicKey);
                const senderRouting = await mlmpManager.serverDecryptRouting(senderOnion);
                const recipientRouting = await mlmpManager.serverDecryptRouting(recipientOnion);
                const encryptedSenderRoutingHash = Crypto.encryptPointer(senderRouting.routingInfo);
                const encryptedRecipientRoutingHash = Crypto.encryptPointer(recipientRouting.routingInfo);
                const senderFingerprint = Crypto.pointerFingerprint(socket.publicKey);
                const recipientFingerprint = Crypto.pointerFingerprint(data.recipientPublicKey);
                
                const dbData = { 
                    senderPointer: Crypto.encryptPointer(socket.publicKey),
                    recipientPointer: Crypto.encryptPointer(data.recipientPublicKey),
                    senderFingerprint: senderFingerprint,
                    recipientFingerprint: recipientFingerprint,
                    mlmp: {
                        senderOnion: senderOnion.onion,
                        recipientOnion: recipientOnion.onion,
                        epoch: senderOnion.epoch,
                        encryptedSenderRoutingHash: encryptedSenderRoutingHash,
                        encryptedRecipientRoutingHash: encryptedRecipientRoutingHash,
                        bucketId: mlmpManager.timing.timeBucketing.bucketizeTimestamp().bucketId,
                        layers: 3
                    },
                    ciphertext_for_recipient: data.ciphertext_for_recipient, 
                    timestamp: new Date(),
                    messageType: data.messageType || 'text',
                    ...(data.ciphertext_for_sender && { ciphertext_for_sender: data.ciphertext_for_sender })
                 };

                mlmpManager.queueMessage(dbData, async (messageWithTiming) => {
                    const result = await dmMessagesCollection.insertOne(messageWithTiming);
                    const messageForClient = { 
                        ...messageWithTiming, 
                        _id: result.insertedId, 
                        senderPublicKey: socket.publicKey, 
                        recipientPublicKey: data.recipientPublicKey 
                    };
                    
                    delete messageForClient.senderPointer;
                    delete messageForClient.recipientPointer;
                    delete messageForClient.mlmp;

                    if (data.recipientPublicKey !== socket.publicKey) {
                        io.to(data.recipientPublicKey).emit('private message', messageForClient);
                    }
                    socket.emit('private message', messageForClient);
                });

                const recipientUser = await usersCollection.findOne({ publicKey: data.recipientPublicKey }, { projection: { username: 1, publicKey: 1, _id: 0 } });
                if (recipientUser) socket.emit('new_conversation_partner', recipientUser);
            } catch (error) {
                 if (!error.msBeforeNext) console.error(`[HATA] 'private message': ${error.message}`, error);
            }
        });

        socket.on('delete private message', async (messageId) => {
            if (!socket.isAuthenticated || !messageId) return;
            try {
                const msgToDelete = await dmMessagesCollection.findOne({ _id: new ObjectId(messageId) });
                if (!msgToDelete) return;
                const senderPK = Crypto.decryptPointer(msgToDelete.senderPointer);
                if (senderPK !== socket.publicKey) return;
                const recipientPK = Crypto.decryptPointer(msgToDelete.recipientPointer);
                await dmMessagesCollection.deleteOne({ _id: new ObjectId(messageId) });
                io.to(senderPK).to(recipientPK).emit('private message deleted', messageId);
            } catch (error) {
                console.error(`[HATA] 'delete private message': ${error.message}`, error);
            }
        });
        
        socket.on('get conversation history', async (otherUserPublicKey) => {
            if (!socket.isAuthenticated) return;
            try {
                let history;
                if (otherUserPublicKey === null) {
                    const results = await redisClient.lrange(GENERAL_CHAT_REDIS_KEY, 0, MAX_GENERAL_MESSAGES - 1);
                    history = results.map(item => JSON.parse(item)).reverse();
                } else {
                    const myFingerprint = Crypto.pointerFingerprint(socket.publicKey);
                    const otherFingerprint = Crypto.pointerFingerprint(otherUserPublicKey);

                    const myOnion = await mlmpManager.encryptMetadata(socket.publicKey);
                    const otherOnion = await mlmpManager.encryptMetadata(otherUserPublicKey);
                    const myRouting = await mlmpManager.serverDecryptRouting(myOnion);
                    const otherRouting = await mlmpManager.serverDecryptRouting(otherOnion);

                    const encryptedMyRoutingHash = Crypto.encryptPointer(myRouting.routingInfo);
                    const encryptedOtherRoutingHash = Crypto.encryptPointer(otherRouting.routingInfo);

                    const query = {
                        $or: [
                            {
                                'mlmp.encryptedSenderRoutingHash': encryptedMyRoutingHash,
                                'mlmp.encryptedRecipientRoutingHash': encryptedOtherRoutingHash
                            },
                            {
                                'mlmp.encryptedSenderRoutingHash': encryptedOtherRoutingHash,
                                'mlmp.encryptedRecipientRoutingHash': encryptedMyRoutingHash
                            },
                            {
                                senderFingerprint: myFingerprint,
                                recipientFingerprint: otherFingerprint
                            },
                            {
                                senderFingerprint: otherFingerprint,
                                recipientFingerprint: myFingerprint
                            }
                        ]
                    };

                    history = await dmMessagesCollection.find(query)
                        .sort({ timestamp: 1 })
                        .limit(200)
                        .toArray();
                    
                    history.forEach(msg => {
                        if (msg.senderPointer) msg.senderPublicKey = Crypto.decryptPointer(msg.senderPointer);
                        if (msg.recipientPointer) msg.recipientPublicKey = Crypto.decryptPointer(msg.recipientPointer);
                        
                        delete msg.senderPointer;
                        delete msg.recipientPointer;
                        delete msg.mlmp;
                        delete msg.senderFingerprint;
                        delete msg.recipientFingerprint;
                    });
                }
                socket.emit('conversation history', { history: history, partnerPublicKey: otherUserPublicKey });
            } catch (err) {
                 console.error(`[HATA] 'get conversation history': ${err.message}`, err);
            }
        });

        socket.on('heartbeat', () => {
            if (socket.isAuthenticated && socket.publicKey) {
                redisClient.setex(`user:${socket.publicKey}:heartbeat`, 45, '1');
            }
        });

        socket.on('disconnect', async () => {
            console.log(`[Bağlantı Kesildi] ${socket.username || socket.id}`);
            if (socket.publicKey) {
                const removedCount = await redisClient.srem('online_users_set', socket.publicKey);
                if (removedCount > 0) {
                    io.emit('user disconnected', { publicKey: socket.publicKey });
                }
            }
        });
    });
    
    setInterval(async () => {
        try {
            const onlineKeys = await redisClient.smembers('online_users_set');
            for (const publicKey of onlineKeys) {
                const heartbeatExists = await redisClient.exists(`user:${publicKey}:heartbeat`);
                if (!heartbeatExists) {
                    console.warn(`[Temizlik] Hayalet kullanıcı siliniyor: ${publicKey}`);
                    await redisClient.srem('online_users_set', publicKey);
                    io.emit('user disconnected', { publicKey: publicKey });
                }
            }
        } catch (error) {
            console.error('[Temizlik] Hata:', error);
        }
    }, 15000);
}

module.exports = {
    setupRedisAdapter,
    initializeSocketListeners
};
