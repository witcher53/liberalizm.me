// /home/witcher53/mesajlasma-uygulamasi/index.js

require('dotenv').config(); // EKSİK 1: .env dosyasını okumak için eklendi.

const express = require('express');
const http = require('http');
const path = require('path');
const socketIo = require('socket.io');
const { MongoClient } = require('mongodb');
const { createClient } = require('redis');
const crypto = require('crypto');
const cors = require('cors'); // EKSİK 2: CORS paketi dahil edildi.

const app = express();
const server = http.createServer(app);

// GÜNCELLEME: Socket.IO için CORS ayarları eklendi.
const io = new socketIo.Server(server, {
  cors: {
    origin: "https://liberalizm.me",
    methods: ["GET", "POST"]
  }
});

const PORT = 3000;

app.use(express.static(path.join(__dirname, 'public')));

// GÜNCELLEME: Şifre artık kodun içinde değil, .env dosyasından okunuyor.
if (!process.env.MONGODB_URI) {
    console.error("KRİTİK HATA: .env dosyasında MONGODB_URI tanımlı değil! Uygulama başlatılamıyor.");
    process.exit(1);
}
const uri = process.env.MONGODB_URI;


const client = new MongoClient(uri);
let messagesCollection;
let usersCollection;

const redisClient = createClient({
    url: 'redis://127.0.0.1:6379'
});
redisClient.on('error', (err) => console.error('Redis Client Error', err));

async function run() {
    try {
        await client.connect();
        await redisClient.connect();

        const database = client.db('chat_app');
        messagesCollection = database.collection('messages');
        usersCollection = database.collection('users');

        console.log("MongoDB Atlas'a başarıyla bağlanıldı!");
        
        try {
            await messagesCollection.createIndex(
                { "timestamp": 1 },
                { name: "message_ttl_fixed", expireAfterSeconds: 86400, partialFilterExpression: { "conversationHash": { "$exists": false } } }
            );
            console.log("TTL indeksi (fixed) başarıyla oluşturuldu veya zaten mevcuttu.");
        } catch (err) {
            if (err.codeName === 'IndexKeySpecsConflict' || err.code === 48 || err.code === 67 || err.code === 85) {
                 console.log("TTL indeksi zaten mevcut. Başlangıç hatası görmezden gelindi.");
            } else {
                 console.error("TTL indeksi oluşturulurken BEKLENMEDİK KRİTİK HATA:", err);
            }
        }

        server.listen(PORT, '127.0.0.1', () => {
            console.log(`Sunucu ${PORT} portunda dinlemede.`);
        });
    } catch (err) {
        console.error("Veritabanına bağlanırken KRİTİK HATA:", err);
        process.exit(1);
    }
}
run();

function createDMHash(key1, key2) {
    const sortedKeys = [key1, key2].sort().join('-');
    return crypto.createHash('sha256').update(sortedKeys).digest('hex');
}

function createConversationSecret(key1, key2) {
    const sortedKeys = [key1, key2].sort().join('+');
    return crypto.createHash('sha256').update(sortedKeys).digest();
}

async function sendUpdatedUserList() {
    const publicKeys = await redisClient.sMembers('online_users_set');
    const cleanedKeys = [];

    for (const key of publicKeys) {
        const userData = await redisClient.hGetAll(`user:${key}`);
        if (userData && userData.socketId && io.sockets.sockets.has(userData.socketId)) {
            cleanedKeys.push(key);
        } else {
            await redisClient.del(`user:${key}`);
            await redisClient.sRem('online_users_set', key);
        }
    }

    const onlineUsersData = await Promise.all(
        cleanedKeys.map(key => redisClient.hGetAll(`user:${key}`))
    );
    io.emit('update user list', onlineUsersData);
}

io.on('connection', async (socket) => {
    socket.on('add user', async (userData) => {
        if (!userData.publicKey || !userData.username) return;

        socket.username = userData.username;
        socket.publicKey = userData.publicKey;

        await redisClient.sAdd('online_users_set', userData.publicKey);

        try {
            await usersCollection.updateOne(
                { publicKey: userData.publicKey },
                { $set: { username: userData.username } },
                { upsert: true }
            );
        } catch (err) {
            console.error("Kullanıcı kaydedilirken hata:", err);
        }

        const userKey = `user:${socket.publicKey}`;
        await redisClient.hSet(userKey, {
            username: userData.username,
            publicKey: userData.publicKey,
            socketId: socket.id 
        });
        await redisClient.expire(userKey, 60);

        await sendUpdatedUserList(); 
    });

    socket.onAny(async () => {
        if (socket.publicKey) {
            await redisClient.expire(`user:${socket.publicKey}`, 60);
        }
    });

    socket.on('get conversations', async () => {
        if (!socket.publicKey) return;
        try {
            const publicKeys = await redisClient.sMembers('online_users_set');
            const onlineUsersData = await Promise.all(
                publicKeys.map(key => redisClient.hGetAll(`user:${key}`))
            );
            
            const allUsers = await usersCollection.find({ publicKey: { $ne: socket.publicKey } }).toArray();
            const conversationHashPromises = [];

            for (const user of allUsers) {
                const conversationHash = createDMHash(socket.publicKey, user.publicKey);
                conversationHashPromises.push(
                    messagesCollection.findOne({ conversationHash }, { projection: { _id: 1 } })
                );
            }
            
            const conversationChecks = await Promise.all(conversationHashPromises);
            const historicalPartners = allUsers.filter((user, index) => conversationChecks[index]);

            const finalPartnersMap = new Map();
            onlineUsersData.forEach(user => {
                if (user.publicKey !== socket.publicKey) {
                    finalPartnersMap.set(user.publicKey, { username: user.username, publicKey: user.publicKey });
                }
            });

            historicalPartners.forEach(user => {
                if (user.publicKey !== socket.publicKey && !finalPartnersMap.has(user.publicKey)) {
                     finalPartnersMap.set(user.publicKey, { username: user.username, publicKey: user.publicKey });
                }
            });

            socket.emit('conversations list', Array.from(finalPartnersMap.values()));

        } catch(err) {
            console.error("Geçmiş sohbetler çekilirken hata:", err);
        }
    });

    socket.on('get conversation history', async (otherUserPublicKey) => {
        if (!socket.publicKey) return;
        
        let history;
        if (otherUserPublicKey === null) {
            history = await messagesCollection.find({ 
                "ciphertext_for_recipient": { "$exists": false } 
            })
            .sort({ _id: -1 })
            .limit(100)
            .toArray();
            
            history.reverse(); 
            
        } else {
            const conversationHash = createDMHash(socket.publicKey, otherUserPublicKey);
            
            history = await messagesCollection.find({ conversationHash })
                .sort({ _id: -1 })  
                .limit(100)         
                .toArray();

            history.reverse(); 

            const conversationSecret = createConversationSecret(socket.publicKey, otherUserPublicKey);
            
            history = history.map(msg => {
                if (msg.encryptedMetadata) {
                    try {
                        const parts = msg.encryptedMetadata.split(':');
                        const iv = Buffer.from(parts.shift(), 'hex');
                        const encryptedText = parts.join(':');
                        
                        const decipher = crypto.createDecipheriv('aes-256-cbc', conversationSecret, iv);
                        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
                        decrypted += decipher.final('utf8');
                        
                        const metadata = JSON.parse(decrypted);
                        msg.senderPublicKey = metadata.sender;

                    } catch (e) {
                        console.error("Metadata çözülürken hata:", e);
                        msg.senderPublicKey = null; 
                    }
                }
                return msg;
            });
        }
        socket.emit('conversation history', { history: history, partnerPublicKey: otherUserPublicKey });
    });

    socket.on('chat message', async (msg, callback) => {
        if (!socket.username || !msg.message) return;
        const data = { username: socket.username, message: msg.message, timestamp: new Date() };
        try {
            await messagesCollection.insertOne(data);
            socket.broadcast.emit('chat message', data);
            if (typeof callback === 'function') callback({ status: 'ok' });
        } catch (err) { if (typeof callback === 'function') callback({ status: 'error' }); }
    });

    socket.on('private message', async (data) => { 
        if (!socket.publicKey) return;

        const conversationHash = createDMHash(socket.publicKey, data.recipientPublicKey);
        const conversationSecret = createConversationSecret(socket.publicKey, data.recipientPublicKey);

        const metadataString = JSON.stringify({
            sender: socket.publicKey,
            recipient: data.recipientPublicKey
        });
        
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', conversationSecret, iv);
        let encrypted = cipher.update(metadataString, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const encryptedMetadata = iv.toString('hex') + ':' + encrypted;

        const dbData = {
            conversationHash,
            encryptedMetadata, 
            senderPublicKey: socket.publicKey, 
            ciphertext_for_recipient: data.ciphertext_for_recipient,
            ciphertext_for_sender: data.ciphertext_for_sender,
            timestamp: new Date()
        };

        try {
            await messagesCollection.insertOne(dbData);
            
            const recipientUserKey = `user:${data.recipientPublicKey}`;
            const recipientData = await redisClient.hGetAll(recipientUserKey); 
            let recipientSocketId = recipientData.socketId;

            if (recipientSocketId && io.sockets.sockets.has(recipientSocketId)) {
                io.to(recipientSocketId).emit('private message', { ciphertext: data.ciphertext_for_recipient, senderPublicKey: socket.publicKey });
                io.to(recipientSocketId).emit('dm notification', { from: socket.publicKey });
            }
        } catch (err) { console.error("Özel mesaj gönderilirken hata:", err); }
    });

    socket.on('disconnect', async () => {
        if (socket.publicKey) {
            await redisClient.del(`user:${socket.publicKey}`);
            await redisClient.sRem('online_users_set', socket.publicKey);
            await sendUpdatedUserList(); 
        }
    });

    setInterval(() => {
        sendUpdatedUserList();
    }, 30000);
});
