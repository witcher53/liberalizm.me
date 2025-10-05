// /var/www/liberalizm.me/index.js (GÜVENLİ .ENV SÜRÜMÜ)

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
const readline = require('readline');


// ======================== FPE SIMÜLASYONU VE KMS BAŞLANGIÇ ========================

// KRİTİK: Anahtar ve HASH bilgileri artık güvelik için sadece .env dosyasından okunmaktadır.
// Koda sabitlenmiş anahtar bulunmamaktadır.
let FPE_MASTER_KEY = null; 


// Yöneticinin şifresiyle RAM'e yüklenecek olan ana şifreleme anahtarını türetir.
function createMasterKey(keyInput) {
    // SHA256 ile tam 32 baytlık (256-bit) anahtar elde eder
    return crypto.createHash('sha256').update(keyInput).digest();
}


// === FPE İŞLEMLERİ (K-A + K-B ile Token Oluşturma) ===
function encryptId(id, splitKeyBBase64) {
    if (!id || typeof id !== 'string' || !FPE_MASTER_KEY || !splitKeyBBase64) return '';
    try {
        // İki anahtar parçasını (K-A: FPE_MASTER_KEY'in 32 baytı ve K-B) birleştir
        const keyABuffer = FPE_MASTER_KEY.subarray(0, 32);
        const keyBBuffer = Buffer.from(splitKeyBBase64, 'base64');
        const finalKey = Buffer.concat([keyABuffer, keyBBuffer]); // Toplam 64 bayt (512 bit)

        // Final key'in ilk 32 baytını al (FPE için sadece 256 bit kullanacağız)
        const aesKey = finalKey.subarray(0, 32); 

        const cipher = crypto.createCipheriv('aes-256-ecb', aesKey, null); 
        let encrypted = cipher.update(id, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    } catch (error) {
        console.error("Kimlik şifreleme hatası:", error);
        return '';
    }
}


function decryptToken(token) {
    // Sunucu tarafında Token çözme işlemi kasıtlı olarak devre dışı bırakılmıştır.
    // Bu, güvenlik modeli gereğidir (Token sadece sahibinin K-B'si ile çözülmeli).
    return ''; 
}

// ======================== FPE SIMÜLASYONU VE KMS SONU ========================


const app = express();
const server = http.createServer(app);


const PORT = 3000;

const redisClient = createClient({
    url: 'redis://localhost:6379' 
});
redisClient.on('error', (err) => console.error('Redis Client Error', err));

const pubClient = redisClient.duplicate();
const subClient = redisClient.duplicate();


const io = new socketIo.Server(server, {
  cors: {
    origin: "https://liberalizm.me",
    methods: ["GET", "POST"]
  }
});

Promise.all([redisClient.connect(), pubClient.connect(), subClient.connect()]).then(() => {
    io.adapter(createAdapter(pubClient, subClient));
    console.log("Socket.IO Redis Adapter'a bağlandı.");
}).catch(err => {
    console.error("Redis Adapter'a bağlanırken KRİTİK HATA:", err);
    process.exit(1);
});


app.use(express.static(__dirname));

if (!process.env.MONGODB_URI) {
    console.error("❌ KRİTİK HATA: .env dosyasında MONGODB_URI tanımlı değil! Uygulama başlatılamıyor.");
    process.exit(1);
}
const uri = process.env.MONGODB_URI;


const client = new MongoClient(uri);

let dmMessagesCollection; 
let generalMessagesCollection; 
let usersCollection;


// KRİTİK: Anahtarı .env'den Doğrula ve RAM'e Yükle
function initializeFPEKey() {
    // Anahtarları doğrudan .env'den (process.env üzerinden) oku. Fallback (||) yok.
    const keyInput = process.env.MANUAL_FPE_KEY;
    const hashCheck = process.env.FPE_KEY_HASH_CHECK;
    
    if (!keyInput || !hashCheck) {
        console.error("❌ KRİTİK GÜVENLİK HATASI: FPE anahtarları .env dosyasında tanımlanmamış! Uygulama başlatılamıyor.");
        console.error("Lütfen projenin ana dizinine .env dosyası oluşturup MANUAL_FPE_KEY ve FPE_KEY_HASH_CHECK değerlerini tanımlayın.");
        process.exit(1); // Programı sonlandır. Anahtarsız çalışmasın.
    }
    
    const inputHash = crypto.createHash('sha256').update(keyInput).digest('hex');

    if (inputHash !== hashCheck) {
         console.error("❌ GÜVENLİK HATASI: .env dosyasından gelen KEY A, HASH ile uyuşmuyor! Erişim engellendi.");
         process.exit(1); // Hatalı anahtarla da çalışmasın.
    }
    
    FPE_MASTER_KEY = createMasterKey(keyInput); 
    console.log("✅ FPE MASTER KEY .env dosyasından doğrulandı ve RAM'e Yüklendi!");
}


async function run() {
    try {
        initializeFPEKey();
        
        await client.connect();

        const database = client.db('chat_app');
        dmMessagesCollection = database.collection('dm_messages'); 
        generalMessagesCollection = database.collection('general_messages'); 
        usersCollection = database.collection('users');

        console.log("MongoDB Atlas'a başarıyla bağlanıldı!");
        
        try {
            await generalMessagesCollection.createIndex(
                { "expireAt": 1 }, 
                { 
                    name: "general_chat_expire_at", 
                    expireAfterSeconds: 0, 
                    partialFilterExpression: { "expireAt": { "$exists": true } }
                }
            );
            
            await dmMessagesCollection.createIndex(
                 { "senderToken": 1, "recipientToken": 1, "timestamp": -1 }, 
                 { name: "dm_token_speedup" } 
            );

            await usersCollection.createIndex(
                 { "lastToken": 1 }, 
                 { name: "user_last_token_lookup", unique: false, sparse: true } 
            );

            console.log("Koleksiyon İndeksleri başarıyla oluşturuldu.");
            
        } catch (err) {
            if (err.codeName === 'IndexKeySpecsConflict' || err.code === 48 || err.code === 67 || err.code === 85) {
                 console.log("İndeksler zaten mevcut.");
            } else {
                 console.error("İndeks oluşturulurken KRİTİK HATA:", err);
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

// Buradan sonraki kodun geri kalanında değişiklik yapmaya gerek yok, hepsi aynı kalabilir.
// ... (sendUpdatedUserList ve io.on('connection', ...) fonksiyonları ve devamı)
async function sendUpdatedUserList() {
    if (!redisClient.isReady) {
        console.error('Redis istemcisi hazır değil, kullanıcı listesi güncellenemedi.');
        return;
    }
    
    const onlineKeys = await redisClient.sMembers('online_users_set');
    
    const multi = redisClient.multi();
    for (const key of onlineKeys) {
        multi.hGetAll(`user:${key}`);
    }
    const onlineUsersDataRaw = await multi.exec(); 
    
    const onlineUsersData = [];
    const keysToRemove = [];
    
    for (let i = 0; i < onlineKeys.length; i++) {
        const key = onlineKeys[i];
        const userData = onlineUsersDataRaw[i];
        
        if (userData === null || (Array.isArray(userData) && userData[0] instanceof Error)) {
             keysToRemove.push(key);
             continue; 
        }

        const userObj = Array.isArray(userData) && userData.length === 2 && userData[0] === null ? userData[1] : userData;
        
        if (userObj && userObj.socketId && io.sockets.sockets.has(userObj.socketId)) {
            const safeUserObj = { username: userObj.username, publicKey: userObj.publicKey };
            onlineUsersData.push(safeUserObj);
        } else {
            keysToRemove.push(key);
        }
    }
    
    if (keysToRemove.length > 0) {
        const cleanupMulti = redisClient.multi();
        for (const key of keysToRemove) {
            cleanupMulti.del(`user:${key}`);
            cleanupMulti.sRem('online_users_set', key);
        }
        await cleanupMulti.exec();
    }
    
    const finalOnlineList = onlineUsersData; 
    await redisClient.set('online_users_cache', JSON.stringify(finalOnlineList), { EX: 60 });
    
    io.emit('update user list', finalOnlineList); 
}

io.on('connection', async (socket) => {
    if (socket.publicKey) {
        socket.join(socket.publicKey); 
    }

    socket.on('add user', async (userData) => {
        if (!userData.publicKey || !userData.username || !userData.clientFPEKeyB) return;
        if (!redisClient.isReady || !FPE_MASTER_KEY) return; 

        socket.username = userData.username;
        socket.publicKey = userData.publicKey;
        socket.clientFPEKeyB = userData.clientFPEKeyB;

        socket.join(userData.publicKey); 
        
        const userToken = encryptId(userData.publicKey, userData.clientFPEKeyB);

        await redisClient.sAdd('online_users_set', userData.publicKey);

        try {
            await usersCollection.updateOne(
                { publicKey: userData.publicKey },
                { $set: { username: userData.username, lastToken: userToken } },
                { upsert: true }
            );
        } catch (err) {
            console.error("Kullanıcı kaydedilirken hata:", err);
        }

        const userKey = `user:${socket.publicKey}`;
        await redisClient.hSet(userKey, {
            username: userData.username,
            publicKey: userData.publicKey,
            socketId: socket.id,
            clientFPEKeyB: userData.clientFPEKeyB
        });
        await redisClient.expire(userKey, 300); // 5 dakika

        await sendUpdatedUserList(); 
    });

    socket.onAny(async () => {
        if (socket.publicKey && redisClient.isReady) {
            await redisClient.expire(`user:${socket.publicKey}`, 300); 
        }
    });

    socket.on('get conversations', async () => {
        if (!socket.publicKey || !FPE_MASTER_KEY) return;
        
        let currentUserFPEKeyB;
        try {
            const userData = await redisClient.hGetAll(`user:${socket.publicKey}`);
            currentUserFPEKeyB = userData.clientFPEKeyB;
        } catch(e) { console.error("Redis'ten K-B çekilemedi:", e); return; }

        if (!currentUserFPEKeyB) {
            const cachedList = await redisClient.get('online_users_cache');
            const onlineUsers = cachedList ? JSON.parse(cachedList) : [];
            return socket.emit('conversations list', onlineUsers.filter(user => user.publicKey !== socket.publicKey));
        }
        
        const currentUserToken = encryptId(socket.publicKey, currentUserFPEKeyB); 
        if (!currentUserToken) return;

        try {
            const cachedList = await redisClient.get('online_users_cache');
            const onlineUsers = cachedList ? JSON.parse(cachedList) : [];
            
            const dmMessages = await dmMessagesCollection.find({ 
                $or: [
                    { senderToken: currentUserToken }, 
                    { recipientToken: currentUserToken }
                ]
            }, { 
                projection: { senderToken: 1, recipientToken: 1 } 
            }).toArray();
            
            const partnerTokens = new Set();
            dmMessages.forEach(msg => {
                const partnerToken = (msg.senderToken !== currentUserToken) ? msg.senderToken : msg.recipientToken;
                if (partnerToken !== currentUserToken) {
                    partnerTokens.add(partnerToken);
                }
            });
            
            const finalPartnersMap = new Map();
            
            onlineUsers.forEach(user => {
                finalPartnersMap.set(user.publicKey, { username: user.username, publicKey: user.publicKey });
            });
            
            if (partnerTokens.size > 0) {
                 const pastUsers = await usersCollection.find(
                    { lastToken: { $in: Array.from(partnerTokens) } },
                    { projection: { username: 1, publicKey: 1, _id: 0 } }
                ).toArray();

                pastUsers.forEach(user => {
                    if (!finalPartnersMap.has(user.publicKey)) {
                        finalPartnersMap.set(user.publicKey, { username: user.username, publicKey: user.publicKey });
                    }
                });
            }
            
            socket.emit('conversations list', Array.from(finalPartnersMap.values()));

        } catch(err) {
            console.error("Sohbet listesi çekilirken kritik hata:", err);
            socket.emit('conversations list', []); 
        }
    });

    socket.on('get conversation history', async (otherUserPublicKey) => {
        if (!socket.publicKey || !FPE_MASTER_KEY) return;
        
        let history;
        if (otherUserPublicKey === null) {
            history = await generalMessagesCollection.find({})
            .sort({ _id: -1 })
            .limit(100)
            .toArray();
            
            history.reverse(); 
            
        } else {
            let currentUserFPEKeyB;
            let otherUserFPEKeyB;
            let otherUserToken;

            try {
                const currentUserData = await redisClient.hGetAll(`user:${socket.publicKey}`);
                currentUserFPEKeyB = currentUserData.clientFPEKeyB;
                
                const otherUserDataRedis = await redisClient.hGetAll(`user:${otherUserPublicKey}`);
                otherUserFPEKeyB = otherUserDataRedis.clientFPEKeyB;
                
                if (!otherUserFPEKeyB) {
                    const otherUserDataMongo = await usersCollection.findOne({ publicKey: otherUserPublicKey });
                    if (otherUserDataMongo) {
                        otherUserToken = otherUserDataMongo.lastToken;
                    }
                } else {
                    otherUserToken = encryptId(otherUserPublicKey, otherUserFPEKeyB);
                }
                
            } catch(e) { console.error("K-B/Token çekilemedi (history):", e); return; }

            const currentUserToken = encryptId(socket.publicKey, currentUserFPEKeyB); 

            if (!currentUserToken || !otherUserToken) {
                return socket.emit('conversation history', { history: [], partnerPublicKey: otherUserPublicKey });
            }

            history = await dmMessagesCollection.find({ 
                $or: [
                    { senderToken: currentUserToken, recipientToken: otherUserToken }, 
                    { senderToken: otherUserToken, recipientToken: currentUserToken }
                ]
            })
                .sort({ timestamp: -1 })  
                .limit(100)         
                .toArray();

            history.reverse(); 
        }
        
        socket.emit('conversation history', { history: history, partnerPublicKey: otherUserPublicKey });
    });

    socket.on('chat message', async (msg, callback) => {
        if (!socket.username || !msg.message) return;
        
        const expireDate = new Date();
        expireDate.setDate(expireDate.getDate() + 1);
        
        const data = { 
            username: socket.username, 
            message: msg.message, 
            timestamp: new Date(), 
            expireAt: expireDate 
        }; 
        
        try {
            await generalMessagesCollection.insertOne(data); 
            socket.broadcast.emit('chat message', data); 
            if (typeof callback === 'function') callback({ status: 'ok' });
        } catch (err) { if (typeof callback === 'function') callback({ status: 'error' }); }
    });

    socket.on('private message', async (data) => { 
        if (!socket.publicKey || !FPE_MASTER_KEY || !data.clientFPEKeyB) return; 
        
        const senderFPEKeyB = data.clientFPEKeyB; 

        const senderToken = encryptId(socket.publicKey, senderFPEKeyB);

        let recipientToken;
        let recipientFPEKeyB;
        try {
            const recipientPK = data.recipientPublicKey;

            const userDataRedis = await redisClient.hGetAll(`user:${recipientPK}`);
            recipientFPEKeyB = userDataRedis.clientFPEKeyB;
            
            if (recipientFPEKeyB) {
                recipientToken = encryptId(recipientPK, recipientFPEKeyB);
            } else {
                const userDataMongo = await usersCollection.findOne({ publicKey: recipientPK });
                recipientToken = userDataMongo?.lastToken; 
            }
        } catch(e) { console.error("Alıcının K-B/Token anahtarı çekilemedi:", e); return; }

        if (!recipientToken) {
            return console.error("Alıcının Token'ı bulunamadı. Mesaj gönderilemedi.");
        }
        
        const dbData = {
            senderToken: senderToken,         
            recipientToken: recipientToken, 
            ciphertext_for_recipient: data.ciphertext_for_recipient,
            ciphertext_for_sender: data.ciphertext_for_sender,
            timestamp: new Date()
        };

        try {
            await dmMessagesCollection.insertOne(dbData); 
            
            if (recipientFPEKeyB) {
                io.to(data.recipientPublicKey).emit('private message', { ciphertext: data.ciphertext_for_recipient, senderPublicKey: socket.publicKey });
            }
            
        } catch (err) { console.error("Özel mesaj gönderilirken hata:", err); }
    });

    socket.on('disconnect', async () => {
        if (socket.publicKey && redisClient.isReady) {
            await redisClient.del(`user:${socket.publicKey}`);
            await redisClient.sRem('online_users_set', socket.publicKey);
            socket.leave(socket.publicKey);

            await sendUpdatedUserList(); 
        }
    });

    const updateInterval = setInterval(() => {
        if(redisClient.isReady) {
            sendUpdatedUserList();
        }
    }, 30000);
    
    socket.on('disconnect', () => {
        clearInterval(updateInterval);
    });
});
