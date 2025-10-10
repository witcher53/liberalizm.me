// /servermongo.js (Genel Mesajlar Kaldırılmış Sürüm)

const { MongoClient } = require('mongodb');

let dmMessagesCollection, usersCollection;

async function createAndVerifyIndexes() {
    try {
        await dmMessagesCollection.createIndex({ senderFingerprint: 1 });
        await dmMessagesCollection.createIndex({ recipientFingerprint: 1 });
        await usersCollection.createIndex({ "publicKey": 1 }, { unique: true });
        console.log("✅ [Sunucu] Koleksiyon İndeksleri başarıyla oluşturuldu/doğrulandı.");
    } catch (err) {
        if (err.code === 85 || err.codeName === 'IndexOptionsConflict') {
            console.log("✅ [Sunucu] Koleksiyon İndeksleri zaten mevcut, devam ediliyor.");
        } else {
            throw err;
        }
    }
}

async function connectToMongo() {
    if (!process.env.MONGODB_URI) { 
        console.error("❌ KRİTİK HATA: MONGODB_URI ortam değişkeni bulunamadı!"); 
        process.exit(1); 
    } 
    
    const uri = process.env.MONGODB_URI;
    const client = new MongoClient(uri);

    await client.connect();
    const database = client.db('chat_app');
    dmMessagesCollection = database.collection('dm_messages');
    usersCollection = database.collection('users');
    
    console.log("✅ [Sunucu] MongoDB Atlas'a başarıyla bağlanıldı!");
    
    await createAndVerifyIndexes();
}

function getCollections() {
    if (!dmMessagesCollection) throw new Error("MongoDB bağlantısı henüz kurulmadı!");
    return { dmMessagesCollection, usersCollection };
}

module.exports = {
    connectToMongo,
    getCollections
};
