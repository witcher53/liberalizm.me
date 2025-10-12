// /servermongo.js (Güncellenmiş Tam Sürüm)

const { MongoClient } = require('mongodb');

let dmMessagesCollection, usersCollection;

async function createAndVerifyIndexes() {
    try {
        // ✅ GÜNCELLEME: Mevcut index'ler korunuyor
        await dmMessagesCollection.createIndex({ senderFingerprint: 1 });
        await dmMessagesCollection.createIndex({ recipientFingerprint: 1 });
        
        // ✅ YENİ: MLMP için index'ler
        await dmMessagesCollection.createIndex({ 'mlmp.senderRoutingHash': 1 });
        await dmMessagesCollection.createIndex({ 'mlmp.recipientRoutingHash': 1 });
        await dmMessagesCollection.createIndex({ 'mlmp.epoch': 1 });
        await dmMessagesCollection.createIndex({ 'mlmp.bucketId': 1 });
        
        // User collection
        await usersCollection.createIndex({ "publicKey": 1 }, { unique: true });
        await usersCollection.createIndex({ "username": 1 });
        
        // ✅ YENİ: MLMP metadata için kullanıcı koleksiyonu index'i
        await usersCollection.createIndex({ 'mlmp.onionPointer': 1 });
        
        console.log("✅ [Sunucu] Tüm koleksiyon İndeksleri başarıyla oluşturuldu/doğrulandı (MLMP dahil).");
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
