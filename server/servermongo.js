// /servermongo.js (Düzeltilmiş)
const { MongoClient } = require('mongodb');

let dmMessagesCollection, generalMessagesCollection, usersCollection;

async function verifyTTLIndex(db) { 
    const COLLECTION_NAME = 'general_messages'; 
    const EXPIRE_AFTER_SECONDS = 86400;
    const INDEX_KEY = 'expireAt'; 
    const INDEX_NAME = 'general_chat_expire_at'; 
    
    try { 
        const collection = db.collection(COLLECTION_NAME); 
        const indexes = await collection.indexes(); 
        const ttlIndexCorrect = indexes.find(i => i.name === INDEX_NAME && i.expireAfterSeconds === EXPIRE_AFTER_SECONDS && i.key.hasOwnProperty(INDEX_KEY) && !i.partialFilterExpression); 
        if (ttlIndexCorrect) { 
            console.log(`✅ [Sunucu] TTL Index '${INDEX_NAME}' doğru ayarlanmış.`); 
            return; 
        } 
        const oldIndex = indexes.find(i => i.name === INDEX_NAME || i.key.hasOwnProperty(INDEX_KEY)); 
        if (oldIndex) { 
            console.warn(`⚠️ [Sunucu] Eski/Bozuk TTL Index '${oldIndex.name}' bulundu, siliniyor...`); 
            await collection.dropIndex(oldIndex.name); 
        } 
        console.log(`🔨 [Sunucu] Yeni TTL Index '${INDEX_NAME}' kuruluyor...`); 
        await collection.createIndex({ [INDEX_KEY]: 1 }, { name: INDEX_NAME, expireAfterSeconds: EXPIRE_AFTER_SECONDS, background: true }); 
        console.log(`✅ [Sunucu] TTL Index başarıyla kuruldu ve doğrulandı!`); 
    } catch (err) { 
        console.error(`!!! [Sunucu] KRİTİK HATA: TTL Index kontrolü/kurulumu BAŞARISIZ OLDU. Hata: ${err.message}`); 
        process.exit(1); 
    } 
}

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
    generalMessagesCollection = database.collection('general_messages');
    usersCollection = database.collection('users');
    
    console.log("✅ [Sunucu] MongoDB Atlas'a başarıyla bağlanıldı!");
    
    await verifyTTLIndex(database);
    await createAndVerifyIndexes();
}

function getCollections() {
    if (!dmMessagesCollection) throw new Error("MongoDB bağlantısı henüz kurulmadı!");
    return { dmMessagesCollection, generalMessagesCollection, usersCollection };
}

module.exports = {
    connectToMongo,
    getCollections
};
