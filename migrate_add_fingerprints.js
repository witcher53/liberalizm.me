// migrate_add_fingerprints.js
require('dotenv').config();
const { MongoClient } = require('mongodb');
const crypto = require('crypto');

const SERVER_SECRET_KEY = process.env.SERVER_SECRET_KEY ? Buffer.from(process.env.SERVER_SECRET_KEY, 'hex') : null;
if (!SERVER_SECRET_KEY) { console.error("SERVER_SECRET_KEY eksik"); process.exit(1); }

function decryptPointer(encryptedPointer) { 
    try {
        const parts = encryptedPointer.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encryptedText = parts[2];
        const decipher = crypto.createDecipheriv('aes-256-gcm', SERVER_SECRET_KEY, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        console.error('Çözüm hatası:', encryptedPointer, e.message);
        return null;
    }
}

function pointerFingerprint(publicKey) {
    return crypto.createHmac('sha256', SERVER_SECRET_KEY).update(publicKey).digest('hex');
}

(async () => {
    const uri = process.env.MONGODB_URI;
    const client = new MongoClient(uri);
    await client.connect();
    const db = client.db('chat_app');
    const coll = db.collection('dm_messages');
    console.log('Veritabanına bağlanıldı. Migration başlıyor...');

    const cursor = coll.find({ senderFingerprint: { $exists: false } });
    let count = 0;
    while (await cursor.hasNext()) {
        const doc = await cursor.next();
        const updates = {};
        try {
            if (doc.senderPointer) {
                const pk = decryptPointer(doc.senderPointer);
                if (pk) updates.senderFingerprint = pointerFingerprint(pk);
            }
            if (doc.recipientPointer) {
                const pk2 = decryptPointer(doc.recipientPointer);
                if (pk2) updates.recipientFingerprint = pointerFingerprint(pk2);
            }
            if (Object.keys(updates).length > 0) {
                await coll.updateOne({ _id: doc._id }, { $set: updates });
                count++;
            }
        } catch (e) {
            console.error('Güncelleme hatası', e);
        }
    }
    console.log('Migration tamamlandı. Güncellenen doküman sayısı:', count);
    await client.close();
    process.exit(0);
})();
