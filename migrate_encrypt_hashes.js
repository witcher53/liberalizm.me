// /migrate_encrypt_hashes.js

require('dotenv').config();
const { MongoClient } = require('mongodb');
const Crypto = require('./server/servercrypto.js');
const Vault = require('./server/servervault.js');

(async () => {
    try {
        console.log("⏳ Başlatılıyor... Önce Vault'tan anahtarlar çekilecek.");
        await Vault.fetchAndSetKeysFromVault();

        if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI bulunamadı!");
        
        const client = new MongoClient(process.env.MONGODB_URI);
        await client.connect();
        console.log("✅ MongoDB'ye bağlandı.");

        const coll = client.db('chat_app').collection('dm_messages');
        
        console.log('🚀 Routing Hash Şifreleme işlemi başlıyor...');
        
        // Şifrelenmemiş hash'i olan ama şifreli hash'i olmayan belgeleri bul
        const cursor = coll.find({
            'mlmp.senderRoutingHash': { $exists: true },
            'mlmp.encryptedSenderRoutingHash': { $exists: false }
        });
        
        let count = 0;
        
        while (await cursor.hasNext()) {
            const doc = await cursor.next();
            
            const encryptedSender = Crypto.encryptPointer(doc.mlmp.senderRoutingHash);
            const encryptedRecipient = Crypto.encryptPointer(doc.mlmp.recipientRoutingHash);

            await coll.updateOne(
                { _id: doc._id },
                {
                    $set: {
                        'mlmp.encryptedSenderRoutingHash': encryptedSender,
                        'mlmp.encryptedRecipientRoutingHash': encryptedRecipient
                    },
                    // Güvenlik için eski, okunabilir hash'leri kaldırıyoruz
                    $unset: {
                        'mlmp.senderRoutingHash': "",
                        'mlmp.recipientRoutingHash': ""
                    }
                }
            );
            count++;
            if (count % 100 === 0) console.log(`✅ ${count} belgenin hash'leri şifrelendi...`);
        }
        
        console.log(`\n🎉 Şifreleme tamamlandı! Toplam ${count} mesaj güncellendi.`);
        
        await client.close();
        console.log("MongoDB bağlantısı kapatıldı.");
        process.exit(0);
        
    } catch (err) {
        console.error("❌ Migration script'i başarısız oldu:", err);
        process.exit(1);
    }
})();
