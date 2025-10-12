// /migrate_to_mlmp.js (Daha Sağlam Hata Kontrolü ile Güncellendi)

require('dotenv').config();
const { MongoClient } = require('mongodb');
const Crypto = require('./server/servercrypto.js');
const MLMPManager = require('./server/mlmp-manager.js');
const Vault = require('./server/servervault.js');

(async () => {
    try {
        // ✅ GÜNCELLEME: Anahtarları Vault'tan çekerek başlıyoruz!
        // Bu, servercrypto'nun doğru anahtarlarla başlatılmasını sağlar.
        await Vault.fetchAndSetKeysFromVault();

        if (!process.env.MONGODB_URI) {
            console.error("MONGODB_URI bulunamadı!");
            process.exit(1);
        }
        const uri = process.env.MONGODB_URI;
        const client = new MongoClient(uri);
        
        await client.connect();
        console.log("MongoDB'ye bağlandı.");

        const db = client.db('chat_app');
        const coll = db.collection('dm_messages');
        
        console.log('🚀 MLMP Migration başlıyor...');
        
        const mlmp = new MLMPManager();
        await mlmp.initialize(null);
        
        const cursor = coll.find({ 'mlmp': { $exists: false } });
        let count = 0;
        let skipped = 0;
        
        while (await cursor.hasNext()) {
            const doc = await cursor.next();
            
            try {
                // ✅ GÜNCELLEME: Pointer alanlarının varlığını ve string olduğunu kontrol et
                if (!doc.senderPointer || !doc.recipientPointer || typeof doc.senderPointer !== 'string' || typeof doc.recipientPointer !== 'string') {
                    // console.log(`⏩ Mesaj atlanıyor ${doc._id}: Gerekli pointer alanları eksik veya geçersiz.`);
                    skipped++;
                    continue; // Bu belgeyi atla ve bir sonrakine geç
                }

                const senderPK = Crypto.decryptPointer(doc.senderPointer);
                const recipientPK = Crypto.decryptPointer(doc.recipientPointer);
                
                if (!senderPK || !recipientPK) {
                    // console.log(`⏩ Mesaj atlanıyor ${doc._id}: İşaretçiler çözülemedi (muhtemelen bozuk veri).`);
                    skipped++;
                    continue;
                }

                const senderOnion = await mlmp.encryptMetadata(senderPK);
                const recipientOnion = await mlmp.encryptMetadata(recipientPK);
                const senderRouting = await mlmp.serverDecryptRouting(senderOnion);
                const recipientRouting = await mlmp.serverDecryptRouting(recipientOnion);
                const bucket = mlmp.timing.timeBucketing.bucketizeTimestamp(new Date(doc.timestamp).getTime());
                
                await coll.updateOne(
                    { _id: doc._id },
                    {
                        $set: {
                            mlmp: {
                                senderOnion: senderOnion.onion,
                                recipientOnion: recipientOnion.onion,
                                epoch: senderOnion.epoch,
                                senderRoutingHash: senderRouting.routingInfo,
                                recipientRoutingHash: recipientRouting.routingInfo,
                                bucketId: bucket.bucketId,
                                layers: 3,
                                migrated: true,
                                migratedAt: new Date()
                            }
                        }
                    }
                );
                
                count++;
                if (count % 100 === 0) {
                    console.log(`✅ ${count} mesaj güncellendi... (${skipped} atlandı)`);
                }
                
            } catch (e) {
                console.error(`❌ Belge ${doc._id} işlenirken kritik hata:`, e.message);
                skipped++;
            }
        }
        
        console.log(`\n🎉 Migration tamamlandı!`);
        console.log(`   - Başarıyla güncellenen mesaj: ${count}`);
        console.log(`   - Atlanan (geçersiz) mesaj: ${skipped}`);
        
        mlmp.shutdown();
        await client.close();
        console.log("MongoDB bağlantısı kapatıldı.");
        process.exit(0);
        
    } catch (err) {
        console.error("Migration script'i başlatılamadı:", err);
        process.exit(1);
    }
})();
