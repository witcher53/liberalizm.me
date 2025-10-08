// /var/www/liberalizm.me/index.js (GÜNCELLENMİŞ Ana Sunucu Dosyası)

require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');

// ✅ DÜZELTİLMİŞ: Bitişik dosya adları ve aynı dizinden yükleme yapılıyor.
const Vault = require('./server/servervault.js'); 
const Mongo = require('./server/servermongo.js'); 
const SocketManager = require('./server/serversocket.js'); 

const app = express();
const server = http.createServer(app);
const PORT = 3000;
const io = new socketIo.Server(server, { 
    cors: { origin: "https://liberalizm.me", methods: ["GET", "POST"] } 
});

// Statik dosyaları sun
app.use(express.static('public')); 

async function startServer() {
    try {
        // 1. Güvenlik Anahtarlarını Al ve Doğrula
        await Vault.fetchAndSetKeysFromVault();

        // 2. Redis ve MongoDB'ye Bağlan
        const redisClient = await SocketManager.setupRedisAdapter(io);
        await Mongo.connectToMongo();
        
        // 3. Socket.IO Dinleyicilerini Başlat
        SocketManager.initializeSocketListeners(io, redisClient);
        console.log("✅ [Sunucu] Socket.IO dinleyicileri başlatıldı.");

        // 4. Sunucuyu Dinlemeye Başla
        server.listen(PORT, '127.0.0.1', () => {
            console.log(`✅ [Sunucu] Sunucu ${PORT} portunda dinlemede. Müşteri kabulüne hazır.`);
        });
    } catch (err) {
        console.error("!!! [Sunucu] KRİTİK HATA: Sunucu başlatılamadı.", err);
        process.exit(1);
    }
}

// Başlangıç akışını başlat
startServer();