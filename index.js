// /index.js (Orijinal Kod + Güvenlik Başlıkları + Hata Düzeltmesi)

const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const path = require('path');
const helmet = require('helmet'); // GÜVENLİK İÇİN EKLENDİ

// Orijinal dosya importların
const Vault = require('./server/servervault.js');
const Mongo = require('./server/servermongo.js');
const SocketServer = require('./server/serversocket.js');
const Upload = require('./server/upload.js');

const PORT = process.env.PORT || 3000;

async function startServer() {
    try {
        // Orijinal Vault fonksiyonun
        await Vault.fetchAndSetKeysFromVault();
        
        const app = express();
        const httpServer = createServer(app);
        const io = new Server(httpServer, {
            cors: { origin: "*", methods: ["GET", "POST"] },
            maxHttpBufferSize: 12e7 // 12 MB
        });

        // --- BAŞLANGIÇ: Güvenlik Başlıkları ---
        app.use(helmet());
        app.use(helmet.contentSecurityPolicy({
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                connectSrc: ["'self'", "wss:", "ws:"],
                imgSrc: ["'self'", "blob:", "data:"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                upgradeInsecureRequests: [],
            },
        }));
        app.use((req, res, next) => {
            res.setHeader('X-Frame-Options', 'DENY');
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('X-XSS-Protection', '1; mode=block');
            res.setHeader('Referrer-Policy', 'no-referrer');
            res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
            res.removeHeader('X-Powered-By'); 
            next();
        });
        // --- BİTİŞ: Güvenlik Başlıkları ---

        const redisClient = await SocketServer.setupRedisAdapter(io);
        
        // Orijinal Mongo fonksiyonun
        await Mongo.connectToMongo();
        
        SocketServer.initializeSocketListeners(io, redisClient);

        app.use(express.static(path.join(__dirname, 'public')));
        
        app.post('/api/upload', Upload.upload.single('file'), Upload.handleUpload);

        // --- BAŞLANGIÇ: Düzeltilmiş "Hepsini Yakala" Satırı ---
        // API ve dosya yolları dışındaki tüm GET isteklerini ana sayfaya yönlendirir.
        app.get(/^(?!\/api).*/, (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'index.html'));
        });
        // --- BİTİŞ: Düzeltilmiş "Hepsini Yakala" Satırı ---

        httpServer.listen(PORT, () => {
            console.log(`✅ [Sunucu] Sunucu ${PORT} portunda dinlemede. Müşteri kabulüne hazır.`);
        });

    } catch (error) {
        console.error(`!!! [Sunucu] KRİTİK HATA: Sunucu başlatılamadı. ${error.stack}`);
        process.exit(1);
    }
}

startServer();
