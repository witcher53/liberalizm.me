// /var/www/liberalizm.me/index.js (CSP - Nonce ile GÜNCELLENMİŞ Ana Sunucu Dosyası)

require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto'); // <-- EKLENDİ
const fs = require('fs');         // <-- EKLENDİ
const path = require('path');     // <-- EKLENDİ

// ✅ DÜZELTİLMİŞ: Bitişik dosya adları ve aynı dizinden yükleme yapılıyor.

const Upload = require('./server/upload.js'); // <-- EKLENDİ
const Vault = require('./server/servervault.js');
const Mongo = require('./server/servermongo.js');
const SocketManager = require('./server/serversocket.js');

const app = express();
const server = http.createServer(app);
const PORT = 3000;
const io = new socketIo.Server(server, {
    cors: { origin: "https://liberalizm.me", methods: ["GET", "POST"] }
});

// --- BAŞLANGIÇ: CSP için Dinamik HTML Sunumu ---
// Ana HTML sayfasını her istekte yeni bir nonce ile sun
app.get('/', (req, res) => {
    // 1. Her istek için benzersiz bir nonce oluştur
    const nonce = crypto.randomBytes(16).toString('base64');

    // 2. Güvenlik politikasını (CSP) tanımla
    // Bu politika, yalnızca kendi sunucumuzdan gelen ve doğru nonce'a sahip betiklerin çalışmasına izin verir.
    const csp = `
        default-src 'self';
        script-src 'self' 'nonce-${nonce}';
        style-src 'self' 'unsafe-inline';
        connect-src 'self' wss:;
        media-src 'self';
    `.replace(/\s{2,}/g, ' ').trim();

    // 3. CSP başlığını yanıt (response) üzerine ayarla
    res.setHeader('Content-Security-Policy', csp);

    // 4. index.html dosyasını diskten oku
    fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8', (err, html) => {
        if (err) {
            console.error("!!! index.html okunamadı!", err);
            return res.status(500).send("Sunucu hatası.");
        }
        // 5. HTML içindeki tüm <script> etiketlerine nonce="... " özelliğini ekle
        const modifiedHtml = html.replace(/<script /g, `<script nonce="${nonce}" `);
        res.send(modifiedHtml);
    });
});
// --- BİTİŞ: CSP için Dinamik HTML Sunumu ---


app.post('/api/upload', Upload.upload.single('file'), Upload.handleUpload); // <-- EKLENDİ

// Statik dosyaları (CSS, client-side JS, resimler vb.) sun

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
