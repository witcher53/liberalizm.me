// server/upload.js

const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const crypto = require('crypto');

// Multer Ayarları
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10 MB limit
    },
    fileFilter: (req, file, cb) => {
        // Şifreli dosya olduğu için sadece genel dosya tiplerini kabul et
        const allowedTypes = ['application/octet-stream', 'image/jpeg', 'image/png'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('İzin verilmeyen dosya türü.'), false);
        }
    }
});

// S3 / DigitalOcean Spaces İstemcisi
// Çevre değişkenlerine ihtiyacımız var: DO_SPACES_ENDPOINT, DO_SPACES_KEY, DO_SPACES_SECRET, DO_SPACES_BUCKET, DO_SPACES_CDN_URL
const s3Client = new S3Client({
    endpoint: process.env.DO_SPACES_ENDPOINT,
    region: 'us-east-1', // Veya kullandığın DO/AWS bölgesi
    credentials: {
        accessKeyId: process.env.DO_SPACES_KEY,
        secretAccessKey: process.env.DO_SPACES_SECRET
    }
});

const BUCKET_NAME = process.env.DO_SPACES_BUCKET;
const CDN_URL = process.env.DO_SPACES_CDN_URL;

// Ana Yükleme Fonksiyonu
const handleUpload = async (req, res) => {
    // Kimlik doğrulama kontrolü (Örn: JWT, session kontrolü vs. burada olmalıdır!)
    // Şimdilik sadece dosya var mı kontrol edelim:
    if (!req.file) {
        return res.status(400).json({ error: 'Yüklenecek dosya bulunamadı.' });
    }

    try {
        // Rastgele dosya adı oluştur
        const randomFileName = crypto.randomBytes(20).toString('hex');
        const fileExtension = 'encrypted'; 
        const finalFileName = `${randomFileName}.${fileExtension}`;

        // S3'e yükle
        const uploadParams = {
            Bucket: BUCKET_NAME,
            Key: `encrypted-images/${finalFileName}`,
            Body: req.file.buffer,
            ACL: 'public-read', // CDN erişimi için
            ContentType: 'application/octet-stream', // Her zaman şifreli ikili dosya olarak işaretle
            // Güvenlik header'ları
            CacheControl: 'max-age=31536000', // 1 yıl
        };

        await s3Client.send(new PutObjectCommand(uploadParams));

        const fileUrl = `${CDN_URL}/encrypted-images/${finalFileName}`;
        
        console.log(`[Upload] Dosya yüklendi: ${finalFileName}`);
        res.status(200).json({ success: true, url: fileUrl });

    } catch (error) {
        console.error("!!! Sunucu dosya yükleme hatası:", error);
        res.status(500).json({ error: 'Dosya yüklenirken sunucuda bir hata oluştu.' });
    }
};

module.exports = {
    upload,
    handleUpload
};
