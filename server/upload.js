// /server/upload.js (Eksik Olan Dosya)

const multer = require('multer');
const sharp = require('sharp');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const crypto = require('crypto');

// 1. Multer Ayarları (Güvenlik ve Limitler)
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 15 * 1024 * 1024 // 15 MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'application/octet-stream'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('İzin verilmeyen dosya türü.'), false);
        }
    }
});

// 2. S3 / DigitalOcean Spaces İstemcisini Ayarla
const s3Client = new S3Client({
    endpoint: process.env.DO_SPACES_ENDPOINT,
    region: 'us-east-1',
    credentials: {
        accessKeyId: process.env.DO_SPACES_KEY,
        secretAccessKey: process.env.DO_SPACES_SECRET
    }
});

const BUCKET_NAME = process.env.DO_SPACES_BUCKET;
const CDN_URL = process.env.DO_SPACES_CDN_URL;

// Ana Yükleme Fonksiyonu
const handleUpload = async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Yüklenecek dosya bulunamadı.' });
    }

    try {
        const randomFileName = crypto.randomBytes(20).toString('hex');
        let processedBuffer;
        let fileExtension;
        let contentType;

        if (req.file.mimetype.startsWith('image/')) {
            processedBuffer = await sharp(req.file.buffer)
                .resize({ width: 1920, height: 1080, fit: 'inside', withoutEnlargement: true })
                .webp({ quality: 85 })
                .toBuffer();
            fileExtension = 'webp';
            contentType = 'image/webp';
        } else {
            processedBuffer = req.file.buffer;
            fileExtension = 'encrypted';
            contentType = 'application/octet-stream';
        }
        
        const finalFileName = `${randomFileName}.${fileExtension}`;

        const uploadParams = {
            Bucket: BUCKET_NAME,
            Key: `files/${finalFileName}`,
            Body: processedBuffer,
            ACL: 'public-read',
            ContentType: contentType
        };

        await s3Client.send(new PutObjectCommand(uploadParams));

        const fileUrl = `${CDN_URL}/files/${finalFileName}`;
        
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
