// /servervault.js (Düzeltilmiş)
const axios = require('axios');
const path = require('path');
// ✅ DÜZELTİLMİŞ: Bitişik dosya adı ve aynı dizinden yükleme.
const Crypto = require('./servercrypto.js'); 

function initializeFPEKey() { 
    const crypto = require('crypto');
    const keyInput = process.env.MANUAL_FPE_KEY; 
    const hashCheck = process.env.FPE_KEY_HASH_CHECK; 
    
    if (!keyInput || !hashCheck) { 
        console.error("❌ KRİTİK GÜVENLİK HATASI: FPE anahtarları ortam değişkenlerinde tanımlanmamış!"); 
        process.exit(1); 
    } 
    
    const inputHash = crypto.createHash('sha256').update(keyInput).digest('hex'); 
    if (inputHash !== hashCheck) { 
        console.error("❌ GÜVENLİK HATASI: MANUAL_FPE_KEY, HASH ile uyuşmuyor!"); 
        process.exit(1); 
    } 
    
    Crypto.setFPEMasterKey(Crypto.createMasterKey(keyInput)); 
    console.log("✅ [Sunucu] FPE MASTER KEY ortam değişkeninden doğrulandı ve RAM'e Yüklendi!"); 
}

async function fetchAndSetKeysFromVault() {
    const vaultAddr = process.env.VAULT_ADDR;
    const vaultToken = process.env.VAULT_TOKEN;
    const secretPath = process.env.SECRET_PATH;
    if (!vaultAddr || !vaultToken || !secretPath) { 
        throw new Error("VAULT_ADDR, VAULT_TOKEN veya SECRET_PATH ortam değişkenleri bulunamadı!"); 
    }
    console.log("⏳ [Sunucu] HashiCorp Vault'tan SERVER_SECRET_KEY çekiliyor...");
    
    const response = await axios.get(`${vaultAddr}/v1/${secretPath}`, { 
        headers: { 'X-Vault-Token': vaultToken } 
    });
    
    const secretData = response.data.data.data;
    if (!secretData || !secretData.SERVER_SECRET_KEY) { 
        throw new Error("Vault'tan SERVER_SECRET_KEY değeri alınamadı veya yol hatalı."); 
    }
    
    const keyFromVault = Buffer.from(secretData.SERVER_SECRET_KEY, 'hex');
    if (keyFromVault.length !== 32) { 
        throw new Error(`Anahtar uzunluğu 32 byte değil (32 olmalı).`); 
    }
    
    Crypto.setServerSecretKey(keyFromVault);
    console.log("✅ [Sunucu] SERVER_SECRET_KEY başarıyla RAM'e yüklendi.");
    
    initializeFPEKey();
}

module.exports = {
    fetchAndSetKeysFromVault
};
