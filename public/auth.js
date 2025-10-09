// /public/auth.js (FİNAL, HATASIZ SÜRÜM)
let identity = null;
let dom, callbacks, crypto, utils;

export function initAuth(dependencies) {
    dom = dependencies.dom;
    callbacks = dependencies.callbacks;
    crypto = dependencies.crypto;
    utils = dependencies.utils;
}

function saveIdentity(id) {
    const storedId = {
        username: id.username, publicKey: id.publicKey, signPublicKey: id.signPublicKey,
        privateKey: id.encryptedPrivateKey, encryptedSignPrivateKey: id.encryptedSignPrivateKey,
        encryptedFPEKeyB: id.encryptedFPEKeyB, salt: id.salt
    };
    localStorage.setItem('chatIdentity', JSON.stringify(storedId));
}

export function checkIdentity() {
    const storedIdentity = localStorage.getItem('chatIdentity');
    if (!storedIdentity) {
        dom.loginOverlay.style.display = 'flex';
        dom.submitNameBtn.textContent = utils.t('login_button');
        return null;
    }
    try {
        const tempIdentity = JSON.parse(storedIdentity);
        if (!tempIdentity.salt || !tempIdentity.encryptedSignPrivateKey || !tempIdentity.signPublicKey) {
            console.warn("Bozuk kimlik formatı algılandı.");
            alert(utils.t('alert_corrupt_identity'));
            return null;
        }
        dom.loginOverlay.style.display = 'flex';
        dom.nameInput.value = tempIdentity.username;
        dom.nameInput.disabled = true;
        dom.submitNameBtn.textContent = utils.t('decrypt_button');
        dom.passwordInput.focus();
        return tempIdentity;
    } catch (e) {
        console.error("Kimlik parse edilemedi:", e);
        alert(utils.t('alert_corrupt_identity'));
        return null;
    }
}

export async function loginWithPassword(tempIdentity) {
    const userPassword = dom.passwordInput.value.trim();
    if (!userPassword) { 
        alert(utils.t('alert_password_required')); 
        return; 
    }
    try {
        const salt = sodium.from_base64(tempIdentity.salt);
        const privateKeyBase64 = await crypto.decryptKey(tempIdentity.privateKey, userPassword, salt);
        const signPrivateKeyBase64 = await crypto.decryptKey(tempIdentity.encryptedSignPrivateKey, userPassword, salt);
        const fpeKeyB = await crypto.decryptKey(tempIdentity.encryptedFPEKeyB, userPassword, salt);
        const fullIdentity = {
            username: tempIdentity.username, publicKey: tempIdentity.publicKey, privateKey: privateKeyBase64,
            signPublicKey: tempIdentity.signPublicKey, signPrivateKey: signPrivateKeyBase64, fpeKeyB: fpeKeyB,
            salt: tempIdentity.salt, encryptedPrivateKey: tempIdentity.privateKey,
            encryptedSignPrivateKey: tempIdentity.encryptedSignPrivateKey, encryptedFPEKeyB: tempIdentity.encryptedFPEKeyB
        };
        await callbacks.startChat(fullIdentity);
    } catch (e) {
        // client.js'ten gelen özel hatayı yoksay
        if (e.message === "AUTH_SPECIFIC_ERROR_HANDLED") {
            return;
        }
        console.error("Giriş sırasında hata:", e);
        alert(utils.t('alert_wrong_password'));
    }
}

export async function createIdentity() {
    try {
        const username = dom.nameInput.value.trim() || 'Anonim';
        const userPassword = dom.passwordInput.value.trim();
        if (userPassword.length < 8) { 
            alert(utils.t('alert_password_required')); 
            return; 
        }
        const signKeyPair = sodium.crypto_sign_keypair();
        const boxPublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(signKeyPair.publicKey);
        const boxPrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(signKeyPair.privateKey);
        const salt = sodium.randombytes_buf(16);
        const saltBase64 = sodium.to_base64(salt);
        const fpeKeyB = sodium.to_base64(sodium.randombytes_buf(32));
        const encryptedPrivateKey = await crypto.encryptKey(sodium.to_base64(boxPrivateKey), userPassword, salt);
        const encryptedSignPrivateKey = await crypto.encryptKey(sodium.to_base64(signKeyPair.privateKey), userPassword, salt);
        const encryptedFPEKeyB = await crypto.encryptKey(fpeKeyB, userPassword, salt);
        identity = {
            username: username, 
            publicKey: sodium.to_base64(boxPublicKey), 
            privateKey: sodium.to_base64(boxPrivateKey),
            signPublicKey: sodium.to_base64(signKeyPair.publicKey), 
            signPrivateKey: sodium.to_base64(signKeyPair.privateKey),
            encryptedPrivateKey, encryptedSignPrivateKey, fpeKeyB, encryptedFPEKeyB, salt: saltBase64
        };
        saveIdentity(identity);
        await callbacks.startChat(identity);
    } catch (e) {
        // client.js'ten gelen özel hatayı yoksay
        if (e.message === "AUTH_SPECIFIC_ERROR_HANDLED") {
            return;
        }
        console.error("Kimlik oluşturulurken hata:", e);
        alert(utils.t('error_creating_identity'));
    }
}
