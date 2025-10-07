// /home/witcher53/mesajlasma-uygulamasi/public/client.js (GÜVENLİK FİNAL: Sumo Build + WebCrypto Fallback)



(async () => {

    let translations = {};

    async function setLanguage(lang) { try { const response = await fetch(`/locales/${lang}.json`); translations = await response.json(); document.querySelectorAll('[data-i18n]').forEach(el => { const key = el.getAttribute('data-i18n'); if (translations[key]) el.innerHTML = translations[key]; }); document.querySelectorAll('[data-i18n-placeholder]').forEach(el => { const key = el.getAttribute('data-i18n-placeholder'); if (translations[key]) el.setAttribute('placeholder', translations[key]); }); document.title = translations['page_title'] || 'Chat'; localStorage.setItem('language', lang); document.getElementById('lang-tr').classList.toggle('active', lang === 'tr'); document.getElementById('lang-en').classList.toggle('active', lang === 'en'); } catch (error) { console.error(`Could not load language: ${lang}`, error); } }

    function t(key) { return translations[key] || key; }

    document.getElementById('lang-en').addEventListener('click', () => setLanguage('en'));

    document.getElementById('lang-tr').addEventListener('click', () => setLanguage('tr'));

    const preferredLang = localStorage.getItem('language') || (navigator.language.startsWith('tr') ? 'tr' : 'en');

    await setLanguage(preferredLang);

    if (typeof sodium === 'undefined' || typeof io === 'undefined' || typeof DOMPurify === 'undefined') { document.body.innerHTML = `<h1>${t('error_libsodium')}</h1>`; return; }

    await sodium.ready;

    const socket = io();

    const messages = document.getElementById('messages');

    const form = document.getElementById('form');

    const input = document.getElementById('input');

    const button = form.querySelector('button');

    const loginOverlay = document.getElementById('login-overlay');

    const nameInput = document.getElementById('name-input');

    const submitNameBtn = document.getElementById('submit-name');

    const mainContainer = document.getElementById('main-container');

    const soundToggle = document.getElementById('sound-toggle');

    const conversationsDiv = document.getElementById('conversations');

    const onlineUsersDiv = document.getElementById('online-users');

    const chatTitle = document.getElementById('chat-title');

    const passwordInput = document.getElementById('password-input');

    let identity = null;

    let isMuted = true;

    let dmPartner = null;

    let onlineUserMap = new Map();

    function playSound() { if (isMuted) return; new Audio('/notification.mp3').play().catch(() => {}); }

    soundToggle.addEventListener('click', () => { isMuted = !isMuted; soundToggle.textContent = isMuted ? t('sound_toggle_off') : t('sound_toggle_on'); if(!isMuted) playSound(); });



    // ==============================================================================

    // FİNAL GÜVENLİK GÜNCELLEMESİ: Argon2 (Tercihen) + PBKDF2 (Yedek Plan)

    // ==============================================================================

    async function deriveKey(password, salt) {

        if (password.length < 8) throw new Error(t('alert_password_required'));



        // Tercih edilen yöntem: Eğer libsodium'un sumo build'i yüklüyse ve pwhash varsa, onu kullan.

        if (sodium && typeof sodium.crypto_pwhash === 'function') {

            console.log("KDF Yöntemi: Argon2 (libsodium)");

            return sodium.crypto_pwhash(

                32, password, salt,

                sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,

                sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,

                sodium.crypto_pwhash_ALG_DEFAULT

            );

        }



        // Yedek Plan (Fallback): Eğer pwhash yoksa, tarayıcının kendi WebCrypto API'sini PBKDF2 ile kullan.

        console.warn("Fallback KDF Yöntemi: PBKDF2 (WebCrypto). Lütfen libsodium-wrappers-sumo kullanın.");

        const enc = new TextEncoder();

        const pwKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);

        const derivedBits = await crypto.subtle.deriveBits(

            { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: 150000 },

            pwKey, 256

        );

        return new Uint8Array(derivedBits);

    }

    
    function deriveKey_legacy(password) { return sodium.crypto_generichash(32, sodium.from_string(password)); }



    async function encryptKey(keyBase64, password, salt) {

        const derivedKey = await deriveKey(password, salt);

        const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);

        const keyBuffer = sodium.from_base64(keyBase64, sodium.base64_variants.URLSAFE_NO_PADDING); 

        const encryptedKey = sodium.crypto_secretbox_easy(keyBuffer, nonce, derivedKey); 

        return sodium.to_base64(nonce, sodium.base64_variants.URLSAFE_NO_PADDING) + '::' + sodium.to_base64(encryptedKey, sodium.base64_variants.URLSAFE_NO_PADDING);

    }



    async function decryptKey(encryptedString, password, salt, isLegacy = false) {

        const derivedKey = isLegacy ? deriveKey_legacy(password) : await deriveKey(password, salt);

        const parts = encryptedString.split('::');

        if (parts.length !== 2) throw new Error("Anahtar formatı bozuk.");

        const nonce = sodium.from_base64(parts[0], sodium.base64_variants.URLSAFE_NO_PADDING);

        const encryptedKey = sodium.from_base64(parts[1], sodium.base64_variants.URLSAFE_NO_PADDING);

        const decryptedKeyBuffer = sodium.crypto_secretbox_open_easy(encryptedKey, nonce, derivedKey);

        return sodium.to_base64(decryptedKeyBuffer, sodium.base64_variants.URLSAFE_NO_PADDING); 

    }

    
    function generateSplitKeyB() { return sodium.to_base64(sodium.randombytes_buf(32), sodium.base64_variants.URLSAFE_NO_PADDING); }

    function saveIdentity(id) { const storedId = { username: id.username, publicKey: id.publicKey, privateKey: id.encryptedPrivateKey, encryptedFPEKeyB: id.encryptedFPEKeyB, salt: id.salt, isEncrypted: true }; localStorage.setItem('chatIdentity', JSON.stringify(storedId)); }



    async function checkIdentity() {

        const storedIdentity = localStorage.getItem('chatIdentity');

        if (!storedIdentity) { loginOverlay.style.display = 'flex'; return; }

        let tempIdentity;

        try { tempIdentity = JSON.parse(storedIdentity); } catch (e) { localStorage.removeItem('chatIdentity'); loginOverlay.style.display = 'flex'; return; }

        loginOverlay.style.display = 'flex'; passwordInput.style.display = 'block'; nameInput.value = tempIdentity.username; nameInput.disabled = true; submitNameBtn.textContent = t('decrypt_button'); passwordInput.focus();

        submitNameBtn.onclick = async () => {

            const userPassword = passwordInput.value.trim();

            if (!userPassword || userPassword.length < 8) { alert(t('alert_password_required')); return; }

            try {

                if (!tempIdentity.salt) {

                    alert(t('alert_security_upgrade_argon2'));

                    const privateKeyBase64 = await decryptKey(tempIdentity.privateKey, userPassword, null, true);

                    const fpeKeyB = tempIdentity.encryptedFPEKeyB ? await decryptKey(tempIdentity.encryptedFPEKeyB, userPassword, null, true) : generateSplitKeyB();

                    const newSalt = sodium.randombytes_buf(16);

                    const newSaltBase64 = sodium.to_base64(newSalt, sodium.base64_variants.URLSAFE_NO_PADDING);

                    const encryptedPrivateKey = await encryptKey(privateKeyBase64, userPassword, newSalt);

                    const encryptedFPEKeyB = await encryptKey(fpeKeyB, userPassword, newSalt);

                    identity = { username: tempIdentity.username, publicKey: tempIdentity.publicKey, privateKey: privateKeyBase64, fpeKeyB: fpeKeyB, encryptedPrivateKey: encryptedPrivateKey, encryptedFPEKeyB: encryptedFPEKeyB, salt: newSaltBase64, isEncrypted: true };

                    saveIdentity(identity);

                } else {

                    const salt = sodium.from_base64(tempIdentity.salt, sodium.base64_variants.URLSAFE_NO_PADDING);

                    const privateKeyBase64 = await decryptKey(tempIdentity.privateKey, userPassword, salt);

                    const fpeKeyB = await decryptKey(tempIdentity.encryptedFPEKeyB, userPassword, salt);

                    identity = { username: tempIdentity.username, publicKey: tempIdentity.publicKey, privateKey: privateKeyBase64, encryptedPrivateKey: tempIdentity.privateKey, fpeKeyB: fpeKeyB, encryptedFPEKeyB: tempIdentity.encryptedFPEKeyB, salt: tempIdentity.salt, isEncrypted: true };

                }

                nameInput.disabled = false; submitNameBtn.textContent = t('login_button'); startChat();

            } catch (e) { alert(t('alert_wrong_password')); console.error("Anahtar çözülürken hata (muhtemelen yanlış şifre):", e); }

        };

    }



    async function createIdentity() { 

        try { 

            const username = nameInput.value.trim() || 'Anonim'; const userPassword = passwordInput.value.trim(); 

            if (userPassword.length < 8) { alert(t('alert_password_required')); return; }

            const keyPair = sodium.crypto_box_keypair(); 

            const publicKeyBase64 = sodium.to_base64(keyPair.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING);

            const privateKeyBase64 = sodium.to_base64(keyPair.privateKey, sodium.base64_variants.URLSAFE_NO_PADDING);

            const salt = sodium.randombytes_buf(16);

            const saltBase64 = sodium.to_base64(salt, sodium.base64_variants.URLSAFE_NO_PADDING);

            const fpeKeyB = generateSplitKeyB();

            const encryptedPrivateKey = await encryptKey(privateKeyBase64, userPassword, salt);

            const encryptedFPEKeyB = await encryptKey(fpeKeyB, userPassword, salt);

            identity = { username: username, publicKey: publicKeyBase64, privateKey: privateKeyBase64, encryptedPrivateKey: encryptedPrivateKey, fpeKeyB: fpeKeyB, encryptedFPEKeyB: encryptedFPEKeyB, salt: saltBase64, isEncrypted: true };

            saveIdentity(identity); 

            startChat(); 

        } catch (e) { console.error("Kimlik oluşturulurken hata:", e); alert(t('error_creating_identity')); } 

    }

    
    // ... (diğer tüm fonksiyonlar ve socket eventleri aynı, değişiklik yok)

    function startChat() { loginOverlay.style.display = 'none'; mainContainer.style.display = 'flex'; form.style.display = 'flex'; socket.emit('add user', { username: identity.username, publicKey: identity.publicKey }); socket.emit('get conversations'); activateChat(null, t('general_chat_title')); }

    submitNameBtn.addEventListener('click', () => { if (nameInput.disabled) { submitNameBtn.onclick(); } else { createIdentity(); } });

    nameInput.addEventListener('keypress', (e) => { if (e.key === 'Enter' && !nameInput.disabled) { createIdentity(); } });

    passwordInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') { if (nameInput.disabled) { submitNameBtn.onclick(); } else { createIdentity(); } } });

    function activateChat(partner, title) { if (partner && partner.publicKey) { const userElement = document.querySelector(`p[data-public-key="${partner.publicKey}"]`); if (userElement) userElement.classList.remove('new-message-indicator'); } dmPartner = partner; chatTitle.textContent = title; input.placeholder = t('placeholder_write_message'); input.disabled = false; button.disabled = false; const historyTarget = partner ? partner.publicKey : null; socket.emit('get conversation history', historyTarget); }

    function renderUser(user, container) { const userElement = document.createElement('p'); userElement.dataset.publicKey = user.publicKey; let onlineIndicator = onlineUserMap.has(user.publicKey) ? '<span class="online-indicator">●</span>' : ''; userElement.innerHTML = onlineIndicator + escapeHtml(user.username || 'Bilinmeyen'); if (identity && user.publicKey === identity.publicKey) { userElement.innerHTML += ` ${t('you_suffix')}`; } userElement.onclick = () => activateChat(user, user.username); container.appendChild(userElement); }

    socket.on('initial user list', (users) => { onlineUserMap.clear(); if(users) { users.forEach(user => { onlineUserMap.set(user.publicKey, user); }); } renderOnlineUserList(); });

    socket.on('user connected', (user) => { onlineUserMap.set(user.publicKey, user); renderOnlineUserList(); updateConversationOnlineStatus(user.publicKey, true); });

    socket.on('user disconnected', (data) => { if (onlineUserMap.has(data.publicKey)) { onlineUserMap.delete(data.publicKey); renderOnlineUserList(); updateConversationOnlineStatus(data.publicKey, false); } });

    function renderOnlineUserList() { onlineUsersDiv.innerHTML = ''; const sortedUsers = Array.from(onlineUserMap.values()).sort((a, b) => { if (identity && a.publicKey === identity.publicKey) return -1; if (identity && b.publicKey === identity.publicKey) return 1; return a.username.localeCompare(b.username); }); sortedUsers.forEach(user => { renderUser(user, onlineUsersDiv); }); }

    function updateConversationOnlineStatus(publicKey, isOnline) { const userElement = conversationsDiv.querySelector(`p[data-public-key="${publicKey}"]`); if (userElement) { const indicator = userElement.querySelector('.online-indicator'); if (isOnline && !indicator) { userElement.insertAdjacentHTML('afterbegin', '<span class="online-indicator">●</span>'); } else if (!isOnline && indicator) { indicator.remove(); } } }

    socket.on('conversations list', (partners) => { conversationsDiv.innerHTML = ''; const generalChat = document.createElement('p'); generalChat.innerHTML = `<strong>${t('general_chat_title')}</strong>`; generalChat.classList.add('active-chat'); generalChat.style.cursor = 'pointer'; generalChat.onclick = () => activateChat(null, t('general_chat_title')); conversationsDiv.appendChild(generalChat); if(partners) { partners.forEach(user => { renderUser(user, conversationsDiv); }); } });

    socket.on('conversation history', (data) => { messages.innerHTML = ''; if (!data || !data.history) return; data.history.forEach(msg => { if (!data.partnerPublicKey) { if (!msg.ciphertext_for_recipient) { addChatMessage({ ...msg, isSelf: msg.username === identity.username }); } return; } if (msg.ciphertext_for_recipient) { let isSelf = false; let ciphertextToDecrypt = null; try { const recipientPKBuffer = sodium.from_base64(identity.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING); const privateKeyBuffer = sodium.from_base64(identity.privateKey, sodium.base64_variants.URLSAFE_NO_PADDING); try { const ciphertextRecipientBuffer = sodium.from_base64(msg.ciphertext_for_recipient, sodium.base64_variants.URLSAFE_NO_PADDING); sodium.crypto_box_seal_open(ciphertextRecipientBuffer, recipientPKBuffer, privateKeyBuffer); ciphertextToDecrypt = msg.ciphertext_for_recipient; isSelf = false; } catch (e) { try { const ciphertextSenderBuffer = sodium.from_base64(msg.ciphertext_for_sender, sodium.base64_variants.URLSAFE_NO_PADDING); sodium.crypto_box_seal_open(ciphertextSenderBuffer, recipientPKBuffer, privateKeyBuffer); ciphertextToDecrypt = msg.ciphertext_for_sender; isSelf = true; } catch (e2) { throw new Error(t('log_undecryptable_message')); } } const decryptedMessage = sodium.to_string(sodium.crypto_box_seal_open(sodium.from_base64(ciphertextToDecrypt, sodium.base64_variants.URLSAFE_NO_PADDING), recipientPKBuffer, privateKeyBuffer)); const senderUsername = isSelf ? identity.username : (dmPartner?.username || onlineUserMap.get(data.partnerPublicKey)?.username || 'Bilinmeyen'); addChatMessage({ username: senderUsername, message: decryptedMessage, timestamp: msg.timestamp, isSelf: isSelf, isEncrypted: true }); } catch (e) { addLog(t('log_undecryptable_message')); console.error(e); } } }); });

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        if (!input.value) return;
        const messageText = input.value;
        input.value = '';

        if (dmPartner) {
            if (!identity.privateKey) {
                return alert(t('error_key_missing'));
            }
            // DM için anında ekranda göster (Optimistic UI)
            addChatMessage({ username: identity.username, message: messageText, timestamp: new Date(), isSelf: true, isEncrypted: true });
            try {
                const recipientPublicKey = dmPartner.publicKey;
                const payload = {
                    recipientPublicKey: recipientPublicKey,
                    ciphertext_for_recipient: sodium.to_base64(sodium.crypto_box_seal(messageText, sodium.from_base64(recipientPublicKey, sodium.base64_variants.URLSAFE_NO_PADDING)), sodium.base64_variants.URLSAFE_NO_PADDING),
                    ciphertext_for_sender: sodium.to_base64(sodium.crypto_box_seal(messageText, sodium.from_base64(identity.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING)), sodium.base64_variants.URLSAFE_NO_PADDING)
                };
                socket.emit('private message', payload);
            } catch (error) {
                console.error("DM gönderilirken kritik şifreleme hatası:", error);
            }
        } else {
            // DEĞİŞİKLİK BURADA: Genel sohbet için de anında ekranda göster ve sunucuya yolla.
            // Sunucudan callback bekleme.
            addChatMessage({ username: identity.username, message: messageText, timestamp: new Date(), isSelf: true, isEncrypted: false });
            const payload = { message: messageText };
            socket.emit('chat message', payload);
        }
    });

    socket.on('private message', (data) => { const senderIsSelf = (data.senderPublicKey === identity.publicKey); const isFromCurrentPartner = dmPartner && data.senderPublicKey === dmPartner.publicKey; if (isFromCurrentPartner || (senderIsSelf && dmPartner && dmPartner.publicKey === identity.publicKey)) { try { const decrypted = sodium.to_string(sodium.crypto_box_seal_open(sodium.from_base64(data.ciphertext, sodium.base64_variants.URLSAFE_NO_PADDING), sodium.from_base64(identity.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING), sodium.from_base64(identity.privateKey, sodium.base64_variants.URLSAFE_NO_PADDING))); const isSelf = senderIsSelf; const senderUsername = isSelf ? identity.username : (onlineUserMap.get(data.senderPublicKey)?.username || 'Bilinmeyen'); if (!isSelf) playSound(); if (!isSelf || (isSelf && dmPartner.publicKey === identity.publicKey)) { addChatMessage({ username: senderUsername, message: decrypted, timestamp: new Date(), isSelf: isSelf, isEncrypted: true }); } } catch (e) { addLog(t('log_undecryptable_message')); console.error("DM decrypt hata:", e); } } else { const userElement = document.querySelector(`p[data-public-key="${data.senderPublicKey}"]`); if (userElement) { userElement.classList.add('new-message-indicator'); playSound(); } } });

    socket.on('chat message', (data) => { if (!dmPartner) { if (identity && data.username !== identity.username) playSound(); addChatMessage({ ...data, isSelf: false }); } });

    function escapeHtml(str) { return DOMPurify.sanitize(str); }

    function addChatMessage(data) { const item = document.createElement('li'); if (data.isSelf) item.classList.add('self-message'); const safeUsername = escapeHtml(data.username || 'Bilinmeyen'); const safeMessage = escapeHtml(data.message || ''); let safeTimestamp = ''; let dateObject; if (data.timestamp instanceof Date) { dateObject = data.timestamp; } else if (typeof data.timestamp === 'string' || typeof data.timestamp === 'number') { dateObject = new Date(data.timestamp); } if (dateObject && dateObject.toString() !== 'Invalid Date') { safeTimestamp = dateObject.toLocaleTimeString(localStorage.getItem('language') || 'tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); } else { safeTimestamp = escapeHtml(data.timestamp || ''); } const encryptedTag = data.isEncrypted ? ' 🔒' : ''; item.innerHTML = `<div class="message-content"><strong>${safeUsername}${encryptedTag}:</strong> ${safeMessage}</div><span class="timestamp">${safeTimestamp}</span>`; messages.appendChild(item); setTimeout(() => { messages.scrollTop = messages.scrollHeight; }, 10); }

    function addLog(text) { addChatMessage({ username: t('system_username'), message: text, timestamp: new Date() }); }



    checkIdentity();

})();
