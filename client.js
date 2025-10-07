// /home/witcher53/mesajlasma-uygulmamasi/public/client.js (FİNAL TEMİZ SÜRÜM - GÜVENLİK VE STATE YAMALI)

(async () => {
    // Dil ve temel DOM elemanları (değişiklik yok)
    let translations = {};
    async function setLanguage(lang) { try { const response = await fetch(`/locales/${lang}.json`); translations = await response.json(); document.querySelectorAll('[data-i18n]').forEach(el => { const key = el.getAttribute('data-i18n'); if (translations[key]) el.innerHTML = translations[key]; }); document.querySelectorAll('[data-i18n-placeholder]').forEach(el => { const key = el.getAttribute('data-i18n-placeholder'); if (translations[key]) el.setAttribute('placeholder', translations[key]); }); document.title = translations['page_title'] || 'Chat'; localStorage.setItem('language', lang); document.getElementById('lang-tr').classList.toggle('active', lang === 'tr'); document.getElementById('lang-en').classList.toggle('active', lang === 'en'); } catch (error) { console.error(`Could not load language: ${lang}`, error); } }
    function t(key) { return translations[key] || key; }
    document.getElementById('lang-en').addEventListener('click', () => setLanguage('en'));
    document.getElementById('lang-tr').addEventListener('click', () => setLanguage('tr'));
    const preferredLang = localStorage.getItem('language') || (navigator.language.startsWith('tr') ? 'tr' : 'en');
    await setLanguage(preferredLang);
    if (typeof sodium === 'undefined' || typeof io === 'undefined' || typeof DOMPurify === 'undefined') { document.body.innerHTML = `<h1>${t('error_libsodium')}</h1>`; return; }
    await sodium.ready;
    let socket = null;
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
    async function deriveKey(password, salt) { if (password.length < 8) throw new Error(t('alert_password_required')); if (sodium && typeof sodium.crypto_pwhash === 'function') { return sodium.crypto_pwhash(32, password, salt, sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE, sodium.crypto_pwhash_ALG_DEFAULT); } console.warn("Fallback KDF: PBKDF2 (WebCrypto)"); const enc = new TextEncoder(); const pwKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']); const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: 150000 }, pwKey, 256); return new Uint8Array(derivedBits); }
    async function encryptKey(keyBase64, password, salt) { const derivedKey = await deriveKey(password, salt); const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES); const keyBuffer = sodium.from_base64(keyBase64); const encryptedKey = sodium.crypto_secretbox_easy(keyBuffer, nonce, derivedKey); return sodium.to_base64(nonce) + '::' + sodium.to_base64(encryptedKey); }
    async function decryptKey(encryptedString, password, salt) { const derivedKey = await deriveKey(password, salt); const parts = (typeof encryptedString === 'string' ? encryptedString : '').split('::'); if (parts.length !== 2) throw new Error("Anahtar formatı bozuk."); try { const nonceBytes = sodium.from_base64(parts[0]); const encryptedBytes = sodium.from_base64(parts[1]); const decryptedKeyBuffer = sodium.crypto_secretbox_open_easy(encryptedBytes, nonceBytes, derivedKey); return sodium.to_base64(decryptedKeyBuffer); } catch (e) { console.error('decryptKey failed:', e.message); throw new Error("Şifre çözme başarısız — yanlış şifre veya bozuk veri."); } }
    function saveIdentity(id) { const storedId = { username: id.username, publicKey: id.publicKey, signPublicKey: id.signPublicKey, privateKey: id.encryptedPrivateKey, encryptedSignPrivateKey: id.encryptedSignPrivateKey, encryptedFPEKeyB: id.encryptedFPEKeyB, salt: id.salt }; localStorage.setItem('chatIdentity', JSON.stringify(storedId)); }
    async function checkIdentity() { const storedIdentity = localStorage.getItem('chatIdentity'); if (!storedIdentity) { loginOverlay.style.display = 'flex'; return; } let tempIdentity; try { tempIdentity = JSON.parse(storedIdentity); if (!tempIdentity.salt || !tempIdentity.encryptedSignPrivateKey || !tempIdentity.signPublicKey) { console.warn("Eski veya bozuk kimlik formatı algılandı. Lütfen yeni bir kimlik oluşturun."); localStorage.removeItem('chatIdentity'); loginOverlay.style.display = 'flex'; return; } } catch (e) { localStorage.removeItem('chatIdentity'); loginOverlay.style.display = 'flex'; return; } loginOverlay.style.display = 'flex'; passwordInput.style.display = 'block'; nameInput.value = tempIdentity.username; nameInput.disabled = true; submitNameBtn.textContent = t('decrypt_button'); passwordInput.focus(); submitNameBtn.onclick = async () => { const userPassword = passwordInput.value.trim(); if (!userPassword || userPassword.length < 8) { alert(t('alert_password_required')); return; } try { const salt = sodium.from_base64(tempIdentity.salt); const privateKeyBase64 = await decryptKey(tempIdentity.privateKey, userPassword, salt); const signPrivateKeyBase64 = await decryptKey(tempIdentity.encryptedSignPrivateKey, userPassword, salt); const fpeKeyB = await decryptKey(tempIdentity.encryptedFPEKeyB, userPassword, salt); identity = { username: tempIdentity.username, publicKey: tempIdentity.publicKey, privateKey: privateKeyBase64, signPublicKey: tempIdentity.signPublicKey, signPrivateKey: signPrivateKeyBase64, fpeKeyB: fpeKeyB, salt: tempIdentity.salt, encryptedPrivateKey: tempIdentity.privateKey, encryptedSignPrivateKey: tempIdentity.encryptedSignPrivateKey, encryptedFPEKeyB: tempIdentity.encryptedFPEKeyB }; nameInput.disabled = false; submitNameBtn.textContent = t('login_button'); await startChat(); } catch (e) { alert(t('alert_wrong_password')); console.error("Giriş sırasında hata:", e); } }; }
    async function createIdentity() { try { const username = nameInput.value.trim() || 'Anonim'; const userPassword = passwordInput.value.trim(); if (userPassword.length < 8) { alert(t('alert_password_required')); return; } const signKeyPair = sodium.crypto_sign_keypair(); const boxPublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(signKeyPair.publicKey); const boxPrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(signKeyPair.privateKey); const salt = sodium.randombytes_buf(16); const saltBase64 = sodium.to_base64(salt); const fpeKeyB = sodium.to_base64(sodium.randombytes_buf(32)); const encryptedPrivateKey = await encryptKey(sodium.to_base64(boxPrivateKey), userPassword, salt); const encryptedSignPrivateKey = await encryptKey(sodium.to_base64(signKeyPair.privateKey), userPassword, salt); const encryptedFPEKeyB = await encryptKey(fpeKeyB, userPassword, salt); identity = { username: username, publicKey: sodium.to_base64(boxPublicKey), privateKey: sodium.to_base64(boxPrivateKey), signPublicKey: sodium.to_base64(signKeyPair.publicKey), signPrivateKey: sodium.to_base64(signKeyPair.privateKey), encryptedPrivateKey, encryptedSignPrivateKey, fpeKeyB, encryptedFPEKeyB, salt: saltBase64 }; saveIdentity(identity); await startChat(); } catch (e) { console.error("Kimlik oluşturulurken hata:", e); alert(t('error_creating_identity')); } }
    async function startChat() { return new Promise((resolve, reject) => { const nonce = sodium.to_hex(sodium.randombytes_buf(32)); const signature = sodium.to_base64(sodium.crypto_sign_detached(sodium.from_hex(nonce), sodium.from_base64(identity.signPrivateKey))); socket = io({ auth: { publicKey: identity.signPublicKey, signature: signature, nonce: nonce } }); socket.on('connect', () => { console.log("Bağlantı başarılı, kimlik doğrulandı."); loginOverlay.style.display = 'none'; mainContainer.style.display = 'flex'; form.style.display = 'flex'; socket.emit('user authenticated', { username: identity.username, boxPublicKey: identity.publicKey }); socket.emit('get conversations'); activateChat(null, t('general_chat_title')); setupSocketListeners(); resolve(); }); socket.on('connect_error', (err) => { alert("Bağlanılamadı: " + err.message); console.error("Connection error:", err); if (socket) socket.disconnect(); loginOverlay.style.display = 'flex'; reject(err); }); }); }
    submitNameBtn.addEventListener('click', () => { if (nameInput.disabled) { submitNameBtn.onclick(); } else { createIdentity(); } });
    nameInput.addEventListener('keypress', (e) => { if (e.key === 'Enter' && !nameInput.disabled) { createIdentity(); } });
    passwordInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') { if (nameInput.disabled) { submitNameBtn.onclick(); } else { createIdentity(); } } });
    function activateChat(partner, title) { if (partner && partner.publicKey) { const userElement = document.querySelector(`#conversations p[data-public-key="${partner.publicKey}"]`); if (userElement) userElement.classList.remove('new-message-indicator'); } dmPartner = partner; chatTitle.textContent = title; input.placeholder = t('placeholder_write_message'); input.disabled = false; button.disabled = false; const historyTarget = partner ? partner.publicKey : null; socket.emit('get conversation history', historyTarget); }
    function renderUser(user, container) { const userElement = document.createElement('p'); userElement.dataset.publicKey = user.publicKey; if (onlineUserMap.has(user.publicKey)) { const onlineIndicator = document.createElement('span'); onlineIndicator.className = 'online-indicator'; onlineIndicator.textContent = '●'; userElement.appendChild(onlineIndicator); userElement.appendChild(document.createTextNode(' ')); } userElement.appendChild(document.createTextNode(user.username || 'Bilinmeyen')); if (identity && user.publicKey === identity.publicKey) { userElement.appendChild(document.createTextNode(` ${t('you_suffix')}`)); } userElement.onclick = () => activateChat(user, user.username); container.appendChild(userElement); }
    function setupSocketListeners() {
        socket.on('initial user list', (users) => { onlineUserMap.clear(); if(users) { users.forEach(user => { onlineUserMap.set(user.publicKey, user); }); } renderOnlineUserList(); });
        socket.on('user connected', (user) => { if (!onlineUserMap.has(user.publicKey)) { onlineUserMap.set(user.publicKey, user); renderOnlineUserList(); updateConversationOnlineStatus(user.publicKey, true); } });
        socket.on('user disconnected', (data) => { if (onlineUserMap.has(data.publicKey)) { onlineUserMap.delete(data.publicKey); renderOnlineUserList(); updateConversationOnlineStatus(data.publicKey, false); } });
        socket.on('conversations list', (partners) => { conversationsDiv.innerHTML = ''; const generalChat = document.createElement('p'); const strongTag = document.createElement('strong'); strongTag.textContent = t('general_chat_title'); generalChat.appendChild(strongTag); generalChat.classList.add('active-chat'); generalChat.style.cursor = 'pointer'; generalChat.onclick = () => activateChat(null, t('general_chat_title')); conversationsDiv.appendChild(generalChat); if(partners) { partners.forEach(user => { renderUser(user, conversationsDiv); }); } });
        socket.on('conversation history', (data) => { messages.innerHTML = ''; if (!data || !data.history) return; data.history.forEach(msg => { if (!data.partnerPublicKey) { if (!msg.ciphertext_for_recipient) { addChatMessage({ ...msg, isSelf: msg.username === identity.username }); } return; } if (msg.ciphertext_for_recipient) { let isSelf = false; let ciphertextToDecrypt = null; try { const recipientPKBuffer = sodium.from_base64(identity.publicKey); const privateKeyBuffer = sodium.from_base64(identity.privateKey); try { const ciphertextRecipientBuffer = sodium.from_base64(msg.ciphertext_for_recipient); sodium.crypto_box_seal_open(ciphertextRecipientBuffer, recipientPKBuffer, privateKeyBuffer); ciphertextToDecrypt = msg.ciphertext_for_recipient; isSelf = false; } catch (e) { try { const ciphertextSenderBuffer = sodium.from_base64(msg.ciphertext_for_sender); sodium.crypto_box_seal_open(ciphertextSenderBuffer, recipientPKBuffer, privateKeyBuffer); ciphertextToDecrypt = msg.ciphertext_for_sender; isSelf = true; } catch (e2) { throw new Error(t('log_undecryptable_message')); } } const decryptedMessage = sodium.to_string(sodium.crypto_box_seal_open(sodium.from_base64(ciphertextToDecrypt), recipientPKBuffer, privateKeyBuffer)); const senderUsername = isSelf ? identity.username : (dmPartner?.username || onlineUserMap.get(data.partnerPublicKey)?.username || 'Bilinmeyen'); addChatMessage({ username: senderUsername, message: decryptedMessage, timestamp: msg.timestamp, isSelf: isSelf, isEncrypted: true }); } catch (e) { addLog(t('log_undecryptable_message')); console.error(e); } } }); });

        // DEĞİŞTİRİLDİ VE YENİ MANTIK EKLENDİ
        socket.on('private message', (data) => {
            const senderIsSelf = (data.senderPublicKey === identity.publicKey);
            const isFromCurrentPartner = dmPartner && data.senderPublicKey === dmPartner.publicKey;

            if (isFromCurrentPartner || (senderIsSelf && dmPartner && dmPartner.publicKey === identity.publicKey)) {
                try {
                    const decrypted = sodium.to_string(sodium.crypto_box_seal_open(sodium.from_base64(data.ciphertext), sodium.from_base64(identity.publicKey), sodium.from_base64(identity.privateKey)));
                    const isSelf = senderIsSelf;
                    const senderUsername = isSelf ? identity.username : (onlineUserMap.get(data.senderPublicKey)?.username || 'Bilinmeyen');
                    if (!isSelf) playSound();
                    if (!isSelf || (isSelf && dmPartner.publicKey === identity.publicKey)) {
                        addChatMessage({ username: senderUsername, message: decrypted, timestamp: new Date(), isSelf: isSelf, isEncrypted: true });
                    }
                } catch (e) {
                    addLog(t('log_undecryptable_message'));
                    console.error("DM decrypt hata:", e);
                }
            } else {
                // YENİ MANTIK BURADA BAŞLIYOR
                // Mesajı gönderen kişi zaten sohbet listemizde var mı diye kontrol et.
                let conversationElement = conversationsDiv.querySelector(`p[data-public-key="${data.senderPublicKey}"]`);

                // Eğer sohbet listemizde yoksa, onu oluşturalım.
                if (!conversationElement) {
                    const senderInfo = onlineUserMap.get(data.senderPublicKey);
                    // Eğer kullanıcının bilgisini online haritasından bulabildiysek, sohbet listesine ekle.
                    if (senderInfo) {
                        renderUser(senderInfo, conversationsDiv);
                        // Elementi şimdi tekrar seçelim çünkü artık DOM'da var.
                        conversationElement = conversationsDiv.querySelector(`p[data-public-key="${data.senderPublicKey}"]`);
                    }
                }

                // Artık elementin var olduğundan emin olduğumuza göre, bildirim ışığını yakabiliriz.
                if (conversationElement) {
                    conversationElement.classList.add('new-message-indicator');
                    playSound();
                }
            }
        });
        
        socket.on('chat message', (data) => { if (!dmPartner) { if (identity && data.username !== identity.username) playSound(); addChatMessage({ ...data, isSelf: false }); } });
    }
    function renderOnlineUserList() { onlineUsersDiv.innerHTML = ''; const sortedUsers = Array.from(onlineUserMap.values()).sort((a, b) => { if (identity && a.publicKey === identity.publicKey) return -1; if (identity && b.publicKey === identity.publicKey) return 1; return a.username.localeCompare(b.username); }); sortedUsers.forEach(user => { renderUser(user, onlineUsersDiv); }); }
    function updateConversationOnlineStatus(publicKey, isOnline) { const userElement = conversationsDiv.querySelector(`p[data-public-key="${publicKey}"]`); if (userElement) { const indicator = userElement.querySelector('.online-indicator'); if (isOnline && !indicator) { const newIndicator = document.createElement('span'); newIndicator.className = 'online-indicator'; newIndicator.textContent = '●'; userElement.prepend(newIndicator); } else if (!isOnline && indicator) { indicator.remove(); } } }
    form.addEventListener('submit', (e) => { e.preventDefault(); if (!input.value) return; const messageText = input.value; input.value = ''; if (dmPartner) { if (!identity.privateKey) { return alert(t('error_key_missing')); } addChatMessage({ username: identity.username, message: messageText, timestamp: new Date(), isSelf: true, isEncrypted: true }); try { const recipientPublicKey = dmPartner.publicKey; const payload = { recipientPublicKey: recipientPublicKey, ciphertext_for_recipient: sodium.to_base64(sodium.crypto_box_seal(messageText, sodium.from_base64(recipientPublicKey))), ciphertext_for_sender: sodium.to_base64(sodium.crypto_box_seal(messageText, sodium.from_base64(identity.publicKey))) }; socket.emit('private message', payload); } catch (error) { console.error("DM gönderilirken kritik şifreleme hatası:", error); } } else { addChatMessage({ username: identity.username, message: messageText, timestamp: new Date(), isSelf: true, isEncrypted: false }); const payload = { message: messageText }; socket.emit('chat message', payload); } });
    function escapeHtml(str) { return DOMPurify.sanitize(str); }
    function addChatMessage(data) { const item = document.createElement('li'); if (data.isSelf) item.classList.add('self-message'); const safeUsername = data.username || 'Bilinmeyen'; const safeMessage = data.message || ''; const encryptedTag = data.isEncrypted ? ' 🔒' : ''; let safeTimestamp = ''; let dateObject; if (data.timestamp instanceof Date) { dateObject = data.timestamp; } else if (typeof data.timestamp === 'string' || typeof data.timestamp === 'number') { dateObject = new Date(data.timestamp); } if (dateObject && !isNaN(dateObject.getTime())) { safeTimestamp = dateObject.toLocaleTimeString(localStorage.getItem('language') || 'tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); } else { safeTimestamp = (data.timestamp || '').toString(); } const messageContentDiv = document.createElement('div'); messageContentDiv.className = 'message-content'; const strongTag = document.createElement('strong'); strongTag.textContent = `${safeUsername}${encryptedTag}:`; messageContentDiv.appendChild(strongTag); messageContentDiv.appendChild(document.createTextNode(` ${safeMessage}`)); const timestampSpan = document.createElement('span'); timestampSpan.className = 'timestamp'; timestampSpan.textContent = safeTimestamp; item.appendChild(messageContentDiv); item.appendChild(timestampSpan); messages.appendChild(item); setTimeout(() => { messages.scrollTop = messages.scrollHeight; }, 10); }
    function addLog(text) { addChatMessage({ username: t('system_username'), message: text, timestamp: new Date() }); }
    checkIdentity();
})();
