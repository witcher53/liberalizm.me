// /public/client.js (DÜZELTİLMİŞ VE EKSİKSİZ SÜRÜM)
import * as Crypto from './crypto.js';
import * as UI from './ui.js';
 import * as Auth from './auth.js';
function init() {
    (async () => {
        let translations = {};
        async function setLanguage(lang) {
            try {
                const response = await fetch(`/locales/${lang}.json`);
                translations = await response.json();
            } catch (error) {
                console.error(`Could not load language file: ${lang}`, error);
                translations = {};
            }
            document.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                if (translations[key]) {
                    if (el.tagName === 'BUTTON' || el.tagName === 'LABEL') {
                        el.textContent = translations[key];
                    } else {
                        el.innerHTML = translations[key];
                    }
                }
            });
            document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
                const key = el.getAttribute('data-i18n-placeholder');
                if (translations[key]) el.setAttribute('placeholder', translations[key]);
            });
            document.title = translations['page_title'] || 'Chat';
            localStorage.setItem('language', lang);
            document.getElementById('lang-tr').classList.toggle('active', lang === 'tr');
            document.getElementById('lang-en').classList.toggle('active', lang === 'en');
        }
        function t(key) { return translations[key] || key; }
        const preferredLang = localStorage.getItem('language') || (navigator.language.startsWith('tr') ? 'tr' : 'en');
        await setLanguage(preferredLang);
        document.getElementById('lang-en').addEventListener('click', () => setLanguage('en'));
        document.getElementById('lang-tr').addEventListener('click', () => setLanguage('tr'));
        if (typeof sodium === 'undefined' || typeof io === 'undefined' || typeof DOMPurify === 'undefined') {
            document.body.innerHTML = `<h1>${t('error_libsodium')}</h1>`;
            return;
        }
        await sodium.ready;

        const dom = {
            messages: document.getElementById('messages'),
            form: document.getElementById('form'),
            input: document.getElementById('input'),
            button: document.querySelector('#form button'),
            loginOverlay: document.getElementById('login-overlay'),
            loginBox: document.getElementById('login-box'),
            nameInput: document.getElementById('name-input'),
            passwordInput: document.getElementById('password-input'),
            submitNameBtn: document.getElementById('submit-name'),
            mainContainer: document.getElementById('main-container'),
            soundToggle: document.getElementById('sound-toggle'),
            conversationsDiv: document.getElementById('conversations'),
            onlineUsersDiv: document.getElementById('online-users'),
            chatTitle: document.getElementById('chat-title'),
            exportIdentityBtn: document.getElementById('export-identity'),
            importIdentityInput: document.getElementById('import-identity-input'),
        };

        let socket = null;
        let identity = null;
        let isMuted = true;
        let dmPartner = null;
        let onlineUserMap = new Map();

        function playSound() { if (isMuted) return; new Audio('/notification.mp3').play().catch(() => {}); }

        function activateChat(partner, title) {
            const currentActive = dom.conversationsDiv.querySelector('.active-chat');
            if (currentActive) currentActive.classList.remove('active-chat');
            if (partner && partner.publicKey) {
                const userElement = dom.conversationsDiv.querySelector(`p[data-public-key="${partner.publicKey}"]`);
                if (userElement) {
                    userElement.classList.add('active-chat');
                    userElement.classList.remove('new-message-indicator');
                }
            } else {
                const generalChatElement = dom.conversationsDiv.querySelector('p:first-child');
                if (generalChatElement) generalChatElement.classList.add('active-chat');
            }
            dmPartner = partner;
            dom.chatTitle.textContent = title;
            dom.input.placeholder = t('placeholder_write_message');
            dom.input.disabled = false;
            dom.button.disabled = false;
            const historyTarget = partner ? partner.publicKey : null;
            socket.emit('get conversation history', historyTarget);
        }

        function renderOnlineUserList() {
            dom.onlineUsersDiv.innerHTML = '';
            const sortedUsers = Array.from(onlineUserMap.values()).sort((a, b) => {
                if (identity && a.publicKey === identity.publicKey) return -1;
                if (identity && b.publicKey === identity.publicKey) return 1;
                return a.username.localeCompare(b.username);
            });
            sortedUsers.forEach(user => UI.renderUser(user, dom.onlineUsersDiv, { identity, t, onUserClick: activateChat, isOnline: true }));
        }

        function setupSocketListeners() {
            socket.on('initial user list', (users) => { onlineUserMap.clear(); if (users) { users.forEach(user => onlineUserMap.set(user.publicKey, user)); } renderOnlineUserList(); });
            socket.on('user connected', (user) => { onlineUserMap.set(user.publicKey, user); renderOnlineUserList(); UI.updateConversationOnlineStatus(user.publicKey, true, dom.conversationsDiv); });
            socket.on('user disconnected', (data) => { if (onlineUserMap.has(data.publicKey)) { onlineUserMap.delete(data.publicKey); renderOnlineUserList(); UI.updateConversationOnlineStatus(data.publicKey, false, dom.conversationsDiv); } });
            socket.on('conversations list', (partners) => {
                dom.conversationsDiv.innerHTML = '';
                const generalChat = document.createElement('p');
                generalChat.innerHTML = `<strong>${t('general_chat_title')}</strong>`;
                generalChat.style.cursor = 'pointer';
                generalChat.onclick = () => activateChat(null, t('general_chat_title'));
                dom.conversationsDiv.appendChild(generalChat);
                if (partners) partners.forEach(user => UI.renderUser(user, dom.conversationsDiv, { identity, t, onUserClick: activateChat, isOnline: onlineUserMap.has(user.publicKey) }));
                activateChat(null, t('general_chat_title'));
            });
            socket.on('conversation history', (data) => {
                dom.messages.innerHTML = '';
                if (!data || !data.history) return;
                const recipientPKBuffer = sodium.from_base64(identity.publicKey);
                const privateKeyBuffer = sodium.from_base64(identity.privateKey);
                data.history.forEach(msg => {
                    if (!data.partnerPublicKey) { UI.addChatMessage({ ...msg, isSelf: msg.username === identity.username }, dom.messages, localStorage.getItem('language')); return; }
                    let isSelf = false, ciphertextToDecrypt = null;
                    if (msg.ciphertext_for_sender) { try { sodium.crypto_box_seal_open(sodium.from_base64(msg.ciphertext_for_sender), recipientPKBuffer, privateKeyBuffer); ciphertextToDecrypt = msg.ciphertext_for_sender; isSelf = true; } catch (e) {} }
                    if (!ciphertextToDecrypt && msg.ciphertext_for_recipient) { try { sodium.crypto_box_seal_open(sodium.from_base64(msg.ciphertext_for_recipient), recipientPKBuffer, privateKeyBuffer); ciphertextToDecrypt = msg.ciphertext_for_recipient; isSelf = false; } catch (e) {} }
                    if (ciphertextToDecrypt) { try { const decrypted = sodium.to_string(sodium.crypto_box_seal_open(sodium.from_base64(ciphertextToDecrypt), recipientPKBuffer, privateKeyBuffer)); const sender = isSelf ? identity.username : (dmPartner?.username || onlineUserMap.get(data.partnerPublicKey)?.username || 'Bilinmeyen'); UI.addChatMessage({ username: sender, message: decrypted, timestamp: msg.timestamp, isSelf: isSelf, isEncrypted: true }, dom.messages, localStorage.getItem('language')); } catch (e) { UI.addLog(t('log_undecryptable_message'), dom.messages, t); } } else { UI.addLog(t('log_undecryptable_message'), dom.messages, t); }
                });
            });
            socket.on('private message', (data) => {
                const isFromCurrent = dmPartner && data.senderPublicKey === dmPartner.publicKey;
                if(isFromCurrent) { try { const decrypted = sodium.to_string(sodium.crypto_box_seal_open(sodium.from_base64(data.ciphertext), sodium.from_base64(identity.publicKey), sodium.from_base64(identity.privateKey))); const sender = onlineUserMap.get(data.senderPublicKey)?.username || 'Bilinmeyen'; playSound(); UI.addChatMessage({ username: sender, message: decrypted, timestamp: new Date(), isSelf: false, isEncrypted: true }, dom.messages, localStorage.getItem('language')); } catch (e) { UI.addLog(t('log_undecryptable_message'), dom.messages, t); } } else { const userEl = document.querySelector(`p[data-public-key="${data.senderPublicKey}"]`); if (userEl) { userEl.classList.add('new-message-indicator'); playSound(); } }
            });
            socket.on('chat message', (data) => { if (!dmPartner && identity && data.username !== identity.username) { playSound(); UI.addChatMessage({ ...data, isSelf: false }, dom.messages, localStorage.getItem('language')); } });
            socket.on('new_conversation_partner', (partner) => { if (!dom.conversationsDiv.querySelector(`p[data-public-key="${partner.publicKey}"]`) && partner) { UI.renderUser(partner, dom.conversationsDiv, { identity, t, onUserClick: activateChat, isOnline: onlineUserMap.has(partner.publicKey) }); UI.updateConversationOnlineStatus(partner.publicKey, onlineUserMap.has(partner.publicKey), dom.conversationsDiv); } });
        }

        async function startChat(id) {
            identity = id;
            return new Promise((resolve, reject) => {
                const timestampHex = Date.now().toString(16).padStart(16, '0');
                const randomBytes = sodium.to_hex(sodium.randombytes_buf(24));
                const nonce = timestampHex + randomBytes;
                const signature = sodium.to_base64(sodium.crypto_sign_detached(sodium.from_hex(nonce), sodium.from_base64(identity.signPrivateKey)));
                socket = io({ auth: { publicKey: identity.signPublicKey, signature: signature, nonce: nonce } });
                socket.on('connect', () => {
                    console.log("Bağlantı başarılı, kimlik doğrulandı.");
                    dom.loginOverlay.style.display = 'none';
                    dom.mainContainer.style.display = 'flex';
                    dom.form.style.display = 'flex';
                    socket.emit('user authenticated', { username: identity.username, boxPublicKey: identity.publicKey });
                    socket.emit('get conversations');
                    setupSocketListeners();
                    const HEARTBEAT_INTERVAL = 25000;
                    setInterval(() => { if (socket.connected) socket.emit('heartbeat'); }, HEARTBEAT_INTERVAL);
                    resolve();
                });
                socket.on('connect_error', (err) => {
                    alert("Bağlanılamadı: " + err.message);
                    if (socket) socket.disconnect();
                    dom.loginOverlay.style.display = 'flex';
                    reject(err);
                });
            });
        }

        function exportIdentity() {
            const identityString = localStorage.getItem('chatIdentity');
            if (!identityString) {
                alert(t('alert_no_identity_to_export') || "Dışa aktarılacak kimlik bulunamadı.");
                return;
            }
            try {
                const identityData = JSON.parse(identityString);
                const blob = new Blob([identityString], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `kimlik_${identityData.username || 'anonim'}.json`;
                dom.loginBox.appendChild(a);
                a.click();
                dom.loginBox.removeChild(a);
                URL.revokeObjectURL(url);
            } catch (e) {
                alert(t('alert_export_failed') || "Kimlik dışa aktarılamadı.");
                console.error("Kimlik dışa aktarılamadı:", e);
            }
        }

        function importIdentity(event) {
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const content = e.target.result;
                    const identityData = JSON.parse(content);
                    if (identityData.publicKey && identityData.salt && identityData.encryptedSignPrivateKey) {
                        localStorage.setItem('chatIdentity', content);
                        alert(t('alert_import_success') || "Kimlik başarıyla içe aktarıldı. Sayfa yenileniyor.");
                        location.reload();
                    } else {
                        throw new Error("Geçersiz kimlik dosyası formatı.");
                    }
                } catch (err) {
                    alert(t('alert_import_failed') || "Kimlik içe aktarılamadı.");
                    console.error("Kimlik içe aktarılamadı:", err);
                }
            };
            reader.readAsText(file);
            event.target.value = '';
        }

        let existingIdentity = null;

        dom.soundToggle.addEventListener('click', () => {
            isMuted = !isMuted;
            dom.soundToggle.textContent = isMuted ? t('sound_toggle_off') : t('sound_toggle_on');
            if(!isMuted) playSound();
        });

const handleLoginSubmit = () => {
    if (existingIdentity) {
        Auth.loginWithPassword(existingIdentity); // Auth. eklendi
    } else {
        Auth.createIdentity(); // Auth. eklendi
    }
};

        dom.form.addEventListener('submit', (e) => {
            e.preventDefault();
            if (!dom.input.value) return;
            const messageText = dom.input.value;
            dom.input.value = '';
            if (dmPartner) {
                UI.addChatMessage({ username: identity.username, message: messageText, timestamp: new Date(), isSelf: true, isEncrypted: true }, dom.messages, localStorage.getItem('language'));
                const payload = { recipientPublicKey: dmPartner.publicKey, ciphertext_for_recipient: sodium.to_base64(sodium.crypto_box_seal(messageText, sodium.from_base64(dmPartner.publicKey))), ciphertext_for_sender: sodium.to_base64(sodium.crypto_box_seal(messageText, sodium.from_base64(identity.publicKey))) };
                socket.emit('private message', payload);
            } else {
                UI.addChatMessage({ username: identity.username, message: messageText, timestamp: new Date(), isSelf: true, isEncrypted: false }, dom.messages, localStorage.getItem('language'));
                socket.emit('chat message', { message: messageText });
            }
        });

        Auth.initAuth({
            dom: { loginOverlay: dom.loginOverlay, nameInput: dom.nameInput, passwordInput: dom.passwordInput, submitNameBtn: dom.submitNameBtn },
            callbacks: { startChat },
            crypto: { encryptKey: Crypto.encryptKey, decryptKey: Crypto.decryptKey },
            utils: { t }
        });

        dom.submitNameBtn.addEventListener('click', handleLoginSubmit);
        dom.passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleLoginSubmit();
            }
        });
        dom.nameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !existingIdentity) {
                handleLoginSubmit();
            }
        });

        dom.exportIdentityBtn.addEventListener('click', exportIdentity);
        dom.importIdentityInput.addEventListener('change', importIdentity);

 existingIdentity = Auth.checkIdentity(); // Auth. eklendi
    })();
}

document.addEventListener('DOMContentLoaded', init);
