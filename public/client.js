// /public/client.js (NİHAİ SÜRÜM - Resim Akışı ve Loglar Eklendi)
import * as Crypto from './crypto.js';
import * as UI from './ui.js';
import * as Auth from './auth.js';
function init() {
    (async () => {
        // ... (init fonksiyonunun başı aynı)
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
            // Anahtar parmak izini gösterecek DOM elemanı
            keyFingerprintContainer: document.getElementById('key-fingerprint-container'),
            // ✅ YENİ: Dosya yükleme DOM elemanları
            fileInput: document.getElementById('file-input'),
            fileUploadLabel: document.getElementById('file-upload-label'),
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
            
            // ✅ YENİ: Dosya yüklemeyi sadece DM'de etkinleştir
            if (dmPartner) {
                dom.fileUploadLabel.style.display = 'block';
            } else {
                dom.fileUploadLabel.style.display = 'none';
                dom.fileInput.value = ''; // Seçili dosyayı temizle
            }

            const historyTarget = partner ? partner.publicKey : null;
            socket.emit('get conversation history', historyTarget);
            
            // Ortak Gizli Kod (Shared Secret) Gösterme Mantığı
            if (dmPartner && dom.keyFingerprintContainer) {
                // Hata Düzeltme: generateSharedSecret çağrısı
                const sharedSecret = Crypto.generateSharedSecret(identity.publicKey, dmPartner.publicKey);
                
                dom.keyFingerprintContainer.innerHTML = `
                    <span style="font-weight:bold;">${t('key_fingerprint_title')}:</span> 
                    <span style="font-family:monospace; color:#3a3;">${sharedSecret}</span>
                    <span style="font-size:0.8em; display:block; color:#ff4d4d;">${t('key_fingerprint_warning')}</span>
                `;
            } else if (dom.keyFingerprintContainer) {
                dom.keyFingerprintContainer.innerHTML = '';
            }
        }

        // ... (renderOnlineUserList ve setupSocketListeners aynı)
        function renderOnlineUserList() {
            dom.onlineUsersDiv.innerHTML = '';
            const sortedUsers = Array.from(onlineUserMap.values()).sort((a, b) => {
                if (identity && a.publicKey === identity.publicKey) return -1;
                if (identity && b.publicKey === identity.publicKey) return 1;
                return a.username.localeCompare(b.username);
            });
            sortedUsers.forEach(user => UI.renderUser(user, dom.onlineUsersDiv, { identity, t, onUserClick: activateChat, isOnline: onlineUserMap.has(user.publicKey) }));
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
            
            // --- BAŞLANGIÇ: 'conversation history' DÜZELTMESİ ---
            socket.on('conversation history', (data) => {
                dom.messages.innerHTML = '';
                if (!data || !data.history) return;
                const recipientPKBuffer = sodium.from_base64(identity.publicKey);
                const privateKeyBuffer = sodium.from_base64(identity.privateKey);
                data.history.forEach(msg => {
                    // ✅ YENİ: messageType kontrolü eklendi
                    if (!data.partnerPublicKey) { 
                        UI.addChatMessage({ ...msg, isSelf: msg.username === identity.username, messageType: msg.messageType || 'text' }, dom.messages, localStorage.getItem('language')); 
                        return; 
                    }
                    
                    const isSelf = (msg.senderPublicKey === identity.publicKey);
                    let ciphertextToDecrypt = null;

                    if (isSelf && msg.ciphertext_for_sender) {
                        ciphertextToDecrypt = msg.ciphertext_for_sender;
                    } else if (!isSelf && msg.ciphertext_for_recipient) {
                        ciphertextToDecrypt = msg.ciphertext_for_recipient;
                    }
                    
                    if (ciphertextToDecrypt) { 
                        try { 
                            const decrypted = sodium.to_string(sodium.crypto_box_seal_open(sodium.from_base64(ciphertextToDecrypt), recipientPKBuffer, privateKeyBuffer)); 
                            const senderUsername = isSelf ? identity.username : (dmPartner?.username || onlineUserMap.get(data.partnerPublicKey)?.username || 'Bilinmeyen'); 
                            // ✅ YENİ: messageType client'a aktarılıyor
                            UI.addChatMessage({ _id: msg._id, username: senderUsername, message: decrypted, timestamp: msg.timestamp, isSelf: isSelf, isEncrypted: true, messageType: msg.messageType || 'text' }, dom.messages, localStorage.getItem('language')); 
                        } catch (e) { 
                            UI.addLog(t('log_undecryptable_message'), dom.messages, t); 
                        } 
                    } else { 
                        UI.addLog(t('log_undecryptable_message'), dom.messages, t); 
                    }
                });
            });
            // --- BİTİŞ: 'conversation history' DÜZELTMESİ ---

            // --- BAŞLANGIÇ: 'private message' DÜZELTMESİ ---
            socket.on('private message', (msg) => {
                if (document.querySelector(`li[data-message-id="${msg._id}"]`)) return;

                const isSelf = (msg.senderPublicKey === identity.publicKey);
                const partnerPK = isSelf ? msg.recipientPublicKey : msg.senderPublicKey;
                
                const isFromCurrent = dmPartner && partnerPK === dmPartner.publicKey;
                
                if (isFromCurrent) {
                    const ciphertext = isSelf ? msg.ciphertext_for_sender : msg.ciphertext_for_recipient;
                    try { 
                        const decrypted = sodium.to_string(sodium.crypto_box_seal_open(sodium.from_base64(ciphertext), sodium.from_base64(identity.publicKey), sodium.from_base64(identity.privateKey))); 
                        const senderUsername = isSelf ? identity.username : (dmPartner?.username || 'Bilinmeyen');
                        playSound(); 
                        // ✅ YENİ: messageType client'a aktarılıyor
                        UI.addChatMessage({ _id: msg._id, username: senderUsername, message: decrypted, timestamp: new Date(), isSelf: isSelf, isEncrypted: true, messageType: msg.messageType || 'text' }, dom.messages, localStorage.getItem('language')); 
                    } catch (e) { 
                        UI.addLog(t('log_undecryptable_message'), dom.messages, t); 
                    }
                } else if (!isSelf) { 
                    const userEl = document.querySelector(`p[data-public-key="${msg.senderPublicKey}"]`); 
                    if (userEl) { 
                        userEl.classList.add('new-message-indicator'); 
                        playSound(); 
                    } 
                }
            });
            // --- BİTİŞ: 'private message' DÜZELTMESİ ---
            
            socket.on('chat message', (data) => { if (!dmPartner && identity && data.username !== identity.username) { playSound(); UI.addChatMessage({ ...data, isSelf: false }, dom.messages, localStorage.getItem('language')); } });
            socket.on('new_conversation_partner', (partner) => { if (!dom.conversationsDiv.querySelector(`p[data-public-key="${partner.publicKey}"]`) && partner) { UI.renderUser(partner, dom.conversationsDiv, { identity, t, onUserClick: activateChat, isOnline: onlineUserMap.has(partner.publicKey) }); UI.updateConversationOnlineStatus(partner.publicKey, onlineUserMap.has(partner.publicKey), dom.conversationsDiv); } });
            
            socket.on('private message deleted', (messageId) => {
                const messageElement = dom.messages.querySelector(`li[data-message-id="${messageId}"]`);
                if (messageElement) {
                    messageElement.remove();
                }
            });
        }

        // ============================================
        // ✅ YENİ: DOSYA İŞLEME VE YÜKLEME MANTIĞI
        // ============================================

        async function encryptAndUploadFile(file) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = async (event) => {
                    try {
                        // 1. Dosya verisini oku (Uint8Array)
                        const fileBytes = new Uint8Array(event.target.result);
                        
                        // 2. Rastgele bir şifreleme anahtarı oluştur (32 bayt)
                        const fileKey = sodium.randombytes_buf(32);
                        
                        // 3. Dosyayı Anahtar ile şifrele (XChaCha20-Poly1305)
                        const nonce = sodium.randombytes_buf(24); // XChaCha20 için nonce boyutu 24 byte'tır
                        // Encrypted dosya buffer'ı: Nonce + Şifreli Metin + MAC
                        const encryptedFile = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(fileBytes, null, nonce, fileKey);
                        
                        // 4. Şifreli Dosyayı FormData olarak hazırla
                        const formData = new FormData();
                        formData.append('file', new Blob([encryptedFile], { type: 'application/octet-stream' }), 'encrypted_file.dat');

                        // 5. Şifreli dosyayı API'ye yükle
                        const uploadResponse = await fetch('/api/upload', {
                            method: 'POST',
                            body: formData,
                        });

                        // S3/DO Spaces hatası varsa burada yakalanır
                        if (!uploadResponse.ok) {
                            let errorText = t('alert_upload_failed');
                            try {
                                const errorData = await uploadResponse.json();
                                errorText = errorData.error || errorText;
                            } catch (e) {
                                // JSON okunamadıysa, doğrudan statü kodunu göster
                                errorText = `${t('alert_upload_failed')} (HTTP ${uploadResponse.status})`;
                            }
                            throw new Error(errorText);
                        }

                        const result = await uploadResponse.json();
                        const fileUrl = result.url; // CDN URL'si
                        
                        // 6. Şifreleme anahtarını (FileKey) Base64'e dönüştür
                        const fileKeyBase64 = sodium.to_base64(fileKey);
                        const recipientPKBuffer = sodium.from_base64(dmPartner.publicKey);
                        const senderPKBuffer = sodium.from_base64(identity.publicKey);
                        
                        // 7. Dosya URL'sini ve Anahtarını Gönderici ve Alıcı için Şifrele
                        // Mesaj içeriği: URL + '::' + Encrypted_File_Key (crypto_box_seal ile şifrelenmiş)
                        
                        // Alıcı için:
                        const encryptedKeyForRecipient = sodium.crypto_box_seal(fileKeyBase64, recipientPKBuffer);
                        const ciphertextForRecipient = fileUrl + '::' + sodium.to_base64(encryptedKeyForRecipient);

                        // Gönderici için: (Kendi anahtarımızla şifreliyoruz)
                        const encryptedKeyForSender = sodium.crypto_box_seal(fileKeyBase64, senderPKBuffer);
                        const ciphertextForSender = fileUrl + '::' + sodium.to_base64(encryptedKeyForSender);

                        resolve({ ciphertextForRecipient, ciphertextForSender });

                    } catch (e) {
                        console.error("Dosya şifreleme/yükleme hatası:", e);
                        // Hata mesajı alert'i zaten fetch'in içinde ayarlandı
                        alert(e.message);
                        reject(e);
                    }
                };

                reader.onerror = () => {
                     alert(t('alert_file_read_error'));
                     reject(new Error(t('alert_file_read_error')));
                };
                reader.readAsArrayBuffer(file);
            });
        }


        // ... (startChat, export/import, event listener'lar aynı kalıyor)
        async function startChat(id) {
            identity = id;
            return new Promise((resolve, reject) => {
                const timestampHex = Date.now().toString(16).padStart(16, '0');
                const randomBytes = sodium.to_hex(sodium.randombytes_buf(24));
                const nonce = timestampHex + randomBytes;
                const signature = sodium.to_base64(sodium.crypto_sign_detached(sodium.from_hex(nonce), sodium.from_base64(identity.signPrivateKey)));
                
                socket = io({ auth: { publicKey: identity.signPublicKey, signature: signature, nonce: nonce } });
                
                socket.on('auth_error', (data) => {
                    alert("Giriş Yapılamadı: " + data.message);
                    if (socket) socket.disconnect();
                    dom.loginOverlay.style.display = 'flex';
                    dom.nameInput.disabled = false;
                    dom.passwordInput.value = '';
                    dom.nameInput.focus();
                    reject(new Error("AUTH_SPECIFIC_ERROR_HANDLED")); 
                });
                
                socket.on('connect', () => {
                    console.log("Bağlantı başarılı, kimlik doğrulandı.");
                    dom.loginOverlay.style.display = 'none';
                    dom.mainContainer.style.display = 'flex';
                    dom.form.style.display = 'flex';
                    socket.emit('user authenticated', { username: identity.username, boxPublicKey: identity.publicKey });
                    socket.emit('get conversations');
                    setupSocketListeners();
                    
                    const HEARTBEAT_INTERVAL = 20000;
                    let heartbeatIntervalId = setInterval(() => { 
                        if (socket.connected) socket.emit('heartbeat'); 
                    }, HEARTBEAT_INTERVAL);
                    
                    socket.once('disconnect', () => {
                        clearInterval(heartbeatIntervalId);
                        document.removeEventListener('visibilitychange', visibilityHandler); 
                    });

                    const visibilityHandler = () => {
                        if (document.visibilityState === 'visible' && socket.connected) {
                            socket.emit('heartbeat');
                        }
                    };
                    document.addEventListener('visibilitychange', visibilityHandler);
                    if (socket.connected) socket.emit('heartbeat');
                    
                    resolve();
                });
                
                socket.on('connect_error', (err) => {
                    console.error("Bağlantı Hatası (Detay):", err.message);
                    alert(t('connection_error_generic') || "Sunucuya bağlanılamadı. Lütfen daha sonra tekrar deneyin.");
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
        
        dom.messages.addEventListener('click', (e) => {
            if (e.target.classList.contains('username-clickable')) {
                const publicKey = e.target.dataset.publicKey;
                if (publicKey && publicKey !== identity.publicKey) {
                    const user = onlineUserMap.get(publicKey);
                    if (user) activateChat(user, user.username);
                }
            }
            if (e.target.classList.contains('delete-btn')) {
                const messageId = e.target.dataset.messageId;
                if (messageId && confirm(t('confirm_delete_message') || 'Bu mesajı herkesten silmek istediğinize emin misiniz?')) {
                    socket.emit('delete private message', messageId);
                }
            }
        });

        // ============================================
        // ✅ YENİ: DOSYA SEÇME OLAYI
        // ============================================

        dom.fileInput.addEventListener('change', () => {
            if (dom.fileInput.files.length > 0) {
                dom.input.placeholder = `${dom.fileInput.files[0].name} ${t('placeholder_file_attached')}`;
                dom.input.disabled = true; // Dosya varsa metin girişi devre dışı
                dom.button.disabled = false;
            } else {
                dom.input.placeholder = t('placeholder_write_message');
                dom.input.disabled = false;
            }
        });


        const handleLoginSubmit = () => {
            if (existingIdentity) {
                Auth.loginWithPassword(existingIdentity);
            } else {
                Auth.createIdentity();
            }
        };

        // ============================================
        // ✅ GÜNCELLEME: FORM GÖNDERME
        // ============================================

        dom.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const file = dom.fileInput.files[0];

            if (dmPartner) {
                if (file) {
                    // Dosya gönderme işlemi
                    UI.addLog(t('log_upload_start'), dom.messages, t); // <-- LOG BAŞLANGIÇ
                    dom.button.disabled = true;
                    dom.fileUploadLabel.style.cursor = 'progress';
                    
                    try {
                        const { ciphertextForRecipient, ciphertextForSender } = await encryptAndUploadFile(file);
                        
                        const payload = { 
                            recipientPublicKey: dmPartner.publicKey, 
                            ciphertext_for_recipient: ciphertextForRecipient, 
                            ciphertext_for_sender: ciphertextForSender,
                            messageType: 'image' // Yeni mesaj tipi
                        };
                        socket.emit('private message', payload);
                        
                        // Başarılı logu
                        UI.addLog(t('log_upload_success'), dom.messages, t); 
                        
                    } catch (error) {
                        console.error("Dosya yükleme/gönderme başarısız:", error);
                        UI.addLog(t('log_upload_fail'), dom.messages, t); // <-- LOG HATA
                        // alert zaten encryptAndUploadFile içinde çağrılıyor
                    } finally {
                        dom.fileInput.value = ''; // Seçili dosyayı temizle
                        dom.input.disabled = false; 
                        dom.button.disabled = false;
                        dom.fileUploadLabel.style.cursor = 'pointer';
                        dom.input.placeholder = t('placeholder_write_message');
                    }

                } else if (dom.input.value) {
                    // Metin gönderme işlemi
                    const messageText = dom.input.value;
                    dom.input.value = '';
                    const payload = { 
                        recipientPublicKey: dmPartner.publicKey, 
                        ciphertext_for_recipient: sodium.to_base64(sodium.crypto_box_seal(messageText, sodium.from_base64(dmPartner.publicKey))), 
                        ciphertext_for_sender: sodium.to_base64(sodium.crypto_box_seal(messageText, sodium.from_base64(identity.publicKey))),
                        messageType: 'text' // Varsayılan mesaj tipi
                    };
                    socket.emit('private message', payload);
                }
            } else if (dom.input.value) {
                // Genel Sohbet (Metin)
                const messageText = dom.input.value;
                dom.input.value = '';
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
        dom.passwordInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') handleLoginSubmit(); });
        dom.nameInput.addEventListener('keypress', (e) => { if (e.key === 'Enter' && !existingIdentity) handleLoginSubmit(); });

        dom.exportIdentityBtn.addEventListener('click', exportIdentity);
        dom.importIdentityInput.addEventListener('change', importIdentity);

        existingIdentity = Auth.checkIdentity();
    })();
}

document.addEventListener('DOMContentLoaded', init);
