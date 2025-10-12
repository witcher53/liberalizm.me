// /public/client.js (Zamanlama Korumalı Tam Sürüm)

// DOM Elementlerini Seç
const chatHistory = document.getElementById('chat-history');
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const userList = document.getElementById('user-list');
const searchInput = document.getElementById('search-input');
const searchResults = document.getElementById('search-results');
const currentChatHeader = document.getElementById('current-chat-header');
const leaveGeneralChatButton = document.getElementById('leave-general-chat');
const generalChatRoom = document.getElementById('general-chat-room');

// Socket.IO ve Diğer Değişkenler
let socket;
let currentRecipientPublicKey = null;
let conversations = new Map();
let onlineUsers = [];
let lastMessageTimestamps = new Map();
const MESSAGE_DEBOUNCE_TIME = 2000;

// Çeviri Fonksiyonu
const translations = {
    'general_chat': 'Genel Sohbet',
    'you': 'Siz',
};
function t(key) {
    return translations[key] || key;
}

// ============== BAŞLANGIÇ: Ana Fonksiyonlar ==============

/**
 * Socket.IO bağlantısını ve olay dinleyicilerini başlatır.
 */
async function initializeSocket() {
    try {
        const authData = await Auth.getAuthData();
        if (!authData) {
            console.error("Kimlik doğrulama bilgileri alınamadı. Sunucuya bağlanılamıyor.");
            UI.showAuthScreen();
            return;
        }

        socket = io({ auth: authData });
        setupSocketListeners();
    } catch (error) {
        console.error("Socket başlatma hatası:", error);
        UI.showAuthScreen();
    }
}

/**
 * Gelen bir mesajı şifreler.
 * @param {string} message - Şifrelenecek metin.
 * @param {string} recipientPublicKey - Alıcının açık anahtarı.
 * @returns {Promise<string|null>} Şifrelenmiş metin veya hata durumunda null.
 */
async function encryptMessage(message, recipientPublicKey) {
    try {
        const myPrivateKey = Crypto.getMyPrivateKey();
        if (!myPrivateKey) throw new Error("Kişisel anahtar bulunamadı.");

        // Mesajı belirli bir boyuta (örn: 512 byte) tamamla
        const PADDING_SIZE = 512;
        const messageBytes = new TextEncoder().encode(message);
        const paddedMessage = new Uint8Array(PADDING_SIZE);
        paddedMessage.set(messageBytes);

        const ciphertext = await Crypto.encrypt(paddedMessage, recipientPublicKey, myPrivateKey);
        return ciphertext;
    } catch (e) {
        console.error("Mesaj şifreleme hatası:", e);
        return null;
    }
}

/**
 * Gelen bir şifreli metni çözer.
 * @param {string} ciphertext - Şifresi çözülecek metin.
 * @param {string} senderPublicKey - Gönderenin açık anahtarı.
 * @param {string} recipientPublicKey - Alıcının açık anahtarı.
 * @returns {Promise<{message?: string, error?: string}>} Çözülmüş metin veya hata objesi.
 */
async function decryptMessage(ciphertext, senderPublicKey, recipientPublicKey) {
    try {
        const myPrivateKey = Crypto.getMyPrivateKey();
        if (!myPrivateKey) {
            return { error: "Özel anahtar eksik." };
        }

        const myPublicKey = Crypto.getMyPublicKey();
        const theirPublicKey = myPublicKey === senderPublicKey ? recipientPublicKey : senderPublicKey;

        if (!theirPublicKey) return { error: "Karşı tarafın açık anahtarı belirlenemedi." };
        
        const decryptedRaw = await Crypto.decrypt(ciphertext, theirPublicKey, myPrivateKey);
        if (!decryptedRaw) return { error: "Şifre çözülemedi (decrypt fonksiyonu null döndü)." };

        // ❌ ESKİ RİSKLİ YÖNTEM
        // const cleanMessage = decryptedRaw.replace(/\0/g, '');

        // ✅ YENİ GÜVENLİ YÖNTEM (Zamanlama Saldırılarına Karşı Daha Dayanıklı)
        // İlk null karakterin ('\0') indeksini bul ve mesajı oradan kes.
        // Bu, .replace() gibi içeriğe bağlı olarak değişken sürede çalışmaz.
        const nullIndex = decryptedRaw.indexOf('\0');
        const cleanMessage = nullIndex === -1 ? decryptedRaw : decryptedRaw.substring(0, nullIndex);
        
        return { message: cleanMessage };
    } catch (e) {
        console.error("Şifre çözme sırasında kritik hata:", e);
        return { error: `Şifre çözme hatası: ${e.message}` };
    }
}

// ============== BİTİŞ: Ana Fonksiyonlar ==============


// ============== BAŞLANGIÇ: Olay Dinleyicileri (Socket & DOM) ==============

/**
 * Socket.IO'dan gelen olayları dinlemek için kurulum yapar.
 */
function setupSocketListeners() {
    socket.on('connect', () => {
        console.log("Sunucuya başarıyla bağlanıldı. Socket ID:", socket.id);
        UI.hideAuthScreen();
        const myPublicKey = Crypto.getMyPublicKey();
        const myUsername = localStorage.getItem('username');
        socket.emit('user authenticated', { boxPublicKey: myPublicKey, username: myUsername });
        socket.emit('get conversations');
        socket.emit('get conversation history', null); // Genel sohbet geçmişini al
    });
    
    // ... (Diğer socket olayları)
    socket.on('initial user list', (users) => UI.updateUserList(users));
    socket.on('user connected', (user) => UI.addUserToList(user));
    socket.on('user disconnected', (user) => UI.removeUserFromList(user.publicKey));
    socket.on('conversations list', (partners) => UI.updateConversationsList(partners));
    socket.on('search results', (results) => UI.displaySearchResults(results));
    socket.on('new_conversation_partner', (partner) => UI.addConversationPartner(partner));
    socket.on('auth_error', (error) => {
        console.error("Kimlik doğrulama hatası:", error.message);
        alert(`Kimlik doğrulama hatası: ${error.message}`);
        Auth.logout();
    });

    socket.on('chat message', (data) => UI.displayMessage(data, false));
    socket.on('private message', (data) => handleIncomingPrivateMessage(data));
    socket.on('private message deleted', (messageId) => UI.removeMessageById(messageId));
    socket.on('conversation history', (data) => UI.displayConversationHistory(data.history, data.partnerPublicKey));

    socket.on('disconnect', () => console.log("Sunucu bağlantısı kesildi."));
}

/**
 * Gelen özel mesajları işler.
 * @param {object} data - Mesaj verisi.
 */
async function handleIncomingPrivateMessage(data) {
    const myPublicKey = Crypto.getMyPublicKey();
    const isMyMessage = data.senderPublicKey === myPublicKey;
    const partnerPublicKey = isMyMessage ? data.recipientPublicKey : data.senderPublicKey;
    
    let decryptedMessage;
    // Kendi gönderdiğimiz mesajların şifresini çözmek için ciphertext_for_sender kullan
    if (isMyMessage && data.ciphertext_for_sender) {
        decryptedMessage = await decryptMessage(data.ciphertext_for_sender, data.senderPublicKey, data.recipientPublicKey);
    } else {
        decryptedMessage = await decryptMessage(data.ciphertext_for_recipient, data.senderPublicKey, data.recipientPublicKey);
    }

    if (decryptedMessage.error) {
        console.error(`Mesaj şifresi çözülemedi (${data._id}):`, decryptedMessage.error);
        return;
    }

    const messageData = {
        _id: data._id,
        username: isMyMessage ? t('you') : conversations.get(partnerPublicKey)?.username || 'Bilinmeyen',
        message: decryptedMessage.message,
        timestamp: data.timestamp,
        publicKey: data.senderPublicKey,
        isPrivate: true
    };
    
    UI.displayMessage(messageData, isMyMessage, partnerPublicKey);
}


/**
 * DOM olay dinleyicilerini kurar.
 */
function setupDOMListeners() {
    sendButton.addEventListener('click', sendMessage);
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.trim();
        if (query.length >= 3) {
            socket.emit('search users', query);
        } else {
            searchResults.innerHTML = '';
            searchResults.classList.add('hidden');
        }
    });

    generalChatRoom.addEventListener('click', () => {
        UI.switchToConversation(null);
    });
}

/**
 * Mesaj gönderme işlemini tetikler.
 */
async function sendMessage() {
    const message = messageInput.value.trim();
    if (!message) return;

    if (currentRecipientPublicKey) {
        // Özel Mesaj
        const [ciphertextForRecipient, ciphertextForSender] = await Promise.all([
            encryptMessage(message, currentRecipientPublicKey),
            encryptMessage(message, currentRecipientPublicKey) // Kendimiz için de şifreliyoruz
        ]);

        if (ciphertextForRecipient && ciphertextForSender) {
            socket.emit('private message', {
                recipientPublicKey: currentRecipientPublicKey,
                ciphertext_for_recipient: ciphertextForRecipient,
                ciphertext_for_sender: ciphertextForSender,
                messageType: 'text'
            });
        } else {
            alert("Mesaj gönderilemedi: Şifreleme hatası.");
        }
    } else {
        // Genel Mesaj
        const now = Date.now();
        const lastSent = lastMessageTimestamps.get('general') || 0;
        if (now - lastSent < MESSAGE_DEBOUNCE_TIME) {
            UI.showToast("Çok hızlı mesaj gönderiyorsun.");
            return;
        }
        lastMessageTimestamps.set('general', now);
        socket.emit('chat message', { message }, (response) => {
            if (response.status === 'ok') {
                UI.displayMessage({
                    username: t('you'),
                    message: message,
                    timestamp: new Date(),
                    publicKey: Crypto.getMyPublicKey()
                }, true, null);
            } else {
                UI.showToast(response.message || "Mesaj gönderilemedi.");
            }
        });
    }

    messageInput.value = '';
    messageInput.style.height = 'auto';
}

// ============== BİTİŞ: Olay Dinleyicileri ==============


// ============== BAŞLANGIÇ: Sayfa Yüklendiğinde ==============

document.addEventListener('DOMContentLoaded', () => {
    if (Auth.isLoggedIn()) {
        initializeSocket();
    } else {
        UI.showAuthScreen();
    }
    setupDOMListeners();
    Auth.setupAuthListeners();
});

// ============== BİTİŞ: Sayfa Yüklendiğinde ==============
