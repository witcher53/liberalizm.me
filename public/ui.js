// /public/ui.js (NİHAİ SÜRÜM - Resim Görüntüleme Desteği)

function escapeHtml(str) {
    return DOMPurify.sanitize(str);
}

// ✅ YENİ: Dosyayı deşifre etme ve blob URL oluşturma fonksiyonu
async function decryptAndCreateBlobUrl(fileUrl, fileKeyBase64) {
    // 1. Şifreli Dosyayı CDN'den indir (ArrayBuffer olarak)
    const response = await fetch(fileUrl);
    if (!response.ok) throw new Error(`Dosya indirme başarısız: HTTP ${response.status}`);
    const encryptedFileBuffer = await response.arrayBuffer();
    const encryptedFileBytes = new Uint8Array(encryptedFileBuffer);
    
    // 2. Şifreleme Anahtarını (FileKey) çıkar
    const fileKey = sodium.from_base64(fileKeyBase64);
    
    // 3. Dosyadan Nonce ve Şifreli Metin/MAC'i çıkar (Nonce, client.js'te başa eklenmişti)
    const NONCE_BYTES = 24; // XChaCha20 için nonce boyutu 24 byte'tır
    const nonce = encryptedFileBytes.slice(0, NONCE_BYTES); // Nonce'ı dosyanın başından oku
    const ciphertextWithMac = encryptedFileBytes.slice(NONCE_BYTES);

    // 4. Dosyayı deşifre et
    const decryptedFileBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertextWithMac, 
        null, 
        nonce, 
        fileKey
    );
    
    // 5. Blob oluştur ve URL döndür
    const fileBlob = new Blob([decryptedFileBytes]); // Tipi tarayıcıya bırak
    return URL.createObjectURL(fileBlob);
}

export function addChatMessage(data, messagesEl, lang) {
    const item = document.createElement('li');
    if (data._id) {
        item.dataset.messageId = data._id;
    }

    if (data.isSelf) {
        item.classList.add('self-message');
    }

    const messageContent = document.createElement('div');
    messageContent.className = 'message-content';

    const usernameStrong = document.createElement('strong');
    
    const usernameSpan = document.createElement('span');
    usernameSpan.textContent = data.username || 'Bilinmeyen';
    
    if (data.publicKey && !data.isSelf) {
        usernameSpan.className = 'username-clickable';
        usernameSpan.dataset.publicKey = data.publicKey;
    }
    
    usernameStrong.appendChild(usernameSpan); 
    
    const statusText = document.createTextNode(`${data.isEncrypted ? ' 🔒' : ''}: `);
    usernameStrong.appendChild(statusText);

    const messageText = document.createElement('span');
    
    // ✅ GÜNCELLEME: Mesaj tipi kontrolü ve asenkron görüntüleme
    if (data.messageType === 'image' && data.message) {
        
        let fileUrl, encryptedKeyBase64;

        if (typeof data.message === 'string') {
            [fileUrl, encryptedKeyBase64] = data.message.split('::');
        } else {
            // Bu sadece history için geçerli olabilir (şu anki client.js yapısında buraya gelmemeli)
             fileUrl = data.message.fileUrl;
             encryptedKeyBase64 = data.message.encryptedKeyBase64;
        }

        // Yer tutucu ekle
        messageText.textContent = data.t('log_upload_start'); 
        messageContent.appendChild(usernameStrong);
        messageContent.appendChild(messageText);
        item.appendChild(messageContent);
        messagesEl.appendChild(item); // Mesajı hemen ekle
        
        // Bu veriler client.js'ten geliyor:
        const recipientPKBuffer = sodium.from_base64(data.identity.publicKey);
        const privateKeyBuffer = sodium.from_base64(data.identity.privateKey);

        if (fileUrl && encryptedKeyBase64) {
            // 1. Dosya şifreleme anahtarını (FileKey) deşifre et
            try {
                const fileKeyBase64 = sodium.to_string(sodium.crypto_box_seal_open(sodium.from_base64(encryptedKeyBase64), recipientPKBuffer, privateKeyBuffer));
                
                // 2. Resmi indir, deşifre et ve görüntüle
                decryptAndCreateBlobUrl(fileUrl, fileKeyBase64)
                    .then(blobUrl => {
                        const img = document.createElement('img');
                        img.src = blobUrl;
                        img.alt = 'Deşifrelenmiş Resim';
                        img.style.maxWidth = '300px'; 
                        img.style.maxHeight = '300px'; 
                        img.style.display = 'block';
                        img.style.marginTop = '5px';
                        img.style.borderRadius = '8px';
                        img.style.cursor = 'pointer';
                        img.onclick = () => window.open(blobUrl, '_blank');
                        
                        messageText.innerHTML = ''; 
                        messageText.appendChild(img);
                    })
                    .catch(err => {
                        console.error("Resim deşifre/görüntüleme hatası:", err);
                        messageText.textContent = data.t('log_image_decrypt_failed'); 
                    });

            } catch(e) {
                console.error("Anahtar deşifre hatası:", e);
                messageText.textContent = data.t('log_image_decrypt_failed');
            }
        }
        
    } else {
        // Varsayılan: Metin mesajını göster
        messageText.textContent = data.message || '';
        messageContent.appendChild(usernameStrong);
        messageContent.appendChild(messageText);
        item.appendChild(messageContent);
        messagesEl.appendChild(item);
    }
    
    // Zaman damgası ve silme butonu mantığı
    const timestampSpan = document.createElement('span');
    timestampSpan.className = 'timestamp';

    let dateObject;
    if (data.timestamp instanceof Date) {
        dateObject = data.timestamp;
    } else if (typeof data.timestamp === 'string' || typeof data.timestamp === 'number') {
        dateObject = new Date(data.timestamp);
    }

    if (dateObject && dateObject.toString() !== 'Invalid Date') {
        timestampSpan.textContent = dateObject.toLocaleTimeString(lang || 'tr-TR', { hour: '2-digit', minute: '2-digit' });
    } else {
        timestampSpan.textContent = '';
    }

    const controlsContainer = document.createElement('div');
    controlsContainer.className = 'message-controls';
    controlsContainer.appendChild(timestampSpan);
    
    if (data.isSelf && data.isEncrypted && data._id) {
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'delete-btn';
        deleteBtn.innerHTML = '&#128465;'; 
        deleteBtn.dataset.messageId = data._id;
        deleteBtn.title = 'Mesajı sil';
        controlsContainer.appendChild(deleteBtn);
    }
    
    item.appendChild(controlsContainer);

    setTimeout(() => {
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }, 10);
}

export function addLog(text, messagesEl, t) {
    addChatMessage({ username: t('system_username'), message: text, timestamp: new Date() }, messagesEl, localStorage.getItem('language'));
}

export function updateConversationOnlineStatus(publicKey, isOnline, conversationsDiv) {
    const userElement = conversationsDiv.querySelector(`p[data-public-key="${publicKey}"]`);
    if (userElement) {
        const indicator = userElement.querySelector('.online-indicator');
        if (isOnline && !indicator) {
            userElement.insertAdjacentHTML('afterbegin', '<span class="online-indicator">●</span> ');
        } else if (!isOnline && indicator) {
            if (indicator.nextSibling && indicator.nextSibling.nodeType === Node.TEXT_NODE) {
                indicator.nextSibling.remove();
            }
            indicator.remove();
        }
    }
}

export function renderUser(user, container, options) {
    const { identity, t, onUserClick, isOnline } = options;

    const userElement = document.createElement('p');
    userElement.dataset.publicKey = user.publicKey;

    if (isOnline) {
        const indicatorSpan = document.createElement('span');
        indicatorSpan.className = 'online-indicator';
        indicatorSpan.textContent = '●';
        userElement.appendChild(indicatorSpan);
        userElement.appendChild(document.createTextNode(' '));
    }

    const usernameNode = document.createTextNode(user.username || 'Bilinmeyen');
    userElement.appendChild(usernameNode);

    if (identity && user.publicKey === identity.publicKey) {
        const selfSuffixNode = document.createTextNode(` ${t('you_suffix')}`);
        userElement.appendChild(selfSuffixNode);
    }

    userElement.onclick = () => onUserClick(user, user.username);
    container.appendChild(userElement);
}
