// /public/ui.js (NİHAİ SÜRÜM - Resim Görüntüleme Desteği)

function escapeHtml(str) {
    return DOMPurify.sanitize(str);
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
    
    // ✅ YENİ: Mesaj tipi kontrolü
    if (data.messageType === 'image' && data.message && data.message.startsWith('http')) {
        // Eğer mesaj tipi resimse, şifrelenmiş resim url'sini göster
        const img = document.createElement('img');
        img.src = data.message;
        img.alt = 'Şifreli Resim';
        img.style.maxWidth = '300px'; 
        img.style.maxHeight = '300px'; 
        img.style.display = 'block';
        img.style.marginTop = '5px';

        // Resmi bir konteynere sar
        const imageWrapper = document.createElement('div');
        imageWrapper.appendChild(img);
        
        // Resim etiketini mesaj içeriğine ekle
        messageText.innerHTML = ''; // Metin alanını temizle
        messageText.appendChild(imageWrapper);
    } else {
        // Varsayılan: Metin mesajını göster
        messageText.textContent = data.message || '';
    }

    messageContent.appendChild(usernameStrong);
    messageContent.appendChild(messageText);

    item.appendChild(messageContent);

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

    // --- BAŞLANGIÇ: SİLME BUTONU EKLEME ---
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
    // --- BİTİŞ: SİLME BUTONU EKLEME ---
    
    messagesEl.appendChild(item);
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
