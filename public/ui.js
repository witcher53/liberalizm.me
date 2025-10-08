// /public/ui.js (Güvenli ve Tam Hali)

function escapeHtml(str) {
    // DOMPurify sanitization'ı burada bir katman olarak kalabilir, zararı yok.
    return DOMPurify.sanitize(str);
}

// --- BAŞLANGIÇ: GÜVENLİ addChatMessage FONKSİYONU ---
export function addChatMessage(data, messagesEl, lang) {
    const item = document.createElement('li');
    if (data.isSelf) {
        item.classList.add('self-message');
    }

    const messageContent = document.createElement('div');
    messageContent.className = 'message-content';

    const usernameStrong = document.createElement('strong');
    // .textContent kullanarak kullanıcı adını ve ikonu güvenli bir şekilde ata
    usernameStrong.textContent = `${data.username || 'Bilinmeyen'}${data.isEncrypted ? ' 🔒' : ''}: `;
    
    const messageText = document.createElement('span');
    // .textContent kullanarak mesajı güvenli bir şekilde ata
    messageText.textContent = data.message || '';

    messageContent.appendChild(usernameStrong);
    messageContent.appendChild(messageText);

    const timestampSpan = document.createElement('span');
    timestampSpan.className = 'timestamp';

    let dateObject;
    if (data.timestamp instanceof Date) {
        dateObject = data.timestamp;
    } else if (typeof data.timestamp === 'string' || typeof data.timestamp === 'number') {
        dateObject = new Date(data.timestamp);
    }

    if (dateObject && dateObject.toString() !== 'Invalid Date') {
        // .textContent kullanarak zaman damgasını güvenli bir şekilde ata
        timestampSpan.textContent = dateObject.toLocaleTimeString(lang || 'tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } else {
        timestampSpan.textContent = data.timestamp || '';
    }

    item.appendChild(messageContent);
    item.appendChild(timestampSpan);
    
    messagesEl.appendChild(item);
    setTimeout(() => {
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }, 10);
}
// --- BİTİŞ: GÜVENLİ FONKSİYON ---

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
