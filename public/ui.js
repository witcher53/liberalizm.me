// Bu dosya, DOM'u manipüle eden tüm arayüz fonksiyonlarını içerir.

function escapeHtml(str) {
    return DOMPurify.sanitize(str);
}

export function addChatMessage(data, messagesEl, lang) {
    const item = document.createElement('li');
    if (data.isSelf) item.classList.add('self-message');
    
    const safeUsername = escapeHtml(data.username || 'Bilinmeyen');
    const safeMessage = escapeHtml(data.message || '');
    let safeTimestamp = '';
    let dateObject;

    if (data.timestamp instanceof Date) {
        dateObject = data.timestamp;
    } else if (typeof data.timestamp === 'string' || typeof data.timestamp === 'number') {
        dateObject = new Date(data.timestamp);
    }

    if (dateObject && dateObject.toString() !== 'Invalid Date') {
        safeTimestamp = dateObject.toLocaleTimeString(lang || 'tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } else {
        safeTimestamp = escapeHtml(data.timestamp || '');
    }
    
    const encryptedTag = data.isEncrypted ? ' 🔒' : '';
    item.innerHTML = `<div class="message-content"><strong>${safeUsername}${encryptedTag}:</strong> ${safeMessage}</div><span class="timestamp">${safeTimestamp}</span>`;
    
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
