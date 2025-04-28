// Validation utilities
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML.replace(/[<>{}]/g, '');
}

function validateInput(input, maxLength, isHash = false) {
    if (!input) return {valid: false, message: 'Field cannot be empty'};

    const sanitized = sanitizeInput(input);
    if (sanitized !== input) {
        return {valid: false, message: 'Invalid characters detected'};
    }

    if (input.length > maxLength) {
        return {valid: false, message: `Input exceeds maximum length of ${maxLength} characters`};
    }

    if (isHash) {
        const hashRegex = /^[0-9a-fA-F]{0,40}$/;
        if (!hashRegex.test(input)) {
            return {valid: false, message: 'Invalid SHA-1 hash format (hexadecimal only)'};
        }
    } else {
        const htmlRegex = /<[a-z][\s\S]*>/i;
        if (htmlRegex.test(input)) {
            return {valid: false, message: 'HTML tags are not allowed'};
        }
    }

    return {valid: true, message: ''};
}

function showValidationError(inputElement, message) {
    inputElement.classList.add('input-error');
    const errorElement = inputElement.nextElementSibling;
    if (errorElement && errorElement.classList.contains('error-message')) {
        errorElement.textContent = message;
    }
}

function clearValidationError(inputElement) {
    inputElement.classList.remove('input-error');
    const errorElement = inputElement.nextElementSibling;
    if (errorElement && errorElement.classList.contains('error-message')) {
        errorElement.textContent = inputElement.getAttribute('data-error-message') || 'Please enter valid input';
    }
}

// Add validation listeners to all inputs
document.querySelectorAll('input[type="text"]').forEach(input => {
    input.addEventListener('input', () => {
        const isHashInput = input.id === 'sha1-verify-inputHash';
        const maxLength = parseInt(input.getAttribute('maxlength'));
        const validation = validateInput(input.value, maxLength, isHashInput);

        if (validation.valid) {
            clearValidationError(input);
        } else {
            showValidationError(input, validation.message);
        }
    });
});

// Algorithm switching
function openAlgorithm(algorithm) {
    document.getElementById('cbc-panel').style.display = 'none';
    document.getElementById('rsa-panel').style.display = 'none';
    document.getElementById('rsa-generator-panel').style.display = 'none';
    document.getElementById('sha1-panel').style.display = 'none';

    document.getElementById(algorithm + '-panel').style.display = 'block';

    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => btn.classList.remove('active'));
    event.currentTarget.classList.add('active');
}

// Mode switching within algorithm
function switchMode(algorithm, mode) {
    const modeButtons = document.querySelectorAll(`#${algorithm}-panel .mode-btn`);
    modeButtons.forEach(btn => btn.classList.remove('active'));
    event.currentTarget.classList.add('active');

    const modePanels = document.querySelectorAll(`#${algorithm}-panel .tab-content`);
    modePanels.forEach(panel => panel.classList.remove('active'));

    document.getElementById(`${algorithm}-${mode}-panel`).classList.add('active');
}

// Animation on load
document.addEventListener('DOMContentLoaded', function () {
    const cards = document.querySelectorAll('.algorithm-card');
    cards.forEach((card, index) => {
        setTimeout(() => {
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, 100 * index);
    });
});

// AJAX functions with validation
function encryptCBC() {
    const inputElement = document.getElementById('cbc-inputText');
    const inputText = inputElement.value;
    const button = event.currentTarget;

    const validation = validateInput(inputText, 500);
    if (!validation.valid) {
        showValidationError(inputElement, validation.message);
        return;
    }

    button.classList.add('loading');
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Encrypting...';

    fetch('/encrypt/cbc', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({inputText: sanitizeInput(inputText)})
    })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            document.getElementById('cbc-key').textContent = data.cbcKey;
            document.getElementById('cbc-encrypt-output').textContent = data.cbcEncryptedText;
            document.getElementById('cbc-inputKey').value = data.cbcKey;
            addCopyButton('cbc-encrypt-output');
            clearValidationError(inputElement);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('cbc-encrypt-output').textContent = 'Error: ' + error.message;
        })
        .finally(() => {
            button.classList.remove('loading');
            button.innerHTML = '<i class="fas fa-lock"></i> Encrypt with CBC';
        });
}

function decryptCBC() {
    const cipherElement = document.getElementById('cbc-inputCipher');
    const keyElement = document.getElementById('cbc-inputKey');
    const inputCipher = cipherElement.value;
    const key = keyElement.value;
    const button = event.currentTarget;

    const cipherValidation = validateInput(inputCipher, 1000);
    const keyValidation = validateInput(key, 100);

    if (!cipherValidation.valid) {
        showValidationError(cipherElement, cipherValidation.message);
        return;
    }
    if (!keyValidation.valid) {
        showValidationError(keyElement, keyValidation.message);
        return;
    }

    button.classList.add('loading');
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Decrypting...';

    fetch('/decrypt/cbc', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            inputCipher: sanitizeInput(inputCipher),
            key: sanitizeInput(key)
        })
    })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            document.getElementById('cbc-decrypt-output').textContent = data.cbcDecryptedText;
            addCopyButton('cbc-decrypt-output');
            clearValidationError(cipherElement);
            clearValidationError(keyElement);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('cbc-decrypt-output').textContent = 'Error: ' + error.message;
        })
        .finally(() => {
            button.classList.remove('loading');
            button.innerHTML = '<i class="fas fa-unlock"></i> Decrypt with CBC';
        });
}

function encryptRSA() {
    const inputElement = document.getElementById('rsa-inputText');
    const inputText = inputElement.value;
    const button = event.currentTarget;

    const validation = validateInput(inputText, 500);
    if (!validation.valid) {
        showValidationError(inputElement, validation.message);
        return;
    }

    button.classList.add('loading');
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Encrypting...';

    fetch('/encrypt/rsa', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({inputText: sanitizeInput(inputText)})
    })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            document.getElementById('rsa-public-key').textContent = data.rsaPublicKey;
            document.getElementById('rsa-private-key').textContent = data.rsaPrivateKey;
            document.getElementById('rsa-encrypt-output').textContent = data.rsaEncryptedText;
            document.getElementById('rsa-inputPrivateKey').value = data.rsaPrivateKey;
            // addCopyButton('rsa-public-key');
            addCopyButton('rsa-private-key');
            addCopyButton('rsa-encrypt-output');
            clearValidationError(inputElement);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('rsa-encrypt-output').textContent = 'Error: ' + error.message;
        })
        .finally(() => {
            button.classList.remove('loading');
            button.innerHTML = '<i class="fas fa-user-lock"></i> Encrypt with RSA';
        });
}

function decryptRSA() {
    const cipherElement = document.getElementById('rsa-inputCipher');
    const keyElement = document.getElementById('rsa-inputPrivateKey');
    const inputCipher = cipherElement.value;
    const privateKey = keyElement.value;
    const button = event.currentTarget;

    const cipherValidation = validateInput(inputCipher, 1000);
    const keyValidation = validateInput(privateKey, 1000);

    if (!cipherValidation.valid) {
        showValidationError(cipherElement, cipherValidation.message);
        return;
    }
    if (!keyValidation.valid) {
        showValidationError(keyElement, keyValidation.message);
        return;
    }

    button.classList.add('loading');
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Decrypting...';

    fetch('/decrypt/rsa', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            inputCipher: sanitizeInput(inputCipher),
            privateKey: sanitizeInput(privateKey)
        })
    })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            document.getElementById('rsa-decrypt-output').textContent = data.rsaDecryptedText;
            addCopyButton('rsa-decrypt-output');
            clearValidationError(cipherElement);
            clearValidationError(keyElement);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('rsa-decrypt-output').textContent = 'Error: ' + error.message;
        })
        .finally(() => {
            button.classList.remove('loading');
            button.innerHTML = '<i class="fas fa-user-unlock"></i> Decrypt with RSA';
        });
}

function encryptRSAGenerator() {
    const inputElement = document.getElementById('rsa-generator-inputText');
    const inputText = inputElement.value;
    const button = event.currentTarget;

    const validation = validateInput(inputText, 500);
    if (!validation.valid) {
        showValidationError(inputElement, validation.message);
        return;
    }

    button.classList.add('loading');
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Encrypting...';

    fetch('/encrypt/rsa-generator', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({inputText: sanitizeInput(inputText)})
    })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            document.getElementById('rsa-generator-public-key').textContent = data.rsaPublicKey;
            document.getElementById('rsa-generator-private-key').textContent = data.rsaPrivateKey;
            document.getElementById('rsa-generator-encrypt-output').textContent = data.rsaEncryptedText;
            document.getElementById('rsa-generator-inputPrivateKey').value = data.rsaPrivateKey;
            // addCopyButton('rsa-generator-public-key');
            addCopyButton('rsa-generator-private-key');
            addCopyButton('rsa-generator-encrypt-output');
            clearValidationError(inputElement);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('rsa-generator-encrypt-output').textContent = 'Error: ' + error.message;
        })
        .finally(() => {
            button.classList.remove('loading');
            button.innerHTML = '<i class="fas fa-user-lock"></i> Encrypt with RSA';
        });
}

function decryptRSAGenerator() {
    const cipherElement = document.getElementById('rsa-generator-inputCipher');
    const keyElement = document.getElementById('rsa-generator-inputPrivateKey');
    const inputCipher = cipherElement.value;
    const privateKey = keyElement.value;
    const button = event.currentTarget;

    const cipherValidation = validateInput(inputCipher, 1000);
    const keyValidation = validateInput(privateKey, 1000);

    if (!cipherValidation.valid) {
        showValidationError(cipherElement, cipherValidation.message);
        return;
    }
    if (!keyValidation.valid) {
        showValidationError(keyElement, keyValidation.message);
        return;
    }

    button.classList.add('loading');
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Decrypting...';

    fetch('/decrypt/rsa-generator', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            inputCipher: sanitizeInput(inputCipher),
            privateKey: sanitizeInput(privateKey)
        })
    })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            document.getElementById('rsa-generator-decrypt-output').textContent = data.rsaDecryptedText;
            addCopyButton('rsa-generator-decrypt-output');
            clearValidationError(cipherElement);
            clearValidationError(keyElement);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('rsa-generator-decrypt-output').textContent = 'Error: ' + error.message;
        })
        .finally(() => {
            button.classList.remove('loading');
            button.innerHTML = '<i class="fas fa-user-unlock"></i> Decrypt with RSA';
        });
}

function hashSHA1() {
    const inputElement = document.getElementById('sha1-inputText');
    const inputText = inputElement.value;
    const button = event.currentTarget;

    const validation = validateInput(inputText, 500);
    if (!validation.valid) {
        showValidationError(inputElement, validation.message);
        return;
    }

    button.classList.add('loading');
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Hashing...';

    fetch('/encrypt/sha1', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({inputText: sanitizeInput(inputText)})
    })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            document.getElementById('sha1-hash-output').textContent = data.sha1HashedText;
            document.getElementById('sha1-verify-inputText').value = inputText;
            document.getElementById('sha1-verify-inputHash').value = data.sha1HashedText;
            addCopyButton('sha1-hash-output');
            clearValidationError(inputElement);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('sha1-hash-output').textContent = 'Error: ' + error.message;
        })
        .finally(() => {
            button.classList.remove('loading');
            button.innerHTML = '<i class="fas fa-hashtag"></i> Generate SHA-1 Hash';
        });
}

function verifySHA1() {
    const textElement = document.getElementById('sha1-verify-inputText');
    const hashElement = document.getElementById('sha1-verify-inputHash');
    const inputText = textElement.value;
    const inputHash = hashElement.value;
    const button = event.currentTarget;

    const textValidation = validateInput(inputText, 500);
    const hashValidation = validateInput(inputHash, 40, true);

    if (!textValidation.valid) {
        showValidationError(textElement, textValidation.message);
        return;
    }
    if (!hashValidation.valid) {
        showValidationError(hashElement, hashValidation.message);
        return;
    }

    button.classList.add('loading');
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verifying...';

    fetch('/verify/sha1', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            inputText: sanitizeInput(inputText),
            inputHash: sanitizeInput(inputHash)
        })
    })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            const outputElement = document.getElementById('sha1-verify-output');
            if (data.isValid) {
                outputElement.innerHTML = '<span class="verification-success"><i class="fas fa-check-circle"></i> Hash verification successful! The text matches the hash.</span>';
            } else {
                outputElement.innerHTML = '<span class="verification-failure"><i class="fas fa-times-circle"></i> Hash verification failed! The text does not match the hash.</span>';
            }
            clearValidationError(textElement);
            clearValidationError(hashElement);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('sha1-verify-output').innerHTML = '<span style="color: red;">Error: ' + error.message + '</span>';
        })
        .finally(() => {
            button.classList.remove('loading');
            button.innerHTML = '<i class="fas fa-check-circle"></i> Verify Hash';
        });
}

function addCopyButton(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const existingBtn = element.querySelector('.copy-btn');
    if (existingBtn) existingBtn.remove();

    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.innerHTML = '<i class="far fa-copy"></i>';
    copyBtn.title = 'Copy to clipboard';
    copyBtn.onclick = () => {
        const text = element.textContent || element.innerText;
        navigator.clipboard.writeText(text.trim()).then(() => {
            copyBtn.innerHTML = '<i class="fas fa-check"></i>';
            setTimeout(() => {
                copyBtn.innerHTML = '<i class="far fa-copy"></i>';
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            copyBtn.innerHTML = '<i class="fas fa-times"></i>';
            setTimeout(() => {
                copyBtn.innerHTML = '<i class="far fa-copy"></i>';
            }, 2000);
        });
    };

    if (element.textContent.trim() !== '') {
        element.appendChild(copyBtn);
    }
}