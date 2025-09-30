// SESSION 3: UI Interaction Handlers
// Fix based on Security Auditor finding #20250928_1015 - Externalize embedded script for CSP compliance
// Fix based on Visual Integrity Enforcer finding #20250928_1015 - Preserve showNotification visual behavior

function setupEventListeners() {
    console.log('Setting up event listeners...');
    const form = document.getElementById('descriptionForm');
    if (form) {
        console.log('Form found, adding submit listener');
        form.addEventListener('submit', handleFormSubmission);
    } else {
        console.error('Form not found!');
    }

    const copyBtn = document.getElementById('copyBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', handleCopyToClipboard);
    }

    // Input method toggle buttons
    const urlModeBtn = document.getElementById('urlModeBtn');
    const barcodeModeBtn = document.getElementById('barcodeModeBtn');
    const manualModeBtn = document.getElementById('manualModeBtn');

    if (urlModeBtn) {
        urlModeBtn.addEventListener('click', () => switchInputMode('url'));
    }

    if (barcodeModeBtn) {
        barcodeModeBtn.addEventListener('click', () => switchInputMode('barcode'));
    }

    if (manualModeBtn) {
        manualModeBtn.addEventListener('click', () => switchInputMode('manual'));
    }

    // Barcode lookup button
    const lookupBarcodeBtn = document.getElementById('lookupBarcodeBtn');
    if (lookupBarcodeBtn) {
        lookupBarcodeBtn.addEventListener('click', handleBarcodeLookup);
    }
}

function handleFormSubmission(event) {
    console.log('Form submitted!');
    event.preventDefault();
    generateDescription();
}

function handleCopyToClipboard() {
    const text = document.getElementById('resultsContent').textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function() {
            showNotification('Description copied to clipboard!', 'success');
        }).catch(function(error) {
            console.error('Copy failed:', error);
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    try {
        document.execCommand('copy');
        showNotification('Description copied to clipboard!', 'success');
    } catch (error) {
        console.error('Fallback copy failed:', error);
        showNotification('Unable to copy text. Please copy manually.', 'error');
    }
    document.body.removeChild(textArea);
}

// CRITICAL VISUAL FUNCTION: Preserve notification styling and transitions
function showNotification(message, type = 'success') {
    // Remove existing notification if any
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }

    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);

    // Show notification
    setTimeout(() => notification.classList.add('show'), 100);

    // Hide notification after 4 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 300);
    }, 4000);
}

// CRITICAL VISUAL FUNCTION: Preserve input mode button states
function switchInputMode(mode) {
    console.log('Switching input mode to:', mode);
    inputMode = mode;
    currentProductInfo = null;

    // Update button states
    const urlModeBtn = document.getElementById('urlModeBtn');
    const barcodeModeBtn = document.getElementById('barcodeModeBtn');
    const manualModeBtn = document.getElementById('manualModeBtn');
    const urlInputGroup = document.getElementById('urlInputGroup');
    const barcodeInputGroup = document.getElementById('barcodeInputGroup');
    const manualInputGroup = document.getElementById('manualInputGroup');
    const productPreview = document.getElementById('productPreview');

    // Remove all active states first
    urlModeBtn.classList.remove('active');
    barcodeModeBtn.classList.remove('active');
    manualModeBtn.classList.remove('active');
    urlInputGroup.classList.remove('active');
    barcodeInputGroup.classList.remove('active');
    manualInputGroup.classList.remove('active');

    // Set active state based on mode
    if (mode === 'url') {
        urlModeBtn.classList.add('active');
        urlInputGroup.classList.add('active');
    } else if (mode === 'barcode') {
        barcodeModeBtn.classList.add('active');
        barcodeInputGroup.classList.add('active');
    } else if (mode === 'manual') {
        manualModeBtn.classList.add('active');
        manualInputGroup.classList.add('active');
    }

    productPreview.style.display = 'none';
    clearErrors();
}

async function handleBarcodeLookup() {
    const barcodeInput = document.getElementById('productBarcode');
    const barcode = barcodeInput.value.trim();

    if (!barcode) {
        showError('barcodeError', 'Please enter a barcode');
        return;
    }

    // Validate barcode format
    if (!/^\d{8,13}$/.test(barcode.replace(/[\s-]/g, ''))) {
        showError('barcodeError', 'Please enter a valid 8-13 digit barcode');
        return;
    }

    const lookupBtn = document.getElementById('lookupBarcodeBtn');
    lookupBtn.disabled = true;
    lookupBtn.textContent = '🔍 Looking up...';

    try {
        const response = await fetch('/.netlify/functions/barcode-lookup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ barcode })
        });

        const data = await response.json();

        if (data.success && data.product) {
            currentProductInfo = data.product;
            showProductPreview(data.product);
            showNotification('Product found! Ready to generate description.', 'success');
        } else {
            showError('barcodeError', 'Product not found in barcode databases');
            showNotification('Product not found. You can still generate a description by filling in the details manually.', 'error');
        }
    } catch (error) {
        console.error('Barcode lookup error:', error);
        showError('barcodeError', 'Failed to lookup barcode. Please try again.');
        showNotification('Lookup failed. Please try again.', 'error');
    } finally {
        lookupBtn.disabled = false;
        lookupBtn.textContent = '🔍 Lookup Product';
    }
}

// CRITICAL VISUAL FUNCTION: Preserve product preview display states
function showProductPreview(product) {
    const productPreview = document.getElementById('productPreview');
    const previewImage = document.getElementById('previewImage');
    const previewName = document.getElementById('previewName');
    const previewBrand = document.getElementById('previewBrand');
    const previewCategory = document.getElementById('previewCategory');

    previewName.textContent = product.name || 'Unknown Product';
    previewBrand.textContent = product.brand || 'Unknown Brand';
    previewCategory.textContent = product.category || 'General Product';

    if (product.imageUrl) {
        previewImage.src = product.imageUrl;
        previewImage.style.display = 'block';
    } else {
        previewImage.style.display = 'none';
    }

    productPreview.style.display = 'block';
}

function showError(errorId, message) {
    let field = null;
    let errorDiv = null;

    if (errorId === 'urlError') {
        field = document.getElementById('productUrl');
        errorDiv = document.getElementById('urlError');
    } else if (errorId === 'barcodeError') {
        field = document.getElementById('productBarcode');
        errorDiv = document.getElementById('barcodeError');
    } else if (errorId === 'brandToneError') {
        field = document.getElementById('brandTone');
        errorDiv = document.getElementById('brandToneError');
    }

    if (field) {
        field.classList.add('error');
    }

    if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
    } else {
        // Fallback for missing error divs
        console.error(`Error div not found for ${errorId}: ${message}`);
        showNotification(message, 'error');
    }
}

// CRITICAL VISUAL FUNCTION: Preserve error state clearing
function clearErrors() {
    const errorElements = document.querySelectorAll('.error');
    errorElements.forEach(element => {
        if (element.tagName === 'DIV') {
            element.textContent = '';
            element.style.display = 'none';
        } else {
            element.classList.remove('error');
        }
    });

    // Clear specific error divs
    const errorIds = ['urlError', 'barcodeError', 'brandToneError'];
    errorIds.forEach(errorId => {
        const errorDiv = document.getElementById(errorId);
        if (errorDiv) {
            errorDiv.textContent = '';
            errorDiv.style.display = 'none';
        }
    });
}