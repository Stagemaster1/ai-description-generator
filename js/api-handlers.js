// SESSION 3: API and Form Handling
// Fix based on Security Auditor finding #20250928_1015 - Externalize embedded script for CSP compliance
// Fix based on Visual Integrity Enforcer finding #20250928_1015 - Preserve form interaction behavior

async function generateDescription() {
    // Get form values
    const productUrl = inputMode === 'url' ? document.getElementById('productUrl').value.trim() : null;
    const productBarcode = inputMode === 'barcode' ? document.getElementById('productBarcode').value.trim() : null;
    const productName = inputMode === 'manual' ? document.getElementById('productName').value.trim() : null;
    const brandTone = document.getElementById('brandTone').value;
    const descriptionLength = document.getElementById('descriptionLength').value;
    const language = document.getElementById('language').value;
    const targetAudience = document.getElementById('targetAudience').value.trim();
    const keyFeatures = document.getElementById('keyFeatures').value.trim();

    // Clear previous errors
    clearErrors();

    // Validation
    if (!validateInputs(productUrl, productBarcode, brandTone)) {
        return;
    }

    // Show loading state
    const generateBtn = document.getElementById('generateBtn');
    const results = document.getElementById('results');
    const resultsContent = document.getElementById('resultsContent');

    generateBtn.classList.add('loading');
    generateBtn.textContent = 'Generating...';
    generateBtn.disabled = true;
    results.style.display = 'none';

    try {
        // Prepare request body based on input mode
        const requestBody = {
            brandTone,
            descriptionLength,
            language,
            targetAudience,
            keyFeatures,
            userId: userState.userId,
            inputMode
        };

        if (inputMode === 'url') {
            requestBody.productUrl = productUrl;
        } else if (inputMode === 'barcode') {
            requestBody.productInfo = currentProductInfo;
        } else if (inputMode === 'manual') {
            // Create a manual product info object
            requestBody.productInfo = {
                name: productName,
                brand: '',
                category: '',
                platform: 'Manual Entry',
                productType: 'product',
                source: 'Manual Entry'
            };
            requestBody.inputMode = 'barcode'; // Treat as barcode mode on backend
        }

        // SECURITY ENHANCEMENT: Use centralized token manager for API authentication
        const response = await makeAuthenticatedRequest('/.netlify/functions/generate', {
            method: 'POST',
            body: JSON.stringify(requestBody)
        });

        const data = await response.json();

        if (data.success && data.description) {
            // Update usage count on backend and sync locally
            await updateUsageCount();
            await syncUserData();

            // Show results
            resultsContent.textContent = data.description;
            results.style.display = 'block';
            results.classList.add('success-animation');

            // Scroll to results
            results.scrollIntoView({ behavior: 'smooth', block: 'center' });

            showNotification('Description generated successfully!', 'success');
        } else {
            throw new Error(data.error || 'Failed to generate description');
        }

    } catch (error) {
        console.error('Error generating description:', error);

        // Check if it's a usage limit error and provide subscription guidance
        const errorMessage = error.message;
        if (errorMessage.includes('Usage limit exceeded') ||
            errorMessage.includes('limit reached') ||
            errorMessage.includes('upgrade') ||
            errorMessage.includes('subscription')) {

            showUsageLimitDialog(errorMessage);
        } else {
            showError('productUrl', 'Failed to generate description. Please try again.');
            showNotification('Generation failed. Please try again.', 'error');
        }
    } finally {
        // Reset button
        generateBtn.classList.remove('loading');
        generateBtn.textContent = 'Generate AI Description';
        generateBtn.disabled = false;
    }
}

function validateInputs(productUrl, productBarcode, brandTone) {
    let isValid = true;

    // Clear previous errors first
    clearErrors();

    // Validate based on input mode
    if (inputMode === 'url') {
        if (!productUrl || productUrl.trim() === '') {
            showError('urlError', 'Please enter a product URL');
            isValid = false;
        } else {
            try {
                const url = new URL(productUrl.trim());
                // Additional URL validation
                if (!['http:', 'https:'].includes(url.protocol)) {
                    throw new Error('Invalid protocol');
                }
            } catch (error) {
                showError('urlError', 'Please enter a valid URL');
                isValid = false;
            }
        }
    } else if (inputMode === 'barcode') {
        // Barcode mode validation
        if (!currentProductInfo) {
            showError('barcodeError', 'Please lookup a product first');
            isValid = false;
        }
    } else if (inputMode === 'manual') {
        // Manual mode validation
        const productName = document.getElementById('productName').value.trim();
        if (!productName) {
            showError('manualError', 'Please enter a product name');
            isValid = false;
        }
    }

    // Validate brand tone
    if (!brandTone || brandTone.trim() === '') {
        showError('brandToneError', 'Please select a brand tone');
        isValid = false;
    }

    return isValid;
}

async function updateUsageCount() {
    // Increment usage on backend
    try {
        if (!userState.userId || !userState.isAuthenticated) {
            return; // User not authenticated
        }

        // Use centralized token manager for authentication
        const response = await makeAuthenticatedRequest('/.netlify/functions/firebase-user', {
            method: 'POST',
            body: JSON.stringify({
                action: 'increment_usage',
                userId: userState.userId
            })
        });

        if (response.ok) {
            const data = await response.json();
            if (data.user) {
                console.log('Usage updated on server');
            }
        }
    } catch (error) {
        console.log('Usage update skipped:', error.message);
    }
}

async function syncUserData() {
    // Sync with backend user data
    try {
        if (!userState.userId || !userState.isAuthenticated) {
            return; // User not authenticated
        }

        // Use centralized token manager for authentication
        const response = await makeAuthenticatedRequest('/.netlify/functions/firebase-user', {
            method: 'POST',
            body: JSON.stringify({
                action: 'get_user',
                userId: userState.userId
            })
        });

        if (response.ok) {
            const data = await response.json();
            if (data.user) {
                console.log('User data synced from server');
            }
        }
    } catch (error) {
        console.log('Sync skipped:', error.message);
        // Don't show error to user - sync is optional
    }
}

async function refreshUsage() {
    // Manual sync for users to refresh their usage data
    await syncUserData();
    showNotification('Usage data refreshed', 'success');
}

function updateUsageDisplay() {
    // Usage display is now managed server-side
    // This function is kept for compatibility but does nothing
}