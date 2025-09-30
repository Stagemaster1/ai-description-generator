/**
 * PLYVO RECOVERY - Session 3: JavaScript Modularization
 *
 * 🧱 CODEBASE ARCHITECT - API Communication Module
 *
 * ARCHITECTURAL CHANGE: JavaScript Externalization - API Layer
 * - Extracted from embedded script block (lines 1664-1928)
 * - Implements API communication with CSP compliance
 * - Manages description generation, usage tracking, and data sync
 *
 * AUDIT TRAIL:
 * - Change Type: API communication modularization
 * - Source: index.html embedded script (API functions)
 * - Rationale: CSP compliance and API abstraction
 * - Reversible: Yes, can re-embed in main script
 * - Containment: Preserved within js/ directory structure
 *
 * Date: 2025-09-28
 * Session: 3
 * Architect: Codebase Architect under Copilot supervision
 */

// API Client Manager
class APIClient {
    constructor() {
        this.baseURL = '';
        this.defaultHeaders = {
            'Content-Type': 'application/json'
        };
    }

    // Main description generation function
    async generateDescription() {
        // Get current state
        const inputMode = window.appState ? window.appState.getInputMode() : window.inputMode;
        const userState = window.appState ? window.appState.getUser() : window.userState;
        const currentProductInfo = window.appState ? window.appState.getProductInfo() : window.currentProductInfo;

        // Get form values
        const productUrl = inputMode === 'url' ? document.getElementById('productUrl')?.value.trim() : null;
        const productBarcode = inputMode === 'barcode' ? document.getElementById('productBarcode')?.value.trim() : null;
        const productName = inputMode === 'manual' ? document.getElementById('productName')?.value.trim() : null;
        const brandTone = document.getElementById('brandTone')?.value;
        const descriptionLength = document.getElementById('descriptionLength')?.value;
        const language = document.getElementById('language')?.value;
        const targetAudience = document.getElementById('targetAudience')?.value.trim();
        const keyFeatures = document.getElementById('keyFeatures')?.value.trim();

        // Clear previous errors
        if (typeof window.clearErrors === 'function') {
            window.clearErrors();
        }

        // Validation
        if (!this.validateInputs(productUrl, productBarcode, brandTone, inputMode)) {
            return;
        }

        // Show loading state
        const generateBtn = document.getElementById('generateBtn');
        const results = document.getElementById('results');
        const resultsContent = document.getElementById('resultsContent');

        if (generateBtn) {
            generateBtn.classList.add('loading');
            generateBtn.textContent = 'Generating...';
            generateBtn.disabled = true;
        }

        if (results) {
            results.style.display = 'none';
        }

        try {
            // Prepare request body based on input mode
            const requestBody = {
                brandTone,
                descriptionLength,
                language,
                targetAudience,
                keyFeatures,
                userId: userState?.userId,
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

            // Make authenticated request
            const response = await this.makeAuthenticatedRequest('/.netlify/functions/generate', {
                method: 'POST',
                body: JSON.stringify(requestBody)
            });

            const data = await response.json();

            if (data.success && data.description) {
                // Update usage count on backend and sync locally
                await this.updateUsageCount();
                await this.syncUserData();

                // Show results
                if (resultsContent) {
                    resultsContent.textContent = data.description;
                }

                if (results) {
                    results.style.display = 'block';
                    results.classList.add('success-animation');

                    // Scroll to results
                    results.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }

                if (typeof window.showNotification === 'function') {
                    window.showNotification('Description generated successfully!', 'success');
                }
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

                if (typeof window.showUsageLimitDialog === 'function') {
                    window.showUsageLimitDialog(errorMessage);
                }
            } else {
                if (typeof window.showError === 'function') {
                    window.showError('productUrl', 'Failed to generate description. Please try again.');
                }
                if (typeof window.showNotification === 'function') {
                    window.showNotification('Generation failed. Please try again.', 'error');
                }
            }
        } finally {
            // Reset button
            if (generateBtn) {
                generateBtn.classList.remove('loading');
                generateBtn.textContent = 'Generate AI Description';
                generateBtn.disabled = false;
            }
        }
    }

    // Validate inputs based on mode
    validateInputs(productUrl, productBarcode, brandTone, inputMode) {
        let isValid = true;

        // Clear previous errors first
        if (typeof window.clearErrors === 'function') {
            window.clearErrors();
        }

        // Validate based on input mode
        if (inputMode === 'url') {
            if (!productUrl || productUrl.trim() === '') {
                if (typeof window.showError === 'function') {
                    window.showError('urlError', 'Please enter a product URL');
                }
                isValid = false;
            } else {
                try {
                    const url = new URL(productUrl.trim());
                    if (!url.hostname || (!url.hostname.includes('.') && url.hostname !== 'localhost')) {
                        if (typeof window.showError === 'function') {
                            window.showError('urlError', 'Please enter a valid URL (include http:// or https://)');
                        }
                        isValid = false;
                    }
                } catch (error) {
                    if (typeof window.showError === 'function') {
                        window.showError('urlError', 'Please enter a valid URL (include http:// or https://)');
                    }
                    isValid = false;
                }
            }
        } else if (inputMode === 'barcode') {
            if (!productBarcode || productBarcode.trim() === '') {
                if (typeof window.showError === 'function') {
                    window.showError('barcodeError', 'Please enter a barcode or look up a product');
                }
                isValid = false;
            }
        } else if (inputMode === 'manual') {
            const productName = document.getElementById('productName')?.value.trim();
            if (!productName) {
                if (typeof window.showError === 'function') {
                    window.showError('nameError', 'Please enter a product name');
                }
                isValid = false;
            }
        }

        // Validate brand tone
        if (!brandTone || brandTone === '') {
            if (typeof window.showError === 'function') {
                window.showError('brandToneError', 'Please select a brand tone');
            }
            isValid = false;
        }

        return isValid;
    }

    // Update usage count
    async updateUsageCount() {
        try {
            const userState = window.appState ? window.appState.getUser() : window.userState;

            if (!userState?.userId || !userState?.isAuthenticated) {
                return; // User not authenticated
            }

            const response = await this.makeAuthenticatedRequest('/.netlify/functions/firebase-user', {
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

                    // Update app state with new usage data
                    if (window.appState && data.user.usage) {
                        window.appState.updateUsage(data.user.usage);
                    }
                }
            }
        } catch (error) {
            console.log('Usage update skipped:', error.message);
        }
    }

    // Sync user data from server
    async syncUserData() {
        try {
            const userState = window.appState ? window.appState.getUser() : window.userState;

            if (!userState?.userId || !userState?.isAuthenticated) {
                return; // User not authenticated
            }

            const response = await this.makeAuthenticatedRequest('/.netlify/functions/firebase-user', {
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

                    // Update app state with server data
                    if (window.appState) {
                        window.appState.setUser({
                            ...window.appState.getUser(),
                            ...data.user
                        });
                    }
                }
            }
        } catch (error) {
            console.log('Sync skipped:', error.message);
            // Don't show error to user - sync is optional
        }
    }

    // Refresh usage data manually
    async refreshUsage() {
        await this.syncUserData();
        if (typeof window.showNotification === 'function') {
            const message = window.t ? window.t('usageDataRefreshed') : 'Usage data refreshed';
            window.showNotification(message, 'success');
        }
    }

    // Barcode lookup API call
    async lookupBarcode(barcode) {
        try {
            const response = await fetch('/.netlify/functions/barcode-lookup', {
                method: 'POST',
                headers: this.defaultHeaders,
                body: JSON.stringify({ barcode })
            });

            return await response.json();
        } catch (error) {
            console.error('Barcode lookup error:', error);
            throw error;
        }
    }

    // Make authenticated request using available auth managers
    async makeAuthenticatedRequest(url, options = {}) {
        try {
            // Try Firebase auth manager first
            if (window.firebaseAuthManager && typeof window.firebaseAuthManager.makeAuthenticatedRequest === 'function') {
                return await window.firebaseAuthManager.makeAuthenticatedRequest(url, options);
            }

            // Fallback to token manager
            if (window.tokenManager && typeof window.tokenManager.makeAuthenticatedRequest === 'function') {
                return await window.tokenManager.makeAuthenticatedRequest(url, options);
            }

            // Basic fallback with default headers
            const headers = {
                ...this.defaultHeaders,
                ...options.headers
            };

            return await fetch(url, {
                ...options,
                headers
            });
        } catch (error) {
            console.error('Authenticated request failed:', error);
            throw error;
        }
    }

    // Generic API request method
    async apiRequest(endpoint, options = {}) {
        try {
            const url = this.baseURL + endpoint;
            const headers = {
                ...this.defaultHeaders,
                ...options.headers
            };

            const response = await fetch(url, {
                ...options,
                headers
            });

            if (!response.ok) {
                throw new Error(`API request failed: ${response.status} ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request error:', error);
            throw error;
        }
    }

    // Sync user to server (from auth module)
    async syncUserToServer(userData) {
        try {
            const response = await fetch('/.netlify/functions/admin', {
                method: 'POST',
                headers: this.defaultHeaders,
                body: JSON.stringify({
                    action: 'sync_user',
                    password: 'demo123', // TODO: Improve security in production
                    userId: userData.userId || this.generateUserIdFromData(userData),
                    userData: {
                        email: userData.email || 'user@unknown.com',
                        monthlyUsage: userData.monthlyUsage || 0,
                        maxUsage: userData.maxUsage,
                        lastActive: new Date().toISOString(),
                        syncedFromClient: true
                    }
                })
            });

            if (!response.ok) {
                throw new Error(`Server sync failed: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Failed to sync user to server:', error);
            throw error;
        }
    }

    // Generate user ID (fallback)
    generateUserIdFromData(userData) {
        // Use Firebase UID if available
        if (window.firebaseAuthManager) {
            const currentUser = window.firebaseAuthManager.getCurrentUser();
            if (currentUser) {
                return currentUser.uid;
            }
        }

        // Fallback for cases where Firebase is not ready
        console.warn('Firebase user not available, using anonymous ID');
        return `anonymous_${Date.now()}`;
    }

    // Update usage display (compatibility function)
    updateUsageDisplay() {
        // Usage display is now managed server-side
        // This function is kept for compatibility but does nothing
        console.log('Usage display update called (server-managed)');
    }
}

// Create global API client instance
const apiClient = new APIClient();

// Legacy function compatibility
async function generateDescription() {
    return apiClient.generateDescription();
}

function validateInputs(productUrl, productBarcode, brandTone) {
    const inputMode = window.appState ? window.appState.getInputMode() : window.inputMode;
    return apiClient.validateInputs(productUrl, productBarcode, brandTone, inputMode);
}

async function updateUsageCount() {
    return apiClient.updateUsageCount();
}

async function syncUserData() {
    return apiClient.syncUserData();
}

async function refreshUsage() {
    return apiClient.refreshUsage();
}

function updateUsageDisplay() {
    return apiClient.updateUsageDisplay();
}

async function syncUserToServer(userData) {
    return apiClient.syncUserToServer(userData);
}

function generateUserIdFromData(userData) {
    return apiClient.generateUserIdFromData(userData);
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        APIClient,
        apiClient,
        generateDescription,
        validateInputs,
        updateUsageCount,
        syncUserData,
        refreshUsage,
        updateUsageDisplay,
        syncUserToServer,
        generateUserIdFromData
    };
}

// Export for browser usage
if (typeof window !== 'undefined') {
    window.APIClient = APIClient;
    window.apiClient = apiClient;
    window.generateDescription = generateDescription;
    window.validateInputs = validateInputs;
    window.updateUsageCount = updateUsageCount;
    window.syncUserData = syncUserData;
    window.refreshUsage = refreshUsage;
    window.updateUsageDisplay = updateUsageDisplay;
    window.syncUserToServer = syncUserToServer;
    window.generateUserIdFromData = generateUserIdFromData;
}