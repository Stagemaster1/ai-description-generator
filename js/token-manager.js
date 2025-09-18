// Centralized Firebase Token Management - Extracted for CSP Compliance
// SECURITY ENHANCEMENT: Centralized Firebase token management

class FirebaseTokenManager {
    constructor() {
        this.currentToken = null;
        this.tokenRefreshPromise = null;
        this.retryCount = 0;
        this.maxRetries = 3;
        this.retryDelay = 1000; // 1 second
    }

    // Get current Firebase ID token with automatic refresh
    async getToken(forceRefresh = false) {
        try {
            const auth = window.firebaseAuth;
            const user = auth?.currentUser;

            if (!user) {
                throw new Error('User not authenticated');
            }

            // Use cached token if available and not forcing refresh
            if (!forceRefresh && this.currentToken) {
                // Check if token is still valid (not expired)
                const tokenData = this.parseJWT(this.currentToken);
                if (tokenData && tokenData.exp > Date.now() / 1000) {
                    return this.currentToken;
                }
            }

            // Get fresh token from Firebase
            const token = await user.getIdToken(forceRefresh);
            this.currentToken = token;
            this.retryCount = 0; // Reset retry count on success
            return token;

        } catch (error) {
            console.error('Token retrieval failed:', error);

            // Implement retry logic for token failures
            if (this.retryCount < this.maxRetries) {
                this.retryCount++;
                console.log(`Retrying token fetch (${this.retryCount}/${this.maxRetries})...`);
                await this.delay(this.retryDelay * this.retryCount);
                return this.getToken(true); // Force refresh on retry
            }

            throw new Error('Failed to obtain authentication token after retries');
        }
    }

    // Parse JWT token to check expiration
    parseJWT(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            return JSON.parse(jsonPayload);
        } catch (error) {
            console.warn('Failed to parse JWT token:', error);
            return null;
        }
    }

    // Clear cached token
    clearToken() {
        this.currentToken = null;
        this.retryCount = 0;
    }

    // Utility delay function
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize global token manager instance
window.tokenManager = new FirebaseTokenManager();

// Enhanced API call wrapper with automatic token handling and retry logic
async function makeAuthenticatedRequest(url, options = {}) {
    const maxRetries = 2;
    let attempt = 0;

    while (attempt <= maxRetries) {
        try {
            // Get current token
            const token = await window.tokenManager.getToken(attempt > 0); // Force refresh on retries

            // Prepare headers
            const headers = {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                ...options.headers
            };

            // Make the request
            const response = await fetch(url, {
                ...options,
                headers
            });

            // Handle authentication errors with specific handling
            if (response.status === 401 && attempt < maxRetries) {
                const errorData = await response.json().catch(() => ({}));
                const errorCode = errorData.code;

                console.log(`Authentication error (${errorCode}), refreshing and retrying...`);

                // Clear token and force refresh based on error type
                window.tokenManager.clearToken();

                // For revoked tokens, we need to re-authenticate
                if (errorCode === 'TOKEN_REVOKED') {
                    console.warn('Token revoked, may need to re-authenticate');
                    // Force Firebase to re-authenticate
                    const auth = window.firebaseAuth;
                    if (auth && auth.currentUser) {
                        try {
                            await auth.currentUser.reload();
                        } catch (reloadError) {
                            console.error('Failed to reload user:', reloadError);
                        }
                    }
                }

                attempt++;
                continue;
            }

            return response;

        } catch (error) {
            if (attempt >= maxRetries) {
                throw error;
            }
            attempt++;
            console.warn(`Request attempt ${attempt} failed, retrying...`, error);
        }
    }
}

// Make authenticated request function globally available
window.makeAuthenticatedRequest = makeAuthenticatedRequest;