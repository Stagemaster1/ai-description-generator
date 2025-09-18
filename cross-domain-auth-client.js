// Cross-Domain Authentication Client Module
// Handles secure authentication across www.soltecsol.com and ai-generator.soltecsol.com
// SESSION 4B Implementation - Client Side

class CrossDomainAuthManager {
    constructor() {
        this.authEndpoint = '/.netlify/functions/cross-domain-auth';
        this.authenticated = false;
        this.userInfo = null;
        this.csrfToken = null;
        this.retryCount = 0;
        this.maxRetries = 3;
        this.lastAuthTime = null;
        this.authTimeoutThreshold = 60 * 60 * 1000; // 1 hour
    }

    // SECURITY ENHANCEMENT: Validate JWT token format
    isValidJWTFormat(token) {
        try {
            if (!token || typeof token !== 'string') {
                return false;
            }

            // JWT should have exactly 3 parts separated by dots
            const parts = token.split('.');
            if (parts.length !== 3) {
                return false;
            }

            // Each part should be valid base64
            for (const part of parts) {
                if (!/^[A-Za-z0-9_-]+$/.test(part)) {
                    return false;
                }
            }

            // Basic payload validation
            const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

            // Check for required Firebase JWT claims
            if (!payload.iss || !payload.aud || !payload.exp || !payload.iat) {
                return false;
            }

            // Check if token is expired
            if (payload.exp * 1000 < Date.now()) {
                console.warn('Token validation failed: expired');
                return false;
            }

            return true;

        } catch (error) {
            console.error('JWT validation error:', error);
            return false;
        }
    }

    // SECURITY ENHANCEMENT: Check authentication timeout
    isAuthenticationStale() {
        if (!this.lastAuthTime) {
            return true;
        }
        return (Date.now() - this.lastAuthTime) > this.authTimeoutThreshold;
    }

    // Initialize cross-domain authentication
    async initialize() {
        try {
            // Check if user is already authenticated via cookies
            const verified = await this.verifyAuthentication();
            if (verified.authenticated) {
                this.authenticated = true;
                this.userInfo = verified.user;
                this.csrfToken = verified.csrfToken;
                console.log('Cross-domain authentication verified:', this.userInfo);
                return true;
            }
            return false;
        } catch (error) {
            console.error('Cross-domain auth initialization failed:', error);
            return false;
        }
    }

    // SECURITY ENHANCEMENT: Authenticate user with enhanced token validation
    async authenticate(firebaseIdToken) {
        try {
            if (!firebaseIdToken) {
                throw new Error('Firebase ID token required for cross-domain authentication');
            }

            // Validate token format before sending
            if (!this.isValidJWTFormat(firebaseIdToken)) {
                throw new Error('Invalid Firebase token format');
            }

            // Enhanced request with additional security headers
            const response = await fetch(this.authEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-Mode': 'cors',
                    ...(this.csrfToken && { 'X-CSRF-Token': this.csrfToken })
                },
                credentials: 'include', // Important for cross-domain cookies
                body: JSON.stringify({
                    action: 'authenticate',
                    idToken: firebaseIdToken,
                    csrfToken: this.csrfToken,
                    timestamp: Date.now() // Add timestamp for replay attack prevention
                })
            });

            const data = await response.json();

            if (!response.ok) {
                // Handle specific error cases
                if (data.emailVerified === false) {
                    throw new EmailVerificationError(data.message || 'Email verification required');
                }
                
                if (data.code === 'TOKEN_EXPIRED') {
                    throw new TokenExpiredError(data.message || 'Authentication token expired');
                }

                if (data.code === 'TOKEN_REVOKED') {
                    throw new TokenRevokedError(data.message || 'Authentication token revoked');
                }

                throw new Error(data.message || data.error || 'Authentication failed');
            }

            // Store authentication state with timestamp
            this.authenticated = true;
            this.userInfo = data.user;
            this.csrfToken = data.csrfToken;
            this.retryCount = 0;
            this.lastAuthTime = Date.now();

            console.log('Cross-domain authentication successful:', this.userInfo);
            
            // Dispatch authentication success event
            window.dispatchEvent(new CustomEvent('crossDomainAuthSuccess', {
                detail: { user: this.userInfo }
            }));

            return {
                success: true,
                user: this.userInfo,
                csrfToken: this.csrfToken
            };

        } catch (error) {
            console.error('Cross-domain authentication failed:', error);
            
            // Dispatch authentication error event
            window.dispatchEvent(new CustomEvent('crossDomainAuthError', {
                detail: { error: error.message, type: error.constructor.name }
            }));

            throw error;
        }
    }

    // SECURITY ENHANCEMENT: Verify existing authentication with enhanced checks
    async verifyAuthentication() {
        try {
            // Check if authentication is stale before making request
            if (this.authenticated && this.isAuthenticationStale()) {
                console.log('Authentication stale, clearing state');
                this.clearAuthenticationState();
                return { authenticated: false };
            }

            const response = await fetch(this.authEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-Mode': 'cors',
                    ...(this.csrfToken && { 'X-CSRF-Token': this.csrfToken })
                },
                credentials: 'include', // Important for cross-domain cookies
                body: JSON.stringify({
                    action: 'verify',
                    timestamp: Date.now(),
                    ...(this.lastAuthTime && { lastAuthTime: this.lastAuthTime })
                })
            });

            const data = await response.json();

            if (response.ok && data.authenticated) {
                // Update authentication timestamp
                this.lastAuthTime = Date.now();

                return {
                    authenticated: true,
                    user: data.user,
                    csrfToken: data.csrfToken
                };
            }

            // Clear stale authentication state
            this.clearAuthenticationState();
            return { authenticated: false };

        } catch (error) {
            console.error('Authentication verification failed:', error);
            this.clearAuthenticationState();
            return { authenticated: false };
        }
    }

    // SECURITY ENHANCEMENT: Clear authentication state securely
    clearAuthenticationState() {
        this.authenticated = false;
        this.userInfo = null;
        this.csrfToken = null;
        this.lastAuthTime = null;
        this.retryCount = 0;
    }

    // Logout and clear cross-domain cookies
    async logout() {
        try {
            const response = await fetch(this.authEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(this.csrfToken && { 'X-CSRF-Token': this.csrfToken })
                },
                credentials: 'include',
                body: JSON.stringify({
                    action: 'logout'
                })
            });

            // Clear local state regardless of response
            this.clearAuthenticationState();

            console.log('Cross-domain logout completed');

            // Dispatch logout event
            window.dispatchEvent(new CustomEvent('crossDomainLogout'));

            return response.ok;

        } catch (error) {
            console.error('Logout failed:', error);
            // Clear local state even if logout request fails
            this.clearAuthenticationState();
            return false;
        }
    }

    // Get current authentication state
    isAuthenticated() {
        return this.authenticated;
    }

    // Get current user info
    getUserInfo() {
        return this.userInfo;
    }

    // Get CSRF token for secure requests
    getCSRFToken() {
        return this.csrfToken;
    }

    // Make authenticated requests with CSRF protection
    async makeAuthenticatedRequest(url, options = {}) {
        if (!this.authenticated) {
            throw new Error('User not authenticated');
        }

        const headers = {
            'Content-Type': 'application/json',
            ...(this.csrfToken && { 'X-CSRF-Token': this.csrfToken }),
            ...options.headers
        };

        const requestOptions = {
            ...options,
            headers,
            credentials: 'include' // Include cookies for cross-domain requests
        };

        try {
            const response = await fetch(url, requestOptions);
            
            // Handle authentication errors
            if (response.status === 401) {
                this.clearAuthenticationState();

                window.dispatchEvent(new CustomEvent('crossDomainAuthExpired'));
                throw new Error('Authentication expired');
            }

            if (response.status === 403) {
                const data = await response.json();
                if (data.emailVerified === false) {
                    throw new EmailVerificationError(data.message || 'Email verification required');
                }
            }

            return response;

        } catch (error) {
            console.error('Authenticated request failed:', error);
            throw error;
        }
    }

    // Enhanced Firebase authentication with email verification check
    async authenticateWithFirebase() {
        try {
            const auth = window.firebaseAuth;
            if (!auth || !auth.currentUser) {
                throw new Error('Firebase user not authenticated');
            }

            // Check if email is verified
            if (!auth.currentUser.emailVerified) {
                throw new EmailVerificationError('Email verification required for cross-domain access');
            }

            // Get Firebase ID token
            const idToken = await auth.currentUser.getIdToken(true); // Force refresh
            
            // Authenticate with our cross-domain system
            return await this.authenticate(idToken);

        } catch (error) {
            console.error('Firebase cross-domain authentication failed:', error);
            throw error;
        }
    }
}

// Custom error classes for better error handling
class EmailVerificationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'EmailVerificationError';
    }
}

class TokenExpiredError extends Error {
    constructor(message) {
        super(message);
        this.name = 'TokenExpiredError';
    }
}

class TokenRevokedError extends Error {
    constructor(message) {
        super(message);
        this.name = 'TokenRevokedError';
    }
}

// Global instance
window.crossDomainAuth = new CrossDomainAuthManager();

// Auto-initialize when Firebase is ready
window.addEventListener('firebaseReady', async () => {
    try {
        console.log('Initializing cross-domain authentication...');
        await window.crossDomainAuth.initialize();
    } catch (error) {
        console.error('Cross-domain auth initialization error:', error);
    }
});

// Handle authentication events
window.addEventListener('crossDomainAuthSuccess', (event) => {
    console.log('Cross-domain authentication successful:', event.detail.user);
    // Update UI state, enable features, etc.
});

window.addEventListener('crossDomainAuthError', (event) => {
    console.error('Cross-domain authentication error:', event.detail.error);
    
    // Handle specific error types
    if (event.detail.type === 'EmailVerificationError') {
        // Show email verification prompt
        showEmailVerificationPrompt();
    }
});

window.addEventListener('crossDomainAuthExpired', () => {
    console.log('Cross-domain authentication expired');
    // Redirect to login or show re-authentication prompt
});

window.addEventListener('crossDomainLogout', () => {
    console.log('Cross-domain logout completed');
    // Update UI state, redirect to login, etc.
});

// Helper function to show email verification prompt
function showEmailVerificationPrompt() {
    // This would be implemented based on your UI framework
    const message = 'Please verify your email address to access cross-domain features. Check your inbox for a verification email.';
    
    // Simple alert for now - replace with proper UI
    alert(message);
    
    // Optionally trigger email verification resend
    const auth = window.firebaseAuth;
    if (auth && auth.currentUser && !auth.currentUser.emailVerified) {
        auth.currentUser.sendEmailVerification().then(() => {
            console.log('Verification email sent');
        }).catch((error) => {
            console.error('Failed to send verification email:', error);
        });
    }
}