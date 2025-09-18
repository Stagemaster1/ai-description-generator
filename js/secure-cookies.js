// Secure Cookie Manager - Extracted for CSP Compliance
// SECURE COOKIE IMPLEMENTATION - Session 5 Requirements

class SecureCookieManager {
    constructor() {
        this.isSecureContext = window.location.protocol === 'https:' || window.location.hostname === 'localhost';
    }

    // Generate CSRF token
    generateCSRFToken() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // Generate session ID
    generateSessionId() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // Set authentication token cookie with exact specified attributes
    setAuthTokenCookie(firebaseToken) {
        if (!firebaseToken) {
            console.warn('Cannot set auth token cookie: no token provided');
            return;
        }

        const cookieValue = `soltecsol_auth_token=${firebaseToken}; Domain=.soltecsol.com; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`;
        document.cookie = cookieValue;
        console.log('Authentication token cookie set');
    }

    // Set CSRF protection cookie with exact specified attributes
    setCSRFCookie() {
        const csrfToken = this.generateCSRFToken();
        const cookieValue = `soltecsol_csrf_token=${csrfToken}; Domain=.soltecsol.com; Path=/; Secure; SameSite=Strict; Max-Age=3600`;
        document.cookie = cookieValue;
        console.log('CSRF protection cookie set');
        return csrfToken;
    }

    // Set session management cookie with exact specified attributes
    setSessionCookie() {
        const sessionId = this.generateSessionId();
        const cookieValue = `soltecsol_session_id=${sessionId}; Domain=.soltecsol.com; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`;
        document.cookie = cookieValue;
        console.log('Session management cookie set');
        return sessionId;
    }

    // Initialize all secure cookies
    async initializeSecureCookies() {
        try {
            // Get Firebase token for authentication cookie
            const firebaseToken = await window.tokenManager.getToken();

            // Set all three required cookies
            this.setAuthTokenCookie(firebaseToken);
            const csrfToken = this.setCSRFCookie();
            const sessionId = this.setSessionCookie();

            console.log('All secure cookies initialized successfully');
            return { csrfToken, sessionId };
        } catch (error) {
            console.error('Failed to initialize secure cookies:', error);
            throw error;
        }
    }

    // Get cookie value by name
    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    // Clear all soltecsol cookies
    clearAllCookies() {
        const cookieNames = ['soltecsol_auth_token', 'soltecsol_csrf_token', 'soltecsol_session_id'];
        cookieNames.forEach(name => {
            document.cookie = `${name}=; Domain=.soltecsol.com; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        });
        console.log('All soltecsol cookies cleared');
    }
}

// Initialize global secure cookie manager instance
window.secureCookieManager = new SecureCookieManager();

// Test function for secure cookie implementation
async function testSecureCookies() {
    console.log('Testing secure cookie implementation...');

    try {
        // Test all three cookies
        const result = await window.secureCookieManager.initializeSecureCookies();

        // Verify cookies were set by checking their existence
        const authCookie = window.secureCookieManager.getCookie('soltecsol_auth_token');
        const csrfCookie = window.secureCookieManager.getCookie('soltecsol_csrf_token');
        const sessionCookie = window.secureCookieManager.getCookie('soltecsol_session_id');

        console.log('Cookie Test Results:');
        console.log('- Authentication Token Cookie:', authCookie ? 'SET' : 'NOT SET');
        console.log('- CSRF Protection Cookie:', csrfCookie ? 'SET' : 'NOT SET');
        console.log('- Session Management Cookie:', sessionCookie ? 'SET' : 'NOT SET');

        if (authCookie && csrfCookie && sessionCookie) {
            console.log('✅ All secure cookies implemented successfully');
            return true;
        } else {
            console.error('❌ Some cookies failed to set');
            return false;
        }
    } catch (error) {
        console.error('❌ Cookie test failed:', error);
        return false;
    }
}

// Make test function globally available
window.testSecureCookies = testSecureCookies;