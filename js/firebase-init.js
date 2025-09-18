// Firebase Initialization Module - Extracted for CSP Compliance
// This module handles secure Firebase initialization and token management

import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js';
import { getAuth, signInAnonymously, onAuthStateChanged, onIdTokenChanged } from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js';

// SECURITY FIX: Load Firebase configuration securely from endpoint
async function initializeFirebaseSecure() {
    try {
        // Fetch Firebase configuration from secure endpoint
        const response = await fetch('/.netlify/functions/firebase-public-config');

        if (!response.ok) {
            throw new Error(`Firebase config fetch failed: ${response.status} ${response.statusText}`);
        }

        const firebaseConfig = await response.json();

        // Validate configuration
        if (!firebaseConfig.apiKey || !firebaseConfig.projectId) {
            throw new Error('Invalid Firebase configuration received');
        }

        // Initialize Firebase with secure configuration
        const app = initializeApp(firebaseConfig);
        const auth = getAuth(app);

        // Make Firebase available globally
        window.firebaseApp = app;
        window.firebaseAuth = auth;
        window.firebaseSignInAnonymously = signInAnonymously;
        window.firebaseOnAuthStateChanged = onAuthStateChanged;
        window.firebaseOnIdTokenChanged = onIdTokenChanged;

        console.log('Firebase initialized securely');

        // Initialize centralized token management
        initializeTokenManager();

        // Initialize secure cookies after token manager is ready
        try {
            await window.secureCookieManager.initializeSecureCookies();
        } catch (error) {
            console.error('Failed to initialize secure cookies during Firebase setup:', error);
        }

        // Dispatch custom event to signal Firebase is ready
        window.dispatchEvent(new CustomEvent('firebaseReady'));

    } catch (error) {
        console.error('Firebase initialization failed:', error);
        // Show user-friendly error message
        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = 'position: fixed; top: 20px; left: 50%; transform: translateX(-50%); background: #ef4444; color: white; padding: 16px; border-radius: 8px; z-index: 9999; font-family: Inter, sans-serif;';
        errorDiv.textContent = 'Service temporarily unavailable. Please try again later.';
        document.body.appendChild(errorDiv);
        setTimeout(() => errorDiv.remove(), 5000);
    }
}

// Initialize token management with automatic refresh monitoring
function initializeTokenManager() {
    const auth = window.firebaseAuth;
    if (!auth) {
        console.error('Firebase Auth not available for token management');
        return;
    }

    // Set up automatic token refresh monitoring
    window.firebaseOnIdTokenChanged(auth, (user) => {
        if (user) {
            console.log('Token changed - clearing cached token');
            window.tokenManager.clearToken();
            // Optionally preload the new token
            window.tokenManager.getToken().catch(error => {
                console.warn('Failed to preload new token:', error);
            });
        } else {
            console.log('User signed out - clearing token cache and cookies');
            window.tokenManager.clearToken();
            window.secureCookieManager.clearAllCookies();
        }
    });

    console.log('Token manager initialized with automatic refresh monitoring');
}

// Initialize Firebase securely when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeFirebaseSecure);
} else {
    initializeFirebaseSecure();
}

// Export for module usage
export { initializeFirebaseSecure, initializeTokenManager };