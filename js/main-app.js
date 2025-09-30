// SESSION 3: Main Application Logic
// Fix based on Security Auditor finding #20250928_1015 - Externalize embedded script for CSP compliance
// Fix based on Visual Integrity Enforcer finding #20250928_1015 - Preserve pixel-perfect visual behavior

// Global app state - use window.currentLanguage for consistency across modules
let currentLanguage = window.currentLanguage || 'en';

// User state object
let userState = {
    userId: null
};

// Global variables for product identification
let currentProductInfo = null;
let inputMode = 'url'; // 'url' or 'barcode'

// SESSION 4: Module dependency validation and error handling
// Fix based on Codebase Architect finding #20250928_1630 - Enhanced module initialization
function checkModuleDependencies() {
    const requiredFunctions = ['showNotification', 'setupEventListeners', 't'];
    const missingDependencies = requiredFunctions.filter(fn => typeof window[fn] !== 'function');

    if (missingDependencies.length > 0) {
        console.warn('Missing module dependencies:', missingDependencies);
        return false;
    }
    return true;
}

// Global error handler with module dependency check
window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
    if (checkModuleDependencies() && typeof showNotification === 'function') {
        showNotification('An unexpected error occurred. Please try again.', 'error');
    }
});

window.addEventListener('error', function(event) {
    console.error('Global error:', event.error);
    if (checkModuleDependencies() && typeof showNotification === 'function') {
        showNotification('An unexpected error occurred. Please refresh the page.', 'error');
    }
});

// Initialize app when DOM is ready and Firebase is available
document.addEventListener('DOMContentLoaded', async function() {
    loadLanguagePreference();
    setupEventListeners();
    updateAllTranslations(); // Apply translations after everything is loaded

    addEntranceAnimations();
});

// Initialize Firebase-dependent features when Firebase is ready
window.addEventListener('firebaseReady', async function() {
    await loadUserState(); // Now async, includes server sync
});

function isLocalStorageAvailable() {
    try {
        const test = '__localStorage_test__';
        localStorage.setItem(test, test);
        localStorage.removeItem(test);
        return true;
    } catch (e) {
        return false;
    }
}

async function loadUserState() {
    try {
        // Initialize Firebase Authentication
        await initializeFirebaseAuth();
    } catch (error) {
        console.error('Error loading user state:', error);
    }
}

async function initializeFirebaseAuth() {
    return new Promise((resolve, reject) => {
        const auth = window.firebaseAuth;
        if (!auth) {
            reject(new Error('Firebase Auth not initialized'));
            return;
        }

        // Listen for authentication state changes
        window.firebaseOnAuthStateChanged(auth, async (user) => {
            try {
                if (user) {
                    // User is signed in
                    console.log('User authenticated:', user.uid);
                    userState.userId = user.uid;
                    userState.isAuthenticated = true;

                    // Initialize secure cookies for authenticated user
                    try {
                        await window.secureCookieManager.initializeSecureCookies();
                    } catch (error) {
                        console.error('Failed to initialize secure cookies for authenticated user:', error);
                    }

                    // Sync with server using Firebase UID
                    await syncFromServer();
                } else {
                    // No user is signed in, sign in anonymously
                    console.log('No user signed in, signing in anonymously...');
                    const result = await window.firebaseSignInAnonymously(auth);
                    console.log('Anonymous sign in successful:', result.user.uid);
                }
                resolve();
            } catch (error) {
                console.error('Firebase authentication error:', error);
                reject(error);
            }
        });
    });
}

async function syncFromServer() {
    try {
        // Ensure user is authenticated with Firebase
        if (!userState.userId || !userState.isAuthenticated) {
            console.warn('User not authenticated, cannot sync with server');
            return;
        }

        // Use centralized token manager for secure authentication
        const response = await makeAuthenticatedRequest('/.netlify/functions/firebase-user', {
            method: 'POST',
            body: JSON.stringify({
                action: 'get_user',
                userId: userState.userId
            })
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success && result.user) {
                console.log('Synced user data from server:', result.user);
            }
        }
    } catch (error) {
        console.warn('Could not sync with server, using local data:', error);
    }
}

function saveUserState() {
    if (!isLocalStorageAvailable()) {
        console.warn('localStorage not available, cannot save state');
        return;
    }

    try {
        // SECURITY FIX: Remove localStorage for sensitive data - server manages all user state
        // Only save non-sensitive UI preferences
        const preferencesToSave = {
            preferredLanguage: userState.preferredLanguage || 'en'
        };
        localStorage.setItem('userPreferences', JSON.stringify(preferencesToSave));
    } catch (error) {
        console.error('Error saving user state:', error);
    }
}

async function syncUserToServer(userData) {
    const response = await fetch('/.netlify/functions/admin', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            action: 'sync_user',
            password: 'demo123', // This would be better handled differently in production
            userId: userData.userId || generateUserIdFromData(userData),
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
}

function generateUserIdFromData(userData) {
    // Use Firebase UID instead of generating random IDs
    const auth = window.firebaseAuth;
    const user = auth?.currentUser;
    if (user) {
        return user.uid;
    }

    // Fallback for cases where Firebase is not ready
    console.warn('Firebase user not available, using anonymous ID');
    return `anonymous_${Date.now()}`;
}

function addEntranceAnimations() {
    // Add subtle entrance animations
    const sections = document.querySelectorAll('.generator-section');
    sections.forEach((section, index) => {
        section.style.opacity = '0';
        section.style.transform = 'translateY(30px)';

        setTimeout(() => {
            section.style.transition = 'all 0.8s ease';
            section.style.opacity = '1';
            section.style.transform = 'translateY(0)';
        }, index * 200);
    });
}

// Check for successful payment on page load
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.get('success') === 'true') {
    showNotification('Payment processed successfully!', 'success');

    // Clean up URL
    window.history.replaceState({}, document.title, window.location.pathname);
}

// SESSION 3C: Enhanced navigation with return URL support
function openSignupWithReturn() {
    const currentUrl = window.location.href;
    const signupUrl = `https://signup.soltecsol.com?return_to=${encodeURIComponent(currentUrl)}`;
    window.open(signupUrl, '_blank', 'noopener,noreferrer');
}

function openSigninWithReturn() {
    const currentUrl = window.location.href;
    const signinUrl = `https://signup.soltecsol.com?tab=signin&return_to=${encodeURIComponent(currentUrl)}`;
    window.open(signinUrl, '_blank', 'noopener,noreferrer');
}