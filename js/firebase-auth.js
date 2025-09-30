/**
 * PLYVO RECOVERY - Session 3: JavaScript Modularization
 *
 * 🧱 CODEBASE ARCHITECT - Firebase Authentication Module
 *
 * ARCHITECTURAL CHANGE: JavaScript Externalization - Authentication
 * - Extracted from embedded script block (lines 1343-1437, 1623-1661)
 * - Implements Firebase authentication flow with CSP compliance
 * - Manages user authentication state and server synchronization
 *
 * AUDIT TRAIL:
 * - Change Type: Authentication modularization
 * - Source: index.html embedded script (Firebase auth functions)
 * - Rationale: CSP compliance and security isolation
 * - Reversible: Yes, can re-embed in main script
 * - Containment: Preserved within js/ directory structure
 *
 * Date: 2025-09-28
 * Session: 3
 * Architect: Codebase Architect under Copilot supervision
 */

// Firebase Authentication Manager
class FirebaseAuthManager {
    constructor() {
        this.auth = null;
        this.isInitialized = false;
        this.currentUser = null;
        this.authStateCallbacks = [];
    }

    // Initialize Firebase Authentication
    async initializeFirebaseAuth() {
        return new Promise((resolve, reject) => {
            this.auth = window.firebaseAuth;
            if (!this.auth) {
                reject(new Error('Firebase Auth not initialized'));
                return;
            }

            // Listen for authentication state changes
            window.firebaseOnAuthStateChanged(this.auth, async (user) => {
                try {
                    this.currentUser = user;

                    if (user) {
                        // User is signed in
                        console.log('User authenticated:', user.uid);

                        // Update app state
                        if (window.appState) {
                            window.appState.setUser({
                                userId: user.uid,
                                isAuthenticated: true
                            });
                        } else {
                            // Fallback for legacy compatibility
                            window.userState = window.userState || {};
                            window.userState.userId = user.uid;
                            window.userState.isAuthenticated = true;
                        }

                        // Initialize secure cookies for authenticated user
                        try {
                            if (window.secureCookieManager) {
                                await window.secureCookieManager.initializeSecureCookies();
                            }
                        } catch (error) {
                            console.error('Failed to initialize secure cookies for authenticated user:', error);
                        }

                        // Sync with server using Firebase UID
                        await this.syncFromServer();
                    } else {
                        // No user is signed in, sign in anonymously
                        console.log('No user signed in, signing in anonymously...');
                        const result = await window.firebaseSignInAnonymously(this.auth);
                        console.log('Anonymous sign in successful:', result.user.uid);
                    }

                    // Notify auth state callbacks
                    this.notifyAuthStateCallbacks(user);

                    if (!this.isInitialized) {
                        this.isInitialized = true;
                        resolve();
                    }
                } catch (error) {
                    console.error('Firebase authentication error:', error);
                    reject(error);
                }
            });
        });
    }

    // Load user state and initialize Firebase auth
    async loadUserState() {
        try {
            await this.initializeFirebaseAuth();
        } catch (error) {
            console.error('Error loading user state:', error);
            throw error;
        }
    }

    // Sync user data from server
    async syncFromServer() {
        try {
            const userState = window.appState ? window.appState.getUser() : window.userState;

            // Ensure user is authenticated with Firebase
            if (!userState?.userId || !userState?.isAuthenticated) {
                console.warn('User not authenticated, cannot sync with server');
                return;
            }

            // Use centralized token manager for secure authentication
            const response = await this.makeAuthenticatedRequest('/.netlify/functions/firebase-user', {
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

                    // Update app state with server data
                    if (window.appState) {
                        window.appState.setUser({
                            ...window.appState.getUser(),
                            ...result.user
                        });
                    }
                }
            }
        } catch (error) {
            console.warn('Could not sync with server, using local data:', error);
        }
    }

    // Sync user data to server
    async syncUserToServer(userData) {
        try {
            const response = await fetch('/.netlify/functions/admin', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
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

    // Generate user ID from Firebase or create fallback
    generateUserIdFromData(userData) {
        // Use Firebase UID instead of generating random IDs
        if (this.currentUser) {
            return this.currentUser.uid;
        }

        // Fallback for cases where Firebase is not ready
        console.warn('Firebase user not available, using anonymous ID');
        return `anonymous_${Date.now()}`;
    }

    // Make authenticated request using token manager
    async makeAuthenticatedRequest(url, options = {}) {
        try {
            // Use token manager if available
            if (window.tokenManager && typeof window.tokenManager.makeAuthenticatedRequest === 'function') {
                return await window.tokenManager.makeAuthenticatedRequest(url, options);
            }

            // Fallback to basic fetch with Firebase token
            const token = await this.getIdToken();
            const headers = {
                'Content-Type': 'application/json',
                ...options.headers
            };

            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }

            return await fetch(url, {
                ...options,
                headers
            });
        } catch (error) {
            console.error('Authenticated request failed:', error);
            throw error;
        }
    }

    // Get Firebase ID token
    async getIdToken() {
        try {
            if (this.currentUser) {
                return await this.currentUser.getIdToken();
            }
            return null;
        } catch (error) {
            console.error('Failed to get ID token:', error);
            return null;
        }
    }

    // Save user state to localStorage (non-sensitive data only)
    saveUserState() {
        if (!this.isLocalStorageAvailable()) {
            console.warn('localStorage not available, cannot save state');
            return;
        }

        try {
            const userState = window.appState ? window.appState.getUser() : window.userState;

            // SECURITY FIX: Remove localStorage for sensitive data - server manages all user state
            // Only save non-sensitive UI preferences
            const preferencesToSave = {
                preferredLanguage: userState?.preferredLanguage || userState?.preferences?.language || 'en'
            };
            localStorage.setItem('userPreferences', JSON.stringify(preferencesToSave));
        } catch (error) {
            console.error('Error saving user state:', error);
        }
    }

    // Check localStorage availability
    isLocalStorageAvailable() {
        try {
            const test = '__localStorage_test__';
            localStorage.setItem(test, test);
            localStorage.removeItem(test);
            return true;
        } catch (e) {
            return false;
        }
    }

    // Subscribe to auth state changes
    onAuthStateChanged(callback) {
        this.authStateCallbacks.push(callback);
        return () => {
            const index = this.authStateCallbacks.indexOf(callback);
            if (index > -1) {
                this.authStateCallbacks.splice(index, 1);
            }
        };
    }

    // Notify auth state callbacks
    notifyAuthStateCallbacks(user) {
        this.authStateCallbacks.forEach(callback => {
            try {
                callback(user);
            } catch (error) {
                console.error('Auth state callback error:', error);
            }
        });
    }

    // Sign out user
    async signOut() {
        try {
            if (this.auth) {
                await this.auth.signOut();

                // Clear app state
                if (window.appState) {
                    window.appState.setUser({
                        userId: null,
                        isAuthenticated: false
                    });
                } else {
                    // Fallback for legacy compatibility
                    if (window.userState) {
                        window.userState.userId = null;
                        window.userState.isAuthenticated = false;
                    }
                }
            }
        } catch (error) {
            console.error('Sign out error:', error);
            throw error;
        }
    }

    // Get current user
    getCurrentUser() {
        return this.currentUser;
    }

    // Check if user is authenticated
    isAuthenticated() {
        return !!(this.currentUser && !this.currentUser.isAnonymous);
    }

    // Check if user is anonymous
    isAnonymous() {
        return !!(this.currentUser && this.currentUser.isAnonymous);
    }
}

// Create global Firebase auth manager instance
const firebaseAuthManager = new FirebaseAuthManager();

// Legacy function compatibility
async function loadUserState() {
    return firebaseAuthManager.loadUserState();
}

async function initializeFirebaseAuth() {
    return firebaseAuthManager.initializeFirebaseAuth();
}

async function syncFromServer() {
    return firebaseAuthManager.syncFromServer();
}

async function syncUserToServer(userData) {
    return firebaseAuthManager.syncUserToServer(userData);
}

function generateUserIdFromData(userData) {
    return firebaseAuthManager.generateUserIdFromData(userData);
}

function saveUserState() {
    return firebaseAuthManager.saveUserState();
}

function isLocalStorageAvailable() {
    return firebaseAuthManager.isLocalStorageAvailable();
}

// For authenticated requests, expose the manager's method
async function makeAuthenticatedRequest(url, options) {
    return firebaseAuthManager.makeAuthenticatedRequest(url, options);
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        FirebaseAuthManager,
        firebaseAuthManager,
        loadUserState,
        initializeFirebaseAuth,
        syncFromServer,
        syncUserToServer,
        generateUserIdFromData,
        saveUserState,
        isLocalStorageAvailable,
        makeAuthenticatedRequest
    };
}

// Export for browser usage
if (typeof window !== 'undefined') {
    window.FirebaseAuthManager = FirebaseAuthManager;
    window.firebaseAuthManager = firebaseAuthManager;
    window.loadUserState = loadUserState;
    window.initializeFirebaseAuth = initializeFirebaseAuth;
    window.syncFromServer = syncFromServer;
    window.syncUserToServer = syncUserToServer;
    window.generateUserIdFromData = generateUserIdFromData;
    window.saveUserState = saveUserState;
    window.isLocalStorageAvailable = isLocalStorageAvailable;
    window.makeAuthenticatedRequest = makeAuthenticatedRequest;
}