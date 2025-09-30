/**
 * PLYVO RECOVERY - Session 3: JavaScript Modularization
 *
 * 🧱 CODEBASE ARCHITECT - Application State Management Module
 *
 * ARCHITECTURAL CHANGE: JavaScript Externalization - Global State
 * - Extracted from embedded script block (lines 295, 1202-1210)
 * - Centralized state management for CSP compliance
 * - Maintains user session and application configuration
 *
 * AUDIT TRAIL:
 * - Change Type: State management modularization
 * - Source: index.html embedded script (global variables)
 * - Rationale: CSP compliance and centralized state control
 * - Reversible: Yes, can re-embed as global variables
 * - Containment: Preserved within js/ directory structure
 *
 * Date: 2025-09-28
 * Session: 3
 * Architect: Codebase Architect under Copilot supervision
 */

// Application state management
class AppState {
    constructor() {
        // Initialize default state
        this.state = {
            // Language and localization
            currentLanguage: 'en',

            // User state object
            userState: {
                userId: null,
                usage: {
                    used: 0,
                    limit: null,
                    isUnlimited: false
                },
                preferences: {
                    language: 'en',
                    theme: 'light'
                }
            },

            // Product identification state
            currentProductInfo: null,
            inputMode: 'url', // 'url', 'barcode', or 'manual'

            // UI state
            isLoading: false,
            errors: {},
            notifications: [],

            // Authentication state
            isAuthenticated: false,
            authToken: null,

            // Feature flags
            features: {
                barcodeMode: true,
                manualMode: true,
                multiLanguage: true
            }
        };

        // State change listeners
        this.listeners = new Map();

        // Initialize from localStorage if available
        this.loadFromStorage();
    }

    // Get current state
    getState() {
        return this.state;
    }

    // Update state with deep merge
    setState(updates) {
        const oldState = JSON.parse(JSON.stringify(this.state));
        this.state = this.deepMerge(this.state, updates);
        this.notifyListeners(oldState, this.state);
        this.saveToStorage();
    }

    // Get specific state property
    get(path) {
        return this.getNestedProperty(this.state, path);
    }

    // Set specific state property
    set(path, value) {
        const updates = this.setNestedProperty({}, path, value);
        this.setState(updates);
    }

    // Subscribe to state changes
    subscribe(listener, path = null) {
        const id = Date.now() + Math.random();
        this.listeners.set(id, { listener, path });
        return () => this.listeners.delete(id);
    }

    // Notify listeners of state changes
    notifyListeners(oldState, newState) {
        this.listeners.forEach(({ listener, path }) => {
            if (path) {
                const oldValue = this.getNestedProperty(oldState, path);
                const newValue = this.getNestedProperty(newState, path);
                if (oldValue !== newValue) {
                    listener(newValue, oldValue);
                }
            } else {
                listener(newState, oldState);
            }
        });
    }

    // Deep merge objects
    deepMerge(target, source) {
        const result = { ...target };

        for (const key in source) {
            if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                result[key] = this.deepMerge(target[key] || {}, source[key]);
            } else {
                result[key] = source[key];
            }
        }

        return result;
    }

    // Get nested property by path (e.g., 'userState.usage.used')
    getNestedProperty(obj, path) {
        return path.split('.').reduce((current, key) => current?.[key], obj);
    }

    // Set nested property by path
    setNestedProperty(obj, path, value) {
        const keys = path.split('.');
        const lastKey = keys.pop();
        const target = keys.reduce((current, key) => {
            current[key] = current[key] || {};
            return current[key];
        }, obj);
        target[lastKey] = value;
        return obj;
    }

    // Load state from localStorage
    loadFromStorage() {
        if (!this.isLocalStorageAvailable()) return;

        try {
            // Load language preference
            const savedLang = localStorage.getItem('preferredLanguage');
            if (savedLang) {
                this.state.currentLanguage = savedLang;
                this.state.userState.preferences.language = savedLang;
            }

            // Load user preferences
            const savedPreferences = localStorage.getItem('userPreferences');
            if (savedPreferences) {
                const preferences = JSON.parse(savedPreferences);
                this.state.userState.preferences = { ...this.state.userState.preferences, ...preferences };
            }

            // Load user state
            const savedUserState = localStorage.getItem('userState');
            if (savedUserState) {
                const userState = JSON.parse(savedUserState);
                this.state.userState = { ...this.state.userState, ...userState };
            }
        } catch (error) {
            console.warn('Failed to load state from localStorage:', error);
        }
    }

    // Save state to localStorage
    saveToStorage() {
        if (!this.isLocalStorageAvailable()) return;

        try {
            // Save language preference
            localStorage.setItem('preferredLanguage', this.state.currentLanguage);

            // Save user preferences
            localStorage.setItem('userPreferences', JSON.stringify(this.state.userState.preferences));

            // Save user state (excluding sensitive data)
            const userStateToSave = {
                userId: this.state.userState.userId,
                usage: this.state.userState.usage,
                preferences: this.state.userState.preferences
            };
            localStorage.setItem('userState', JSON.stringify(userStateToSave));
        } catch (error) {
            console.warn('Failed to save state to localStorage:', error);
        }
    }

    // Check if localStorage is available
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

    // Reset state to defaults
    reset() {
        this.state = {
            currentLanguage: 'en',
            userState: {
                userId: null,
                usage: { used: 0, limit: null, isUnlimited: false },
                preferences: { language: 'en', theme: 'light' }
            },
            currentProductInfo: null,
            inputMode: 'url',
            isLoading: false,
            errors: {},
            notifications: [],
            isAuthenticated: false,
            authToken: null,
            features: {
                barcodeMode: true,
                manualMode: true,
                multiLanguage: true
            }
        };
        this.saveToStorage();
    }

    // Language management
    setLanguage(langCode) {
        this.setState({
            currentLanguage: langCode,
            userState: {
                preferences: {
                    language: langCode
                }
            }
        });
    }

    getCurrentLanguage() {
        return this.state.currentLanguage;
    }

    // User state management
    setUser(userData) {
        this.setState({
            userState: {
                ...userData,
                preferences: {
                    ...this.state.userState.preferences,
                    ...userData.preferences
                }
            },
            isAuthenticated: !!userData.userId
        });
    }

    getUser() {
        return this.state.userState;
    }

    // Usage tracking
    updateUsage(usage) {
        this.setState({
            userState: {
                usage: { ...this.state.userState.usage, ...usage }
            }
        });
    }

    // Product info management
    setProductInfo(productInfo) {
        this.setState({ currentProductInfo: productInfo });
    }

    getProductInfo() {
        return this.state.currentProductInfo;
    }

    // Input mode management
    setInputMode(mode) {
        this.setState({ inputMode: mode });
    }

    getInputMode() {
        return this.state.inputMode;
    }

    // Loading state
    setLoading(isLoading) {
        this.setState({ isLoading });
    }

    isAppLoading() {
        return this.state.isLoading;
    }

    // Error management
    setError(key, message) {
        this.setState({
            errors: { ...this.state.errors, [key]: message }
        });
    }

    clearError(key) {
        const errors = { ...this.state.errors };
        delete errors[key];
        this.setState({ errors });
    }

    clearAllErrors() {
        this.setState({ errors: {} });
    }

    getError(key) {
        return this.state.errors[key];
    }

    // Notification management
    addNotification(notification) {
        const notifications = [...this.state.notifications, {
            id: Date.now(),
            timestamp: new Date(),
            ...notification
        }];
        this.setState({ notifications });
    }

    removeNotification(id) {
        const notifications = this.state.notifications.filter(n => n.id !== id);
        this.setState({ notifications });
    }

    clearAllNotifications() {
        this.setState({ notifications: [] });
    }
}

// Create global app state instance
const appState = new AppState();

// Legacy global variables for backward compatibility
let currentLanguage = appState.getCurrentLanguage();
let userState = appState.getUser();
let currentProductInfo = appState.getProductInfo();
let inputMode = appState.getInputMode();

// Subscribe to language changes to update legacy variable
appState.subscribe((newLang) => {
    currentLanguage = newLang;
    if (typeof window !== 'undefined') {
        window.currentLanguage = newLang;
    }
}, 'currentLanguage');

// Subscribe to user state changes
appState.subscribe((newUserState) => {
    userState = newUserState;
    if (typeof window !== 'undefined') {
        window.userState = newUserState;
    }
}, 'userState');

// Subscribe to product info changes
appState.subscribe((newProductInfo) => {
    currentProductInfo = newProductInfo;
    if (typeof window !== 'undefined') {
        window.currentProductInfo = newProductInfo;
    }
}, 'currentProductInfo');

// Subscribe to input mode changes
appState.subscribe((newInputMode) => {
    inputMode = newInputMode;
    if (typeof window !== 'undefined') {
        window.inputMode = newInputMode;
    }
}, 'inputMode');

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        AppState,
        appState,
        currentLanguage,
        userState,
        currentProductInfo,
        inputMode
    };
}

// Export for browser usage
if (typeof window !== 'undefined') {
    window.AppState = AppState;
    window.appState = appState;
    window.currentLanguage = currentLanguage;
    window.userState = userState;
    window.currentProductInfo = currentProductInfo;
    window.inputMode = inputMode;
}