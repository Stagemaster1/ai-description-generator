/**
 * PLYVO RECOVERY - Session 3: JavaScript Modularization
 *
 * 🧱 CODEBASE ARCHITECT - Event Handlers Module
 *
 * ARCHITECTURAL CHANGE: JavaScript Externalization - Event Binding
 * - Extracted from embedded script block (lines 1439-1598, 2156-2212)
 * - Implements CSP-compliant addEventListener patterns
 * - Manages DOM event binding and user interactions
 *
 * AUDIT TRAIL:
 * - Change Type: Event handling modularization
 * - Source: index.html embedded script (event setup functions)
 * - Rationale: CSP compliance and separation of concerns
 * - Reversible: Yes, can re-embed as inline event handlers
 * - Containment: Preserved within js/ directory structure
 *
 * Date: 2025-09-28
 * Session: 3
 * Architect: Codebase Architect under Copilot supervision
 */

// Event Handlers Manager
class EventHandlersManager {
    constructor() {
        this.eventListeners = new Map();
        this.isInitialized = false;
    }

    // Main setup function for all event listeners
    setupEventListeners() {
        if (this.isInitialized) {
            console.warn('Event listeners already initialized');
            return;
        }

        console.log('Setting up event listeners...');

        // Form submission
        this.setupFormEvents();

        // Input mode switching
        this.setupInputModeEvents();

        // Language switching
        this.setupLanguageEvents();

        // Dialog and navigation events
        this.setupDialogEvents();
        this.setupNavigationEvents();

        // URL parameter handling
        this.handleURLParameters();

        this.isInitialized = true;
        console.log('Event listeners setup complete');
    }

    // Setup form-related events
    setupFormEvents() {
        const form = document.getElementById('descriptionForm');
        if (form) {
            console.log('Form found, adding submit listener');
            this.addEventListener(form, 'submit', this.handleFormSubmission.bind(this));
        } else {
            console.error('Form not found!');
        }

        const copyBtn = document.getElementById('copyBtn');
        if (copyBtn) {
            this.addEventListener(copyBtn, 'click', this.handleCopyToClipboard.bind(this));
        }
    }

    // Setup input mode switching events
    setupInputModeEvents() {
        const urlModeBtn = document.getElementById('urlModeBtn');
        const barcodeModeBtn = document.getElementById('barcodeModeBtn');
        const manualModeBtn = document.getElementById('manualModeBtn');

        if (urlModeBtn) {
            this.addEventListener(urlModeBtn, 'click', () => this.switchInputMode('url'));
        }

        if (barcodeModeBtn) {
            this.addEventListener(barcodeModeBtn, 'click', () => this.switchInputMode('barcode'));
        }

        if (manualModeBtn) {
            this.addEventListener(manualModeBtn, 'click', () => this.switchInputMode('manual'));
        }

        // Barcode lookup button
        const lookupBarcodeBtn = document.getElementById('lookupBarcodeBtn');
        if (lookupBarcodeBtn) {
            this.addEventListener(lookupBarcodeBtn, 'click', this.handleBarcodeLookup.bind(this));
        }
    }

    // Setup language switching events
    setupLanguageEvents() {
        const toggle = document.getElementById('languageToggle');
        const dropdown = document.getElementById('languageDropdown');
        const options = document.querySelectorAll('.language-option');
        const flag = document.getElementById('currentLanguageFlag');
        const name = document.getElementById('currentLanguageName');

        if (toggle && dropdown) {
            this.addEventListener(toggle, 'click', () => {
                dropdown.style.display = dropdown.style.display === 'none' ? 'block' : 'none';
            });
        }

        if (options.length && flag && name) {
            options.forEach(option => {
                this.addEventListener(option, 'click', () => {
                    const selectedFlag = option.querySelector('span')?.textContent || '';
                    const selectedName = option.textContent.replace(selectedFlag, '').trim();
                    flag.textContent = selectedFlag;
                    name.textContent = selectedName;
                    dropdown.style.display = 'none';

                    // Extract language code from option data attribute or text
                    const langCode = option.getAttribute('data-lang') || this.extractLanguageCode(selectedName);
                    if (langCode && window.appState) {
                        window.appState.setLanguage(langCode);
                    }
                });
            });
        }
    }

    // Setup dialog events
    setupDialogEvents() {
        document.querySelectorAll('[data-close-dialog]').forEach(button => {
            this.addEventListener(button, 'click', () => {
                const overlay = button.closest('.usage-limit-dialog-overlay');
                if (overlay) overlay.remove();
            });
        });
    }

    // Setup navigation events
    setupNavigationEvents() {
        const signIn = document.getElementById('signInButton');
        if (signIn) {
            this.addEventListener(signIn, 'click', () => {
                window.location.href = 'https://login.soltecsol.com';
            });
        }

        const login = document.getElementById('loginButton');
        if (login) {
            this.addEventListener(login, 'click', () => {
                window.location.href = 'https://login.soltecsol.com';
            });
        }
    }

    // Handle URL parameters
    handleURLParameters() {
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('success') === 'true') {
            if (typeof window.showNotification === 'function') {
                window.showNotification('Payment processed successfully!', 'success');
            }
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }

    // Form submission handler
    handleFormSubmission(event) {
        console.log('Form submitted!');
        event.preventDefault();

        if (typeof window.generateDescription === 'function') {
            window.generateDescription();
        } else {
            console.error('generateDescription function not available');
        }
    }

    // Copy to clipboard handler
    handleCopyToClipboard() {
        const resultsContent = document.getElementById('resultsContent');
        if (!resultsContent) {
            console.error('Results content not found');
            return;
        }

        const text = resultsContent.textContent;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
                if (typeof window.showNotification === 'function') {
                    window.showNotification(window.t ? window.t('descriptionCopied') : 'Description copied to clipboard!', 'success');
                }
            }).catch(error => {
                console.error('Copy failed:', error);
                this.fallbackCopy(text);
            });
        } else {
            this.fallbackCopy(text);
        }
    }

    // Fallback copy method
    fallbackCopy(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            if (typeof window.showNotification === 'function') {
                window.showNotification(window.t ? window.t('descriptionCopied') : 'Description copied to clipboard!', 'success');
            }
        } catch (error) {
            console.error('Fallback copy failed:', error);
            if (typeof window.showNotification === 'function') {
                window.showNotification('Unable to copy text. Please copy manually.', 'error');
            }
        }
        document.body.removeChild(textArea);
    }

    // Switch input mode
    switchInputMode(mode) {
        console.log('Switching input mode to:', mode);

        // Update app state
        if (window.appState) {
            window.appState.setInputMode(mode);
            window.appState.setProductInfo(null);
        } else {
            // Fallback for legacy compatibility
            window.inputMode = mode;
            window.currentProductInfo = null;
        }

        // Update UI elements
        this.updateInputModeUI(mode);

        // Clear any existing errors
        if (typeof window.clearErrors === 'function') {
            window.clearErrors();
        }
    }

    // Update input mode UI
    updateInputModeUI(mode) {
        const urlModeBtn = document.getElementById('urlModeBtn');
        const barcodeModeBtn = document.getElementById('barcodeModeBtn');
        const manualModeBtn = document.getElementById('manualModeBtn');
        const urlInputGroup = document.getElementById('urlInputGroup');
        const barcodeInputGroup = document.getElementById('barcodeInputGroup');
        const manualInputGroup = document.getElementById('manualInputGroup');
        const productPreview = document.getElementById('productPreview');

        // Remove all active states first
        [urlModeBtn, barcodeModeBtn, manualModeBtn].forEach(btn => {
            if (btn) btn.classList.remove('active');
        });

        [urlInputGroup, barcodeInputGroup, manualInputGroup].forEach(group => {
            if (group) group.classList.remove('active');
        });

        // Set active state based on mode
        if (mode === 'url') {
            urlModeBtn?.classList.add('active');
            urlInputGroup?.classList.add('active');
        } else if (mode === 'barcode') {
            barcodeModeBtn?.classList.add('active');
            barcodeInputGroup?.classList.add('active');
        } else if (mode === 'manual') {
            manualModeBtn?.classList.add('active');
            manualInputGroup?.classList.add('active');
        }

        if (productPreview) {
            productPreview.style.display = 'none';
        }
    }

    // Handle barcode lookup
    async handleBarcodeLookup() {
        const barcodeInput = document.getElementById('productBarcode');
        const barcode = barcodeInput?.value.trim();

        if (!barcode) {
            if (typeof window.showError === 'function') {
                window.showError('barcodeError', 'Please enter a barcode');
            }
            return;
        }

        // Validate barcode format
        if (!/^\d{8,13}$/.test(barcode.replace(/[\s-]/g, ''))) {
            if (typeof window.showError === 'function') {
                window.showError('barcodeError', 'Please enter a valid 8-13 digit barcode');
            }
            return;
        }

        const lookupBtn = document.getElementById('lookupBarcodeBtn');
        if (lookupBtn) {
            lookupBtn.disabled = true;
            lookupBtn.textContent = '🔍 Looking up...';
        }

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
                // Update app state with product info
                if (window.appState) {
                    window.appState.setProductInfo(data.product);
                } else {
                    window.currentProductInfo = data.product;
                }

                this.showProductPreview(data.product);

                if (typeof window.showNotification === 'function') {
                    window.showNotification('Product found! Ready to generate description.', 'success');
                }
            } else {
                if (typeof window.showError === 'function') {
                    window.showError('barcodeError', 'Product not found in barcode databases');
                }
                if (typeof window.showNotification === 'function') {
                    window.showNotification('Product not found. You can still generate a description by filling in the details manually.', 'error');
                }
            }
        } catch (error) {
            console.error('Barcode lookup error:', error);
            if (typeof window.showError === 'function') {
                window.showError('barcodeError', 'Failed to lookup barcode. Please try again.');
            }
            if (typeof window.showNotification === 'function') {
                window.showNotification('Lookup failed. Please try again.', 'error');
            }
        } finally {
            if (lookupBtn) {
                lookupBtn.disabled = false;
                lookupBtn.textContent = '🔍 Lookup Product';
            }
        }
    }

    // Show product preview
    showProductPreview(product) {
        const productPreview = document.getElementById('productPreview');
        const previewImage = document.getElementById('previewImage');
        const previewName = document.getElementById('previewName');
        const previewBrand = document.getElementById('previewBrand');
        const previewCategory = document.getElementById('previewCategory');

        if (previewName) previewName.textContent = product.name || 'Unknown Product';
        if (previewBrand) previewBrand.textContent = product.brand || 'Unknown Brand';
        if (previewCategory) previewCategory.textContent = product.category || 'General Product';

        if (product.imageUrl && previewImage) {
            previewImage.src = product.imageUrl;
            previewImage.style.display = 'block';
        } else if (previewImage) {
            previewImage.style.display = 'none';
        }

        if (productPreview) {
            productPreview.style.display = 'block';
        }
    }

    // Extract language code from language name
    extractLanguageCode(languageName) {
        const languageMap = {
            'English': 'en',
            'Español': 'es',
            'Français': 'fr',
            'Deutsch': 'de',
            'Italiano': 'it',
            'Português': 'pt',
            'Nederlands': 'nl',
            '日本語': 'ja',
            '中文': 'zh',
            'Русский': 'ru',
            'العربية': 'ar',
            'हिन्दी': 'hi',
            '한국어': 'ko'
        };
        return languageMap[languageName] || 'en';
    }

    // Add event listener with tracking
    addEventListener(element, event, handler) {
        if (!element) return;

        const key = `${element.id || 'unnamed'}_${event}`;

        // Remove existing listener if present
        if (this.eventListeners.has(key)) {
            const { element: oldElement, event: oldEvent, handler: oldHandler } = this.eventListeners.get(key);
            oldElement.removeEventListener(oldEvent, oldHandler);
        }

        // Add new listener
        element.addEventListener(event, handler);
        this.eventListeners.set(key, { element, event, handler });
    }

    // Remove all event listeners
    removeAllEventListeners() {
        this.eventListeners.forEach(({ element, event, handler }) => {
            element.removeEventListener(event, handler);
        });
        this.eventListeners.clear();
        this.isInitialized = false;
    }

    // Re-initialize event listeners
    reinitialize() {
        this.removeAllEventListeners();
        this.setupEventListeners();
    }
}

// Create global event handlers manager instance
const eventHandlersManager = new EventHandlersManager();

// Legacy function compatibility
function setupEventListeners() {
    return eventHandlersManager.setupEventListeners();
}

function handleFormSubmission(event) {
    return eventHandlersManager.handleFormSubmission(event);
}

function handleCopyToClipboard() {
    return eventHandlersManager.handleCopyToClipboard();
}

function fallbackCopy(text) {
    return eventHandlersManager.fallbackCopy(text);
}

function switchInputMode(mode) {
    return eventHandlersManager.switchInputMode(mode);
}

async function handleBarcodeLookup() {
    return eventHandlersManager.handleBarcodeLookup();
}

function showProductPreview(product) {
    return eventHandlersManager.showProductPreview(product);
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        EventHandlersManager,
        eventHandlersManager,
        setupEventListeners,
        handleFormSubmission,
        handleCopyToClipboard,
        fallbackCopy,
        switchInputMode,
        handleBarcodeLookup,
        showProductPreview
    };
}

// Export for browser usage
if (typeof window !== 'undefined') {
    window.EventHandlersManager = EventHandlersManager;
    window.eventHandlersManager = eventHandlersManager;
    window.setupEventListeners = setupEventListeners;
    window.handleFormSubmission = handleFormSubmission;
    window.handleCopyToClipboard = handleCopyToClipboard;
    window.fallbackCopy = fallbackCopy;
    window.switchInputMode = switchInputMode;
    window.handleBarcodeLookup = handleBarcodeLookup;
    window.showProductPreview = showProductPreview;
}