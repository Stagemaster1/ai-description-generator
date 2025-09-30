// SESSION 3: DOM Event Management
// Fix based on Security Auditor finding #20250928_1015 - Externalize embedded script for CSP compliance
// Fix based on Visual Integrity Enforcer finding #20250928_1015 - Preserve addEventListener patterns

// SESSION 4: Enhanced module initialization with dependency validation
// Fix based on Codebase Architect finding #20250928_1630 - Improved DOM event binding architecture

// Module initialization with dependency checking
function initializeDOMEvents() {
    // Validate module dependencies before proceeding
    const requiredModules = ['setupEventListeners', 't', 'showNotification'];
    const missingModules = requiredModules.filter(fn => typeof window[fn] !== 'function');

    if (missingModules.length > 0) {
        console.warn('[DOM Events] Missing dependencies:', missingModules);
        // Retry after a short delay
        setTimeout(initializeDOMEvents, 100);
        return;
    }

    console.log('[DOM Events] All dependencies loaded, initializing...');
    bindDOMEvents();
}

// DOM event binding using addEventListener patterns for CSP compliance
function bindDOMEvents() {
    // Language dropdown
    const toggle = document.getElementById('languageToggle');
    const dropdown = document.getElementById('languageDropdown');
    const options = document.querySelectorAll('.language-option');
    const flag = document.getElementById('currentLanguageFlag');
    const name = document.getElementById('currentLanguageName');

    if (toggle && dropdown) {
        toggle.addEventListener('click', () => {
            if (typeof toggleLanguageDropdown === 'function') {
                toggleLanguageDropdown();
            } else {
                // Fallback toggle
                dropdown.style.display = dropdown.style.display === 'none' || dropdown.style.display === '' ? 'block' : 'none';
            }
        });
    }

    if (options.length && flag && name) {
        options.forEach(option => {
            option.addEventListener('click', () => {
                const langCode = option.getAttribute('data-lang');
                if (langCode && typeof selectLanguage === 'function') {
                    selectLanguage(langCode);
                } else {
                    // Fallback to basic UI update
                    const selectedFlag = option.querySelector('span')?.textContent || '';
                    const selectedName = option.textContent.replace(selectedFlag, '').trim();
                    flag.textContent = selectedFlag;
                    name.textContent = selectedName;
                    dropdown.style.display = 'none';
                }
            });
        });
    }

    // Dialog close buttons
    document.querySelectorAll('[data-close-dialog]').forEach(button => {
        button.addEventListener('click', () => {
            const overlay = button.closest('.usage-limit-dialog-overlay');
            if (overlay) overlay.remove();
        });
    });

    // Sign-in button
    const signIn = document.getElementById('signInButton');
    if (signIn) {
        signIn.addEventListener('click', () => {
            window.location.href = 'https://login.soltecsol.com';
        });
    }

    // Login button
    const login = document.getElementById('loginButton');
    if (login) {
        login.addEventListener('click', () => {
            window.location.href = 'https://login.soltecsol.com';
        });
    }

    // Payment success handling
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('success') === 'true') {
        if (typeof showNotification === 'function') {
            showNotification('Payment processed successfully!', 'success');
        }
        window.history.replaceState({}, document.title, window.location.pathname);
    }

    // Call setupEventListeners if available
    if (typeof setupEventListeners === 'function') {
        setupEventListeners();
    }
}

// Initialize when DOM is ready with enhanced dependency management
document.addEventListener('DOMContentLoaded', initializeDOMEvents);