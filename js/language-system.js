// SESSION 3: Language System and Translation Management
// Fix based on Security Auditor finding #20250928_1015 - Externalize embedded script for CSP compliance
// Fix based on Visual Integrity Enforcer finding #20250928_1015 - Preserve language dropdown behavior

// Translation system
function t(key) {
    return translations[currentLanguage]?.[key] || translations.en[key] || key;
}

// CRITICAL VISUAL FUNCTION: Preserve dropdown toggle behavior
function toggleLanguageDropdown() {
    const dropdown = document.getElementById('languageDropdown');
    dropdown.style.display = dropdown.style.display === 'none' || dropdown.style.display === '' ? 'block' : 'none';
}

// CRITICAL VISUAL FUNCTION: Preserve language selection and display updates
function selectLanguage(langCode) {
    changeLanguage(langCode);
    document.getElementById('languageDropdown').style.display = 'none';
    updateLanguageDisplay(langCode);
}

function updateLanguageDisplay(langCode) {
    const languages = {
        en: { flag: '🇺🇸', name: 'English' },
        es: { flag: '🇪🇸', name: 'Español' },
        fr: { flag: '🇫🇷', name: 'Français' },
        de: { flag: '🇩🇪', name: 'Deutsch' },
        it: { flag: '🇮🇹', name: 'Italiano' },
        'pt-BR': { flag: '🇧🇷', name: 'Português (BR)' },
        nl: { flag: '🇳🇱', name: 'Nederlands' },
        ja: { flag: '🇯🇵', name: '日本語' },
        zh: { flag: '🇨🇳', name: '中文' },
        ru: { flag: '🇷🇺', name: 'Русский' },
        ar: { flag: '🇸🇦', name: 'العربية' },
        hi: { flag: '🇮🇳', name: 'हिन्दी' },
        ko: { flag: '🇰🇷', name: '한국어' }
    };

    if (languages[langCode]) {
        document.getElementById('currentLanguageFlag').textContent = languages[langCode].flag;
        document.getElementById('currentLanguageName').textContent = languages[langCode].name;
    }
}

function changeLanguage(langCode) {
    currentLanguage = langCode;
    window.currentLanguage = langCode; // Ensure global consistency
    localStorage.setItem('preferredLanguage', langCode);
    updateAllTranslations();
    updatePageTitle();

    // Force update all modules that use currentLanguage
    if (window.appState && typeof window.appState.setLanguage === 'function') {
        window.appState.setLanguage(langCode);
    }
}

function loadLanguagePreference() {
    const savedLang = localStorage.getItem('preferredLanguage') || 'en';
    currentLanguage = savedLang;
    window.currentLanguage = savedLang; // Ensure global consistency
    updateLanguageDisplay(savedLang);
    updateAllTranslations(); // Force full translation update on load
}

function updatePageTitle() {
    document.title = t('pageTitle');
}

function updateAllTranslations() {
    // Ensure currentLanguage is properly set
    if (!currentLanguage || !translations[currentLanguage]) {
        currentLanguage = 'en';
    }

    // Update all elements with data-translate attributes
    const elements = document.querySelectorAll('[data-translate]');
    elements.forEach(element => {
        const key = element.getAttribute('data-translate');
        if (translations[currentLanguage] && translations[currentLanguage][key]) {
            if (key === 'usageCounterText') {
                // Dynamic usage counter with placeholder replacement using current language
                const used = element.dataset.used || '0';
                const total = element.dataset.total || '3';

                // Use localized numbers if localizeNumber function is available
                const localizedUsed = (typeof localizeNumber === 'function') ?
                    localizeNumber(parseInt(used), currentLanguage) : used;
                const localizedTotal = (typeof localizeNumber === 'function') ?
                    localizeNumber(parseInt(total), currentLanguage) : total;

                element.textContent = translations[currentLanguage][key]
                    .replace('{{used}}', localizedUsed)
                    .replace('{{total}}', localizedTotal);
            } else {
                element.textContent = translations[currentLanguage][key];
            }
        }
    });

    // Update placeholders
    const placeholders = document.querySelectorAll('[data-translate-placeholder]');
    placeholders.forEach(element => {
        const key = element.getAttribute('data-translate-placeholder');
        if (translations[currentLanguage] && translations[currentLanguage][key]) {
            element.placeholder = translations[currentLanguage][key];
        }
    });

    // Update page title
    updatePageTitle();
}

// Initialize translation system when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    loadLanguagePreference();
    console.log('[Language System] Initialized with language:', currentLanguage);
});

// Close language dropdown when clicking outside
document.addEventListener('click', function(event) {
    const dropdown = document.getElementById('languageDropdown');
    const toggle = document.getElementById('languageToggle');
    if (dropdown && toggle && !toggle.contains(event.target) && !dropdown.contains(event.target)) {
        dropdown.style.display = 'none';
    }
});