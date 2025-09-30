// SESSION 31: Usage Counter Native Number System Fix
// Ensures currentLanguage binding with native numerals for non-Latin locales

// Localize numbers to native scripts
function localizeNumber(number, lang) {
    const numStr = number.toString();

    // Native numeral mappings for non-Latin locales
    const numeralMaps = {
        'ar': ['٠', '١', '٢', '٣', '٤', '٥', '٦', '٧', '٨', '٩'], // Arabic-Indic digits
        'hi': ['०', '१', '२', '३', '४', '५', '६', '७', '८', '९'], // Devanagari digits
        'ja': ['〇', '一', '二', '三', '四', '五', '六', '七', '八', '九'], // Japanese numerals
        'zh': ['〇', '一', '二', '三', '四', '五', '六', '七', '八', '九'], // Chinese numerals
        'ko': ['영', '일', '이', '삼', '사', '오', '육', '칠', '팔', '구'], // Korean numerals
        'ru': number => {
            // Russian text numbers for small values
            const ruNumbers = ['ноль', 'один', 'два', 'три', 'четыре', 'пять', 'шесть', 'семь', 'восемь', 'девять'];
            return ruNumbers[number] || number.toString();
        }
    };

    if (numeralMaps[lang]) {
        if (typeof numeralMaps[lang] === 'function') {
            return numeralMaps[lang](number);
        } else {
            return numStr.split('').map(digit => numeralMaps[lang][parseInt(digit)] || digit).join('');
        }
    }

    return numStr; // Default to Western numerals for Latin-script languages
}

function updateUsageCounter(used, total) {
    const usageElement = document.getElementById('usageText');
    if (usageElement) {
        // Store values in data attributes
        usageElement.dataset.used = used.toString();
        usageElement.dataset.total = total.toString();

        // Ensure currentLanguage is set
        const lang = window.currentLanguage || currentLanguage || 'en';

        // Update with current language using translations object - NO FALLBACK
        if (translations[lang] && translations[lang]['usageCounterText']) {
            // Localize numbers to native scripts
            const localizedUsed = localizeNumber(used, lang);
            const localizedTotal = localizeNumber(total, lang);

            usageElement.textContent = translations[lang]['usageCounterText']
                .replace('{{used}}', localizedUsed)
                .replace('{{total}}', localizedTotal);
        }
    }
}

// Initialize usage counter on page load
document.addEventListener('DOMContentLoaded', function() {
    // Wait for language system to initialize
    setTimeout(() => {
        updateUsageCounter(0, 3);
    }, 100);
});