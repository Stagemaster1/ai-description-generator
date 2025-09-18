// CSP Nonce Generator - For Secure Inline Content
// Generates cryptographically secure nonces for CSP compliance

class CSPNonceManager {
    constructor() {
        this.currentNonce = null;
        this.nonceLength = 16; // 128-bit nonce
    }

    // Generate cryptographically secure nonce
    generateNonce() {
        const array = new Uint8Array(this.nonceLength);
        crypto.getRandomValues(array);
        const nonce = btoa(String.fromCharCode.apply(null, array))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        this.currentNonce = nonce;
        return nonce;
    }

    // Get current nonce, generate if not exists
    getCurrentNonce() {
        if (!this.currentNonce) {
            return this.generateNonce();
        }
        return this.currentNonce;
    }

    // Apply nonce to inline script elements
    applyNonceToInlineScripts() {
        const nonce = this.getCurrentNonce();
        const inlineScripts = document.querySelectorAll('script:not([src]):not([nonce])');

        inlineScripts.forEach(script => {
            script.setAttribute('nonce', nonce);
        });

        return nonce;
    }

    // Apply nonce to inline style elements
    applyNonceToInlineStyles() {
        const nonce = this.getCurrentNonce();
        const inlineStyles = document.querySelectorAll('style:not([nonce])');

        inlineStyles.forEach(style => {
            style.setAttribute('nonce', nonce);
        });

        return nonce;
    }

    // Generate and set CSP meta tag with nonce
    updateCSPMetaWithNonce(existingCSP = '') {
        const nonce = this.getCurrentNonce();

        // Update script-src to include nonce instead of unsafe-inline
        let updatedCSP = existingCSP.replace(/'unsafe-inline'/g, '');

        // Add nonce to script-src
        if (updatedCSP.includes('script-src')) {
            updatedCSP = updatedCSP.replace(
                /script-src ([^;]+)/,
                `script-src $1 'nonce-${nonce}'`
            );
        }

        // Add nonce to style-src
        if (updatedCSP.includes('style-src')) {
            updatedCSP = updatedCSP.replace(
                /style-src ([^;]+)/,
                `style-src $1 'nonce-${nonce}'`
            );
        }

        // Clean up any double spaces or semicolons
        updatedCSP = updatedCSP.replace(/\s+/g, ' ').replace(/;\s*;/g, ';').trim();

        return updatedCSP;
    }

    // Initialize nonce system for the current page
    initializeNonceSystem() {
        const nonce = this.generateNonce();

        // Apply nonces to existing inline content
        this.applyNonceToInlineScripts();
        this.applyNonceToInlineStyles();

        console.log('CSP Nonce system initialized with nonce:', nonce);
        return nonce;
    }
}

// Global CSP nonce manager
window.cspNonceManager = new CSPNonceManager();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.cspNonceManager.initializeNonceSystem();
    });
} else {
    window.cspNonceManager.initializeNonceSystem();
}