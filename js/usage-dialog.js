// SESSION 3: Usage Limit Dialog System
// Fix based on Security Auditor finding #20250928_1015 - Externalize embedded script for CSP compliance
// Fix based on Visual Integrity Enforcer finding #20250928_1015 - Preserve dialog styling and behavior

// Show usage limit dialog with subscription guidance
function showUsageLimitDialog(errorMessage) {
    const dialog = document.createElement('div');
    dialog.className = 'usage-limit-dialog-overlay';
    dialog.innerHTML = `
        <div class="usage-limit-dialog">
            <div class="dialog-header">
                <h3>⚡ Usage Limit Reached</h3>
                <button class="dialog-close" data-close-dialog aria-label="Close">×</button>

            </div>
            <div class="dialog-body">
                <p class="error-message">${errorMessage}</p>
                <p class="upgrade-message">Upgrade to unlock unlimited AI-generated descriptions and boost your e-commerce success!</p>
                <div class="dialog-actions">
                    <a href="https://subscriptions.soltecsol.com" target="_blank" class="upgrade-btn">
                        💳 View Subscription Plans
                    </a>
                    <button class="dialog-close-btn" data-close-dialog="true">
                        Maybe Later
                    </button>
                </div>
            </div>
        </div>
    `;

    // Add dialog styles if not already present
    if (!document.getElementById('usage-limit-dialog-styles')) {
        const styles = document.createElement('style');
        styles.id = 'usage-limit-dialog-styles';
        styles.textContent = `
            .usage-limit-dialog-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                backdrop-filter: blur(5px);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 10000;
                animation: fadeIn 0.3s ease;
            }
            .usage-limit-dialog {
                background: white;
                border-radius: 16px;
                max-width: 500px;
                width: 90%;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                overflow: hidden;
                animation: slideUp 0.3s ease;
            }
            .dialog-header {
                background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                color: white;
                padding: 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .dialog-header h3 {
                margin: 0;
                font-size: 1.2rem;
            }
            .dialog-close {
                background: none;
                border: none;
                color: white;
                font-size: 24px;
                cursor: pointer;
                width: 30px;
                height: 30px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: background 0.2s ease;
            }
            .dialog-close:hover {
                background: rgba(255, 255, 255, 0.2);
            }
            .dialog-body {
                padding: 30px;
                text-align: center;
            }
            .error-message {
                color: #e74c3c;
                font-weight: 600;
                margin-bottom: 15px;
            }
            .upgrade-message {
                color: #2c3e50;
                margin-bottom: 25px;
                line-height: 1.5;
            }
            .dialog-actions {
                display: flex;
                gap: 15px;
                justify-content: center;
                flex-wrap: wrap;
            }
            .upgrade-btn {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 12px 24px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 600;
                transition: transform 0.2s ease, box-shadow 0.2s ease;
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }
            .upgrade-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
            }
            .dialog-close-btn {
                background: #95a5a6;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                transition: background 0.2s ease;
            }
            .dialog-close-btn:hover {
                background: #7f8c8d;
            }
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            @keyframes slideUp {
                from { transform: translateY(50px); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }
        `;
        document.head.appendChild(styles);
    }

    document.body.appendChild(dialog);

    // Close on outside click
    dialog.addEventListener('click', (e) => {
        if (e.target === dialog) {
            dialog.remove();
        }
    });
}