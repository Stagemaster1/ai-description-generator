        // Token manager and secure cookie manager are loaded from external files

        // Initialize token management with automatic refresh monitoring
        function initializeTokenManager() {
            const auth = window.firebaseAuth;
            if (!auth) {
                console.warn('Firebase Auth not available for token management');
                return;
            }

            // Monitor authentication state changes
            auth.onAuthStateChanged(async (user) => {
                if (user) {
                    console.log('User authenticated - initializing token management');
                    try {
                        await window.tokenManager.getToken();

                        // Initialize secure cookies for authenticated user
                        try {
                            await window.secureCookieManager.initializeSecureCookies();
                        } catch (error) {
                            console.error('Failed to initialize secure cookies for authenticated user:', error);
                        }

                        // Update user info display
                        updateUserInfo();

                        // Check if user has verified email and needs to choose plan
                        if (user.emailVerified) {
                            console.log('Email verified - checking if user needs to choose plan');

                            // Check if user already has a plan (exists in Firestore)
                            const hasExistingPlan = await checkUserHasPlan(user.uid);

                            if (hasExistingPlan) {
                                // User already chose a plan, redirect accordingly
                                console.log('User has existing plan, redirecting...');
                                const validatedReturnUrl = getValidatedReturnUrl();
                                sessionStorage.removeItem('auth_return_url');
                                window.location.href = validatedReturnUrl;
                            } else {
                                // New verified user - show plan choice modal
                                console.log('New verified user - showing plan choice modal');
                                showPlanChoiceModal();
                            }
                        } else {
                            showMessage('Please verify your email address before continuing.', 'warning');
                        }
                    } catch (error) {
                        console.error('Token management initialization failed:', error);
                    }
                } else {
                    console.log('User signed out - clearing token cache and cookies');
                    window.tokenManager.clearToken();
                    window.secureCookieManager.clearAllCookies();
                    updateUserInfo();
                }
            });

            // Monitor token refresh events
            auth.onIdTokenChanged(async (user) => {
                if (user) {
                    try {
                        await window.tokenManager.getToken();
                    } catch (error) {
                        console.error('Token refresh monitoring failed:', error);
                    }
                }
            });
        }

        // Notification system for user feedback
        function showNotification(message, type = 'success') {
            // Remove existing notification if any
            const existingNotification = document.querySelector('.notification');
            if (existingNotification) {
                existingNotification.remove();
            }

            // Create new notification
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.textContent = message;

            document.body.appendChild(notification);

            // Auto-remove after 5 seconds
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 5000);
        }

        // Show form messages
        function showMessage(message, type = 'info') {
            const messageArea = document.getElementById('messageArea');
            messageArea.innerHTML = `<div class="message ${type}">${message}</div>`;
        }

        // Clear form messages
        function clearMessage() {
            const messageArea = document.getElementById('messageArea');
            messageArea.innerHTML = '';
        }

        // Field validation functions
        function showFieldError(fieldId, message) {
            const errorElement = document.getElementById(fieldId + 'Error');
            const inputElement = document.getElementById(fieldId);

            if (errorElement && inputElement) {
                errorElement.textContent = message;
                errorElement.classList.add('show');
                inputElement.classList.add('error');
                inputElement.classList.remove('success');
            }
        }

        function clearFieldError(fieldId) {
            const errorElement = document.getElementById(fieldId + 'Error');
            const inputElement = document.getElementById(fieldId);

            if (errorElement && inputElement) {
                errorElement.classList.remove('show');
                inputElement.classList.remove('error');
            }
        }

        function showFieldSuccess(fieldId) {
            const inputElement = document.getElementById(fieldId);
            if (inputElement) {
                inputElement.classList.add('success');
                inputElement.classList.remove('error');
            }
        }

        // Email validation
        function validateEmail(email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return emailRegex.test(email);
        }

        // Password strength validation
        function validatePasswordStrength(password) {
            const checks = {
                length: password.length >= 8,
                uppercase: /[A-Z]/.test(password),
                lowercase: /[a-z]/.test(password),
                number: /\d/.test(password),
                special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
            };

            const passedChecks = Object.values(checks).filter(Boolean).length;

            let strength = 'weak';
            if (passedChecks >= 4) strength = 'strong';
            else if (passedChecks >= 3) strength = 'good';
            else if (passedChecks >= 2) strength = 'fair';

            return { strength, checks, score: passedChecks };
        }

        // Update password strength indicator
        function updatePasswordStrength(password) {
            const strengthIndicator = document.getElementById('passwordStrength');
            const strengthFill = document.getElementById('strengthFill');
            const strengthText = document.getElementById('strengthText');

            if (!password) {
                strengthIndicator.classList.remove('show');
                return;
            }

            const result = validatePasswordStrength(password);
            strengthIndicator.classList.add('show');

            // Update strength bar
            strengthFill.className = `strength-fill ${result.strength}`;

            // Update strength text
            const strengthLabels = {
                weak: 'Weak',
                fair: 'Fair',
                good: 'Good',
                strong: 'Strong'
            };

            strengthText.textContent = strengthLabels[result.strength];
        }

        // No tab switching needed - signup only page

        // Anti-Abuse System: IP Tracking + Disposable Email Blocking + Signup Cookie
        // NOTE: Cookies only prevent NEW signups, not sign-ins (users can login from any device)
        class AntiAbuseSystem {
            constructor() {
                this.ipAddress = null;
            }

            // Get user's IP address for logging
            async getIPAddress() {
                try {
                    // Use serverless function to get IP
                    const response = await fetch('/.netlify/functions/get-client-ip');
                    const data = await response.json();
                    this.ipAddress = data.ip;
                    return this.ipAddress;
                } catch (error) {
                    console.error('Failed to get IP address:', error);
                    // Fallback: use a third-party service
                    try {
                        const fallbackResponse = await fetch('https://api.ipify.org?format=json');
                        const fallbackData = await fallbackResponse.json();
                        this.ipAddress = fallbackData.ip;
                        return this.ipAddress;
                    } catch (fallbackError) {
                        console.error('Fallback IP fetch failed:', fallbackError);
                        return null;
                    }
                }
            }

            // Check if device already used for signup
            async checkForAbuse(email) {
                try {
                    // Get IP address for logging
                    const ipAddress = await this.getIPAddress();

                    // Check if cookie exists (device already used for signup)
                    if (this.hasSignupCookie()) {
                        return {
                            blocked: true,
                            reason: 'signup_already_used',
                            message: 'This device has already been used to create an account. Please sign in instead.'
                        };
                    }

                    // TODO: Check Firestore for IP abuse patterns (server-side)
                    // For now, return the IP to be stored with user account
                    return {
                        blocked: false,
                        ipAddress: ipAddress
                    };

                } catch (error) {
                    console.error('Anti-abuse check failed:', error);
                    // Allow signup if check fails (don't block legitimate users)
                    return { blocked: false };
                }
            }

            // Set persistent cookie after successful signup
            setSignupCookie() {
                // Cookie expires in 1 year
                const expiryDate = new Date();
                expiryDate.setFullYear(expiryDate.getFullYear() + 1);
                const timestamp = new Date().getTime();

                document.cookie = `soltecsol_signup_used=${timestamp}; expires=${expiryDate.toUTCString()}; path=/; secure; samesite=strict`;
            }

            // Check if signup cookie exists
            hasSignupCookie() {
                return document.cookie.includes('soltecsol_signup_used=');
            }

            // Block disposable email domains
            isDisposableEmail(email) {
                const disposableDomains = [
                    'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
                    'throwaway.email', 'temp-mail.org', 'fakeinbox.com', 'trashmail.com',
                    'yopmail.com', 'maildrop.cc', 'sharklasers.com', 'getnada.com',
                    'tempr.email', 'dispostable.com', 'emailondeck.com', 'mohmal.com'
                ];

                const emailDomain = email.toLowerCase().split('@')[1];
                return disposableDomains.includes(emailDomain);
            }
        }

        // Initialize anti-abuse system
        const antiAbuse = new AntiAbuseSystem();

        // Setup agreement checkbox to enable/disable submit button
        function setupAgreementCheckbox() {
            const checkbox = document.getElementById('agreementCheckbox');
            const submitBtn = document.getElementById('signupSubmit');

            if (checkbox && submitBtn) {
                checkbox.addEventListener('change', () => {
                    submitBtn.disabled = !checkbox.checked;
                });
            }
        }

        // Create Firebase account directly
        async function createFirebaseAccount(email, password, ipAddress) {
            const submitBtn = document.getElementById('signupSubmit');
            const buttonText = document.getElementById('signupButtonText');
            const spinner = document.getElementById('signupSpinner');

            try {
                // Show loading state
                submitBtn.disabled = true;
                buttonText.style.display = 'none';
                spinner.classList.add('show');

                // Create user with Firebase
                const userCredential = await window.firebaseCreateUserWithEmailAndPassword(window.firebaseAuth, email, password);
                const user = userCredential.user;

                // Send email verification
                await window.firebaseSendEmailVerification(user);

                // Set signup cookie to prevent repeat signups from this device
                antiAbuse.setSignupCookie();

                showMessage('Account created! Please check your email to verify your account.', 'success');

                // Reset form
                document.getElementById('signupForm').reset();
                document.getElementById('passwordStrength').classList.remove('show');

                // Re-disable submit button after form reset
                document.getElementById('signupSubmit').disabled = true;

            } catch (error) {
                console.error('Sign up error:', error);

                let errorMessage = 'Failed to create account. Please try again.';

                switch (error.code) {
                    case 'auth/email-already-in-use':
                        errorMessage = 'Email address is already in use';
                        showFieldError('signupEmail', errorMessage);
                        break;
                    case 'auth/weak-password':
                        errorMessage = 'Password is too weak';
                        showFieldError('signupPassword', errorMessage);
                        break;
                    case 'auth/invalid-email':
                        errorMessage = 'Invalid email address';
                        showFieldError('signupEmail', errorMessage);
                        break;
                    default:
                        showMessage(errorMessage, 'error');
                }

            } finally {
                // Reset loading state
                submitBtn.disabled = false;
                buttonText.style.display = 'inline';
                spinner.classList.remove('show');
            }
        }

        // Sign up form handler - now shows ToS modal instead of direct signup
        async function handleSignUp(event) {
            event.preventDefault();

            const email = document.getElementById('signupEmail').value.trim();
            const password = document.getElementById('signupPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;

            // Clear previous errors
            clearMessage();
            clearFieldError('signupEmail');
            clearFieldError('signupPassword');
            clearFieldError('confirmPassword');

            let isValid = true;

            // Validate email
            if (!email) {
                showFieldError('signupEmail', 'Email is required');
                isValid = false;
            } else if (!validateEmail(email)) {
                showFieldError('signupEmail', 'Please enter a valid email address');
                isValid = false;
            } else if (antiAbuse.isDisposableEmail(email)) {
                showFieldError('signupEmail', 'Disposable email addresses are not allowed. Please use a permanent email address.');
                isValid = false;
            } else {
                showFieldSuccess('signupEmail');
            }

            // Validate password
            if (!password) {
                showFieldError('signupPassword', 'Password is required');
                isValid = false;
            } else {
                const strengthResult = validatePasswordStrength(password);
                if (strengthResult.score < 3) {
                    showFieldError('signupPassword', 'Password is too weak');
                    isValid = false;
                } else {
                    showFieldSuccess('signupPassword');
                }
            }

            // Validate password confirmation
            if (!confirmPassword) {
                showFieldError('confirmPassword', 'Please confirm your password');
                isValid = false;
            } else if (password !== confirmPassword) {
                showFieldError('confirmPassword', 'Passwords do not match');
                isValid = false;
            } else {
                showFieldSuccess('confirmPassword');
            }

            if (!isValid) {
                return;
            }

            // Anti-abuse check
            const abuseCheck = await antiAbuse.checkForAbuse(email);
            if (abuseCheck.blocked) {
                showMessage(abuseCheck.message, 'error');
                return;
            }

            // Create Firebase account directly (ToS/GDPR already agreed via checkbox)
            await createFirebaseAccount(email, password, abuseCheck.ipAddress);
        }

        // Sign in moved to login.html - signup page is signup-only

        // Update user info display
        function updateUserInfo() {
            try {
                const auth = window.firebaseAuth;
                const userInfoDiv = document.getElementById('userInfo');

                if (auth && auth.currentUser && userInfoDiv) {
                    const user = auth.currentUser;
                    userInfoDiv.innerHTML = `
                        <strong>User:</strong> ${user.email}
                        ${user.emailVerified ? '✓' : '❌'}
                        <span style="margin-left: 0.5rem; font-size: 0.75rem;">${user.uid.substring(0, 8)}</span>
                    `;
                    userInfoDiv.style.display = 'block';
                } else if (userInfoDiv) {
                    userInfoDiv.style.display = 'none';
                }
            } catch (error) {
                console.error('Failed to update user info:', error);
            }
        }

        // Language is handled globally by plyvo.js universal translation system

        // Enhanced error handling with user-friendly messages
        window.addEventListener('error', function(event) {
            console.error('Global error:', event.error);
            if (typeof showNotification === 'function') {
                showNotification('An unexpected error occurred. Please refresh the page.', 'error');
            }
        });

        window.addEventListener('unhandledrejection', function(event) {
            console.error('Unhandled promise rejection:', event.reason);
            if (typeof showNotification === 'function') {
                showNotification('An unexpected error occurred. Please try again.', 'error');
            }
        });

        // Initialize everything when DOM is ready and Firebase is available
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize cross-subdomain language system
            initializeLanguageSystem();

            // Setup form event listeners
            const signupForm = document.getElementById('signupForm');
            const signupPassword = document.getElementById('signupPassword');

            if (signupForm) {
                signupForm.addEventListener('submit', handleSignUp);
            }

            if (signupPassword) {
                signupPassword.addEventListener('input', (e) => {
                    updatePasswordStrength(e.target.value);
                });
            }

            // Setup agreement checkbox handler
            setupAgreementCheckbox();

            // Wait for Firebase to be ready
            if (window.firebaseAuth) {
                initializeInfrastructure();
            } else {
                window.addEventListener('firebaseReady', initializeInfrastructure);
            }
        });

        async function initializeInfrastructure() {
            try {
                console.log('Initializing signup page infrastructure...');

                // Initialize token management
                initializeTokenManager();

                // Update user info display
                await updateUserInfo();

                console.log('Signup page infrastructure initialized successfully');

            } catch (error) {
                console.error('Infrastructure initialization failed:', error);
                showNotification('Service initialization failed. Please refresh the page.', 'error');
            }
        }

        // SECURITY ENHANCEMENT: Secure URL validation function
        function getValidatedReturnUrl() {
            // Check secure sessionStorage first, then URL parameters
            let returnUrl = getSecureSessionData('soltecsol_auth_return_url');
            if (!returnUrl) {
                const urlParams = new URLSearchParams(window.location.search);
                returnUrl = urlParams.get('return_to') || urlParams.get('returnUrl');
            }

            // Default to app if no return URL
            returnUrl = returnUrl || 'https://app.soltecsol.com';

            // Enhanced security validation for return URLs
            try {
                // Decode URL first to handle encoded attacks
                const decodedUrl = decodeURIComponent(returnUrl);
                const url = new URL(decodedUrl);

                // Strict validation rules
                const allowedDomains = ['app.soltecsol.com', 'www.soltecsol.com', 'soltecsol.com', 'subscriptions.soltecsol.com', 'signup.soltecsol.com'];
                const isValidDomain = allowedDomains.includes(url.hostname);
                const isHttps = url.protocol === 'https:';
                const hasNoUserInfo = !url.username && !url.password;
                const isSafePath = !decodedUrl.includes('javascript:') && !decodedUrl.includes('data:') && !decodedUrl.includes('vbscript:');

                if (isValidDomain && isHttps && hasNoUserInfo && isSafePath) {
                    // Additional path validation - no directory traversal or suspicious patterns
                    const suspiciousPatterns = ['../', '.\\', '%2e%2e', '%5c', '\\'];
                    const hasSuspiciousPattern = suspiciousPatterns.some(pattern =>
                        decodedUrl.toLowerCase().includes(pattern)
                    );

                    if (!hasSuspiciousPattern) {
                        return decodedUrl;
                    }
                }

                console.warn('Invalid return URL blocked:', decodedUrl);
                return 'https://app.soltecsol.com';

            } catch (error) {
                console.warn('Return URL validation error:', error.message);
                return 'https://app.soltecsol.com';
            }
        }

        // SECURITY ENHANCEMENT: Secure sessionStorage management
        function setSecureSessionData(key, value) {
            try {
                // Validate key naming convention
                if (!key.startsWith('soltecsol_') || key.includes('<script') || key.includes('javascript:')) {
                    console.error('Invalid session key rejected:', key);
                    return false;
                }

                // Validate value content
                if (typeof value === 'string' && (value.includes('<script') || value.includes('javascript:') || value.includes('data:'))) {
                    console.error('Suspicious session value rejected');
                    return false;
                }

                // Store with expiration timestamp
                const data = {
                    value: value,
                    expires: Date.now() + (60 * 60 * 1000) // 1 hour
                };

                sessionStorage.setItem(key, JSON.stringify(data));
                return true;

            } catch (error) {
                console.error('Failed to set secure session data:', error);
                return false;
            }
        }

        function getSecureSessionData(key) {
            try {
                const stored = sessionStorage.getItem(key);
                if (!stored) return null;

                const data = JSON.parse(stored);

                // Check expiration
                if (Date.now() > data.expires) {
                    sessionStorage.removeItem(key);
                    return null;
                }

                return data.value;

            } catch (error) {
                console.error('Failed to get secure session data:', error);
                sessionStorage.removeItem(key); // Remove corrupted data
                return null;
            }
        }

        // Utility function to handle URL parameters securely
        function handleUrlParams() {
            const urlParams = new URLSearchParams(window.location.search);

            // Handle email verification
            const verified = urlParams.get('verified');
            if (verified === 'true') {
                showNotification('Email verified successfully! You can now sign in.', 'success');
                // Clean up URL
                window.history.replaceState({}, document.title, window.location.pathname);
                // Switch to sign in tab
                document.querySelector('[data-tab="signin"]').click();
                return;
            }

            // SESSION 3C: Handle tab parameter for direct navigation - validate input
            const tabParam = urlParams.get('tab');
            if (tabParam && /^[a-z]+$/.test(tabParam) && ['signin', 'signup'].includes(tabParam)) {
                // Switch to specified tab if valid
                setTimeout(() => {
                    const tabButton = document.querySelector(`[data-tab="${tabParam}"]`);
                    if (tabButton) {
                        tabButton.click();
                    }
                }, 100); // Small delay to ensure tabs are initialized
            }

            // Store return URL securely after validation
            const returnUrl = urlParams.get('return_to') || urlParams.get('returnUrl');
            if (returnUrl) {
                // Pre-validate the URL before storing
                try {
                    const decodedUrl = decodeURIComponent(returnUrl);
                    const url = new URL(decodedUrl);
                    const allowedDomains = ['app.soltecsol.com', 'www.soltecsol.com', 'soltecsol.com', 'subscriptions.soltecsol.com', 'signup.soltecsol.com'];

                    if (allowedDomains.includes(url.hostname) && url.protocol === 'https:') {
                        setSecureSessionData('soltecsol_auth_return_url', decodedUrl);
                    } else {
                        console.warn('Invalid return URL parameter rejected:', decodedUrl);
                    }
                } catch (error) {
                    console.warn('Malformed return URL parameter rejected:', returnUrl);
                }
            }
        }

        // Handle URL parameters when page loads
        handleUrlParams();

        // Check if user already has a plan in Firestore
        async function checkUserHasPlan(userId) {
            try {
                // Get Firebase ID token for authentication
                const token = await window.tokenManager.getToken();

                // Call serverless function to check Firestore
                const response = await fetch(`/.netlify/functions/check-user-status?userId=${userId}`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });

                if (!response.ok) {
                    if (response.status === 404) {
                        // User not found in Firestore - needs to choose plan
                        return false;
                    }
                    throw new Error(`Failed to check user status: ${response.statusText}`);
                }

                const result = await response.json();
                console.log('User status check result:', result);

                // User exists in either Users or users collection
                return result.exists === true;

            } catch (error) {
                console.error('Error checking user plan:', error);
                // On error, assume user needs to choose plan to be safe
                return false;
            }
        }

        // Show plan choice modal
        function showPlanChoiceModal() {
            const modal = document.getElementById('planChoiceModal');
            if (modal) {
                modal.style.display = 'flex';
                console.log('Plan choice modal displayed');
            } else {
                console.error('Plan choice modal not found in DOM');
            }
        }

        // Handle trial choice
        async function chooseTrial() {
            try {
                console.log('User chose trial plan');

                const modal = document.getElementById('planChoiceModal');
                modal.style.display = 'none';

                // Show loading message
                showMessage('Creating your trial account...', 'info');

                // Get Firebase ID token
                const token = await window.tokenManager.getToken();

                // Call serverless function to create trial user in Firestore
                const response = await fetch('/.netlify/functions/create-trial-user', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({
                        ipAddress: antiAbuse.ipAddress || 'unknown'
                    })
                });

                if (!response.ok) {
                    throw new Error(`Failed to create trial user: ${response.statusText}`);
                }

                const result = await response.json();
                console.log('Trial user created:', result);

                showMessage('Trial account activated! Redirecting to app...', 'success');

                // Redirect to app after 2 seconds
                setTimeout(() => {
                    window.location.href = 'https://app.soltecsol.com';
                }, 2000);

            } catch (error) {
                console.error('Error creating trial account:', error);
                showMessage('Failed to activate trial. Please try again or contact support.', 'error');
                // Show modal again
                document.getElementById('planChoiceModal').style.display = 'flex';
            }
        }

        // Handle subscribe choice
        function chooseSubscribe() {
            console.log('User chose to subscribe');
            showMessage('Redirecting to subscription page...', 'info');
            setTimeout(() => {
                window.location.href = 'https://subscriptions.soltecsol.com';
            }, 1000);
        }

        // Make functions globally accessible for onclick handlers
        window.chooseTrial = chooseTrial;
        window.chooseSubscribe = chooseSubscribe;

        // Initialize cross-subdomain language system
        function initializeLanguageSystem() {
            try {
                console.log('Initializing cross-subdomain language system for signup page...');

                // Check if plyvo.js loaded successfully
                if (typeof window.updateLanguageUniversal !== 'function') {
                    console.error('plyvo.js not loaded - language system unavailable');
                    return;
                }

                if (typeof window.CrossSubdomainLanguage === 'undefined') {
                    console.error('CrossSubdomainLanguage not available');
                    return;
                }

                // Get language from cross-subdomain cookie (set by landing page)
                let preferredLang = window.CrossSubdomainLanguage.getCookie();
                console.log('Language from cross-subdomain cookie:', preferredLang);

                // Fallback to URL parameter
                if (!preferredLang) {
                    const urlParams = new URLSearchParams(window.location.search);
                    preferredLang = urlParams.get('lang');
                    console.log('Language from URL parameter:', preferredLang);
                }

                // Fallback to localStorage
                if (!preferredLang) {
                    preferredLang = localStorage.getItem('preferredLanguage');
                    console.log('Language from localStorage:', preferredLang);
                }

                // Apply language using universal system
                if (preferredLang && window.translations && window.translations[preferredLang]) {
                    console.log('Applying language:', preferredLang);
                    window.updateLanguageUniversal(preferredLang);
                } else {
                    console.log('Defaulting to English');
                    window.updateLanguageUniversal('en');
                }

                console.log('Cross-subdomain language system initialized successfully');

            } catch (error) {
                console.error('Language system initialization failed:', error);
                // Fallback to English on error
                if (typeof window.updateLanguageUniversal === 'function') {
                    window.updateLanguageUniversal('en');
                }
            }
        }

