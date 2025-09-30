        // SECURITY ENHANCEMENT: Centralized Firebase token management
        class FirebaseTokenManager {
            constructor() {
                this.currentToken = null;
                this.tokenRefreshThreshold = 300000; // 5 minutes before expiry
                this.refreshTimer = null;
                this.tokenListeners = new Set();
            }

            // Get current valid token, refreshing if needed
            async getValidToken() {
                try {
                    const auth = window.firebaseAuth;
                    if (!auth || !auth.currentUser) {
                        this.clearToken();
                        return null;
                    }

                    // Get token with force refresh if close to expiry
                    const forceRefresh = this.shouldForceRefresh();
                    const token = await auth.currentUser.getIdToken(forceRefresh);

                    this.currentToken = token;
                    this.scheduleTokenRefresh();
                    this.notifyTokenListeners(token);

                    return token;

                } catch (error) {
                    console.error('Token refresh failed:', error);
                    this.clearToken();
                    throw error;
                }
            }

            // Check if token should be force refreshed
            shouldForceRefresh() {
                if (!this.currentToken) return true;

                try {
                    const payload = JSON.parse(atob(this.currentToken.split('.')[1]));
                    const expiry = payload.exp * 1000;
                    const timeToExpiry = expiry - Date.now();

                    return timeToExpiry < this.tokenRefreshThreshold;
                } catch (error) {
                    console.warn('Token validation failed:', error);
                    return true;
                }
            }

            // Schedule automatic token refresh
            scheduleTokenRefresh() {
                if (this.refreshTimer) {
                    clearTimeout(this.refreshTimer);
                }

                if (!this.currentToken) return;

                try {
                    const payload = JSON.parse(atob(this.currentToken.split('.')[1]));
                    const expiry = payload.exp * 1000;
                    const refreshTime = expiry - Date.now() - this.tokenRefreshThreshold;

                    if (refreshTime > 0) {
                        this.refreshTimer = setTimeout(() => {
                            this.getValidToken().catch(error => {
                                console.error('Scheduled token refresh failed:', error);
                            });
                        }, refreshTime);
                    }
                } catch (error) {
                    console.warn('Token refresh scheduling failed:', error);
                }
            }

            // Clear cached token and timers
            clearToken() {
                this.currentToken = null;
                if (this.refreshTimer) {
                    clearTimeout(this.refreshTimer);
                    this.refreshTimer = null;
                }
                this.notifyTokenListeners(null);
            }

            // Add token change listener
            addTokenListener(callback) {
                this.tokenListeners.add(callback);
            }

            // Remove token change listener
            removeTokenListener(callback) {
                this.tokenListeners.delete(callback);
            }

            // Notify all listeners of token changes
            notifyTokenListeners(token) {
                this.tokenListeners.forEach(callback => {
                    try {
                        callback(token);
                    } catch (error) {
                        console.error('Token listener error:', error);
                    }
                });
            }
        }

        // SECURITY ENHANCEMENT: Secure Cookie Manager for enhanced security
        class SecureCookieManager {
            constructor() {
                this.cookieSettings = {
                    secure: true,
                    sameSite: 'Strict',
                    httpOnly: false, // Can't be httpOnly for client-side access
                    maxAge: 3600 // 1 hour
                };
            }

            // Set a secure cookie with enhanced security settings
            setCookie(name, value, options = {}) {
                try {
                    const settings = { ...this.cookieSettings, ...options };
                    let cookieString = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;

                    if (settings.maxAge) {
                        cookieString += `; Max-Age=${settings.maxAge}`;
                    }

                    if (settings.path) {
                        cookieString += `; Path=${settings.path}`;
                    }

                    if (settings.domain) {
                        cookieString += `; Domain=${settings.domain}`;
                    }

                    if (settings.secure && window.location.protocol === 'https:') {
                        cookieString += '; Secure';
                    }

                    if (settings.sameSite) {
                        cookieString += `; SameSite=${settings.sameSite}`;
                    }

                    document.cookie = cookieString;
                    return true;

                } catch (error) {
                    console.error('Failed to set secure cookie:', error);
                    return false;
                }
            }

            // Get cookie value
            getCookie(name) {
                try {
                    const encodedName = encodeURIComponent(name);
                    const cookies = document.cookie.split(';');

                    for (const cookie of cookies) {
                        const [cookieName, cookieValue] = cookie.trim().split('=');
                        if (cookieName === encodedName) {
                            return decodeURIComponent(cookieValue);
                        }
                    }

                    return null;

                } catch (error) {
                    console.error('Failed to get cookie:', error);
                    return null;
                }
            }

            // Delete cookie
            deleteCookie(name, options = {}) {
                try {
                    const settings = { ...options, maxAge: 0, expires: 'Thu, 01 Jan 1970 00:00:00 UTC' };
                    this.setCookie(name, '', settings);
                    return true;

                } catch (error) {
                    console.error('Failed to delete cookie:', error);
                    return false;
                }
            }

            // Initialize secure cookies for authenticated sessions
            async initializeSecureCookies() {
                try {
                    const auth = window.firebaseAuth;
                    if (!auth || !auth.currentUser) {
                        console.log('No authenticated user for cookie initialization');
                        return false;
                    }

                    // Get fresh Firebase token
                    const token = await window.tokenManager.getValidToken();
                    if (!token) {
                        throw new Error('Failed to get valid authentication token');
                    }

                    // Set authentication cookie
                    const authSuccess = this.setCookie('soltecsol_auth_token', token, {
                        path: '/',
                        maxAge: 3600,
                        secure: window.location.protocol === 'https:',
                        sameSite: 'Strict'
                    });

                    // Generate and set CSRF token
                    const csrfToken = this.generateCSRFToken();
                    const csrfSuccess = this.setCookie('soltecsol_csrf_token', csrfToken, {
                        path: '/',
                        maxAge: 3600,
                        secure: window.location.protocol === 'https:',
                        sameSite: 'Strict'
                    });

                    // Set session identifier
                    const sessionId = this.generateSessionId();
                    const sessionSuccess = this.setCookie('soltecsol_session_id', sessionId, {
                        path: '/',
                        maxAge: 3600,
                        secure: window.location.protocol === 'https:',
                        sameSite: 'Strict'
                    });

                    const allSuccess = authSuccess && csrfSuccess && sessionSuccess;
                    console.log(`Secure cookies initialized: ${allSuccess ? 'SUCCESS' : 'PARTIAL/FAILED'}`);

                    return allSuccess;

                } catch (error) {
                    console.error('Secure cookie initialization failed:', error);
                    return false;
                }
            }

            // Generate CSRF token
            generateCSRFToken() {
                const array = new Uint8Array(32);
                window.crypto.getRandomValues(array);
                return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
            }

            // Generate session identifier
            generateSessionId() {
                const timestamp = Date.now().toString(36);
                const randomBytes = new Uint8Array(16);
                window.crypto.getRandomValues(randomBytes);
                const randomString = Array.from(randomBytes, byte => byte.toString(36)).join('');
                return `${timestamp}_${randomString}`;
            }

            // Clear all authentication-related cookies
            clearAllCookies() {
                try {
                    this.deleteCookie('soltecsol_auth_token', { path: '/' });
                    this.deleteCookie('soltecsol_csrf_token', { path: '/' });
                    this.deleteCookie('soltecsol_session_id', { path: '/' });
                    console.log('All secure cookies cleared');
                    return true;

                } catch (error) {
                    console.error('Failed to clear secure cookies:', error);
                    return false;
                }
            }
        }

        // Global instances
        window.tokenManager = new FirebaseTokenManager();
        window.secureCookieManager = new SecureCookieManager();

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
                        await window.tokenManager.getValidToken();

                        // Initialize secure cookies for authenticated user
                        try {
                            await window.secureCookieManager.initializeSecureCookies();
                        } catch (error) {
                            console.error('Failed to initialize secure cookies for authenticated user:', error);
                        }

                        // Update user info display
                        updateUserInfo();

                        // Redirect to app on successful authentication with secure return URL handling
                        if (user.emailVerified) {
                            showNotification('Sign in successful! Redirecting...', 'success');
                            setTimeout(() => {
                                // Get and validate return URL securely
                                const validatedReturnUrl = getValidatedReturnUrl();

                                // Clear stored return URL before redirect
                                sessionStorage.removeItem('auth_return_url');
                                window.location.href = validatedReturnUrl;
                            }, 2000);
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
                        await window.tokenManager.getValidToken();
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
                weak: translations[currentLanguage]?.passwordWeak || 'Weak',
                fair: translations[currentLanguage]?.passwordFair || 'Fair',
                good: translations[currentLanguage]?.passwordGood || 'Good',
                strong: translations[currentLanguage]?.passwordStrong || 'Strong'
            };

            strengthText.textContent = strengthLabels[result.strength];
        }

        // No tab switching needed - signup only page

        // Modal Management
        let signupData = null; // Store signup data temporarily

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

        // Load ToS content
        async function loadTosContent() {
            try {
                const response = await fetch('tos.html');
                const html = await response.text();

                // Extract body content from tos.html
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const body = doc.body;

                document.getElementById('tosContent').innerHTML = body.innerHTML || '<p>Terms of Service content</p>';
            } catch (error) {
                console.error('Failed to load ToS:', error);
                document.getElementById('tosContent').innerHTML = '<p>Failed to load Terms of Service. Please contact support.</p>';
            }
        }

        // Load DPA content
        async function loadDpaContent() {
            try {
                const response = await fetch('dpa.html');
                const html = await response.text();

                // Extract body content from dpa.html
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const body = doc.body;

                document.getElementById('dpaContent').innerHTML = body.innerHTML || '<p>Data Protection Agreement content</p>';
            } catch (error) {
                console.error('Failed to load DPA:', error);
                document.getElementById('dpaContent').innerHTML = '<p>Failed to load Data Protection Agreement. Please contact support.</p>';
            }
        }

        // Show ToS Modal
        function showTosModal() {
            const modal = document.getElementById('tosModal');
            modal.style.display = 'flex';
            loadTosContent();
        }

        // Hide ToS Modal
        function hideTosModal() {
            const modal = document.getElementById('tosModal');
            modal.style.display = 'none';
        }

        // Show DPA Modal
        function showDpaModal() {
            const modal = document.getElementById('dpaModal');
            modal.style.display = 'flex';
            loadDpaContent();
        }

        // Hide DPA Modal
        function hideDpaModal() {
            const modal = document.getElementById('dpaModal');
            modal.style.display = 'none';
        }

        // Setup ToS checkbox handler
        function setupTosCheckbox() {
            const checkbox = document.getElementById('tosCheckbox');
            const continueBtn = document.getElementById('tosContinue');

            checkbox.addEventListener('change', () => {
                continueBtn.disabled = !checkbox.checked;
            });

            continueBtn.addEventListener('click', () => {
                if (checkbox.checked) {
                    hideTosModal();
                    showDpaModal();
                }
            });
        }

        // Setup DPA checkbox handler
        function setupDpaCheckbox() {
            const checkbox = document.getElementById('dpaCheckbox');
            const submitBtn = document.getElementById('dpaSubmit');

            checkbox.addEventListener('change', () => {
                submitBtn.disabled = !checkbox.checked;
            });

            submitBtn.addEventListener('click', async () => {
                if (checkbox.checked && signupData) {
                    hideDpaModal();
                    // Now proceed with actual Firebase signup
                    await createFirebaseAccount(signupData);
                }
            });
        }

        // Create Firebase account after both modals accepted
        async function createFirebaseAccount(data) {
            const { email, password } = data;

            const submitBtn = document.getElementById('signupSubmit');
            const buttonText = document.getElementById('signupButtonText');
            const spinner = document.getElementById('signupSpinner');

            try {
                // Show loading state
                submitBtn.disabled = true;
                buttonText.style.display = 'none';
                spinner.style.display = 'inline-block';

                // Create user with Firebase
                const userCredential = await window.firebaseCreateUserWithEmailAndPassword(window.firebaseAuth, email, password);
                const user = userCredential.user;

                // Send email verification
                await window.firebaseSendEmailVerification(user);

                // Set signup cookie to prevent repeat signups from this device
                antiAbuse.setSignupCookie();

                showMessage(translations[currentLanguage]?.verificationEmailSent || 'Account created! Please check your email to verify your account.', 'success');

                // Reset form
                document.getElementById('signupForm').reset();
                document.getElementById('passwordStrength').classList.remove('show');
                signupData = null;

            } catch (error) {
                console.error('Sign up error:', error);

                let errorMessage = translations[currentLanguage]?.signupError || 'Failed to create account. Please try again.';

                switch (error.code) {
                    case 'auth/email-already-in-use':
                        errorMessage = translations[currentLanguage]?.emailInUse || 'Email address is already in use';
                        showFieldError('signupEmail', errorMessage);
                        break;
                    case 'auth/weak-password':
                        errorMessage = translations[currentLanguage]?.passwordWeak || 'Password is too weak';
                        showFieldError('signupPassword', errorMessage);
                        break;
                    case 'auth/invalid-email':
                        errorMessage = translations[currentLanguage]?.emailInvalid || 'Invalid email address';
                        showFieldError('signupEmail', errorMessage);
                        break;
                    default:
                        showMessage(errorMessage, 'error');
                }

            } finally {
                // Reset loading state
                submitBtn.disabled = false;
                buttonText.style.display = 'inline';
                spinner.style.display = 'none';
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
                showFieldError('signupEmail', translations[currentLanguage]?.emailRequired || 'Email is required');
                isValid = false;
            } else if (!validateEmail(email)) {
                showFieldError('signupEmail', translations[currentLanguage]?.emailInvalid || 'Please enter a valid email address');
                isValid = false;
            } else if (antiAbuse.isDisposableEmail(email)) {
                showFieldError('signupEmail', 'Disposable email addresses are not allowed. Please use a permanent email address.');
                isValid = false;
            } else {
                showFieldSuccess('signupEmail');
            }

            // Validate password
            if (!password) {
                showFieldError('signupPassword', translations[currentLanguage]?.passwordRequired || 'Password is required');
                isValid = false;
            } else {
                const strengthResult = validatePasswordStrength(password);
                if (strengthResult.score < 3) {
                    showFieldError('signupPassword', translations[currentLanguage]?.passwordWeak || 'Password is too weak');
                    isValid = false;
                } else {
                    showFieldSuccess('signupPassword');
                }
            }

            // Validate password confirmation
            if (!confirmPassword) {
                showFieldError('confirmPassword', translations[currentLanguage]?.confirmPasswordRequired || 'Please confirm your password');
                isValid = false;
            } else if (password !== confirmPassword) {
                showFieldError('confirmPassword', translations[currentLanguage]?.passwordMismatch || 'Passwords do not match');
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

            // Store signup data temporarily (including IP for Firestore)
            signupData = {
                email,
                password,
                ipAddress: abuseCheck.ipAddress
            };

            // Show ToS modal instead of creating account directly
            showTosModal();
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

        // Internationalization framework with 6 languages
        const translations = {
            en: {
                // Language names
                english: 'English',
                spanish: 'Español',
                french: 'Français',
                german: 'Deutsch',
                italian: 'Italiano',
                portuguese: 'Português',

                // Header
                signupTitle: 'Create Account',
                signupSubtitle: 'Join SolTecSol and unlock AI-powered product description generation',
                backToApp: 'Back to App',

                // Navigation
                signUp: 'Sign Up',
                signIn: 'Sign In',

                // Form labels
                emailLabel: 'Email Address',
                passwordLabel: 'Password',
                confirmPasswordLabel: 'Confirm Password',

                // Placeholders
                emailPlaceholder: 'Enter your email address',
                passwordPlaceholder: 'Create a strong password',
                confirmPasswordPlaceholder: 'Confirm your password',
                signinPasswordPlaceholder: 'Enter your password',

                // Buttons
                createAccount: 'Create Account',
                signInButton: 'Sign In',
                forgotPassword: 'Forgot Password?',

                // Validation messages
                emailRequired: 'Email is required',
                emailInvalid: 'Please enter a valid email address',
                emailInUse: 'Email address is already in use',
                emailNotFound: 'No account found with this email address',
                passwordRequired: 'Password is required',
                confirmPasswordRequired: 'Please confirm your password',
                passwordMismatch: 'Passwords do not match',
                passwordWeak: 'Weak',
                passwordFair: 'Fair',
                passwordGood: 'Good',
                passwordStrong: 'Strong',

                // Status messages
                verificationEmailSent: 'Account created! Please check your email to verify your account.',
                emailNotVerified: 'Please verify your email address before signing in.',
                passwordResetSent: 'Password reset email sent. Please check your inbox.',
                signinSuccess: 'Sign in successful! Redirecting...',

                // Error messages
                signupError: 'Failed to create account. Please try again.',
                signinError: 'Failed to sign in. Please try again.',
                passwordResetError: 'Failed to send password reset email.',
                invalidCredentials: 'Invalid email or password',
                accountDisabled: 'This account has been disabled',
                tooManyRequests: 'Too many failed attempts. Please try again later'
            },
            es: {
                // Language names
                english: 'English',
                spanish: 'Español',
                french: 'Français',
                german: 'Deutsch',
                italian: 'Italiano',
                portuguese: 'Português',

                // Header
                signupTitle: 'Crear Cuenta',
                signupSubtitle: 'Únete a SolTecSol y desbloquea la generación de descripciones de productos con IA',
                backToApp: 'Volver a la App',

                // Navigation
                signUp: 'Registrarse',
                signIn: 'Iniciar Sesión',

                // Form labels
                emailLabel: 'Dirección de Email',
                passwordLabel: 'Contraseña',
                confirmPasswordLabel: 'Confirmar Contraseña',

                // Placeholders
                emailPlaceholder: 'Ingresa tu dirección de email',
                passwordPlaceholder: 'Crea una contraseña segura',
                confirmPasswordPlaceholder: 'Confirma tu contraseña',
                signinPasswordPlaceholder: 'Ingresa tu contraseña',

                // Buttons
                createAccount: 'Crear Cuenta',
                signInButton: 'Iniciar Sesión',
                forgotPassword: '¿Olvidaste la contraseña?',

                // Validation messages
                emailRequired: 'El email es requerido',
                emailInvalid: 'Por favor ingresa una dirección de email válida',
                emailInUse: 'La dirección de email ya está en uso',
                emailNotFound: 'No se encontró ninguna cuenta con esta dirección de email',
                passwordRequired: 'La contraseña es requerida',
                confirmPasswordRequired: 'Por favor confirma tu contraseña',
                passwordMismatch: 'Las contraseñas no coinciden',
                passwordWeak: 'Débil',
                passwordFair: 'Regular',
                passwordGood: 'Buena',
                passwordStrong: 'Fuerte',

                // Status messages
                verificationEmailSent: '¡Cuenta creada! Por favor revisa tu email para verificar tu cuenta.',
                emailNotVerified: 'Por favor verifica tu dirección de email antes de iniciar sesión.',
                passwordResetSent: 'Email de restablecimiento de contraseña enviado. Por favor revisa tu bandeja de entrada.',
                signinSuccess: '¡Inicio de sesión exitoso! Redirigiendo...',

                // Error messages
                signupError: 'Error al crear la cuenta. Por favor intenta de nuevo.',
                signinError: 'Error al iniciar sesión. Por favor intenta de nuevo.',
                passwordResetError: 'Error al enviar el email de restablecimiento de contraseña.',
                invalidCredentials: 'Email o contraseña inválidos',
                accountDisabled: 'Esta cuenta ha sido deshabilitada',
                tooManyRequests: 'Demasiados intentos fallidos. Por favor intenta de nuevo más tarde'
            },
            fr: {
                // Language names
                english: 'English',
                spanish: 'Español',
                french: 'Français',
                german: 'Deutsch',
                italian: 'Italiano',
                portuguese: 'Português',

                // Header
                signupTitle: 'Créer un Compte',
                signupSubtitle: 'Rejoignez SolTecSol et débloquez la génération de descriptions de produits alimentée par l\'IA',
                backToApp: 'Retour à l\'App',

                // Navigation
                signUp: 'S\'inscrire',
                signIn: 'Se Connecter',

                // Form labels
                emailLabel: 'Adresse Email',
                passwordLabel: 'Mot de Passe',
                confirmPasswordLabel: 'Confirmer le Mot de Passe',

                // Placeholders
                emailPlaceholder: 'Entrez votre adresse email',
                passwordPlaceholder: 'Créez un mot de passe fort',
                confirmPasswordPlaceholder: 'Confirmez votre mot de passe',
                signinPasswordPlaceholder: 'Entrez votre mot de passe',

                // Buttons
                createAccount: 'Créer un Compte',
                signInButton: 'Se Connecter',
                forgotPassword: 'Mot de passe oublié?',

                // Validation messages
                emailRequired: 'L\'email est requis',
                emailInvalid: 'Veuillez entrer une adresse email valide',
                emailInUse: 'L\'adresse email est déjà utilisée',
                emailNotFound: 'Aucun compte trouvé avec cette adresse email',
                passwordRequired: 'Le mot de passe est requis',
                confirmPasswordRequired: 'Veuillez confirmer votre mot de passe',
                passwordMismatch: 'Les mots de passe ne correspondent pas',
                passwordWeak: 'Faible',
                passwordFair: 'Correct',
                passwordGood: 'Bon',
                passwordStrong: 'Fort',

                // Status messages
                verificationEmailSent: 'Compte créé! Veuillez vérifier votre email pour vérifier votre compte.',
                emailNotVerified: 'Veuillez vérifier votre adresse email avant de vous connecter.',
                passwordResetSent: 'Email de réinitialisation du mot de passe envoyé. Veuillez vérifier votre boîte de réception.',
                signinSuccess: 'Connexion réussie! Redirection...',

                // Error messages
                signupError: 'Échec de la création du compte. Veuillez réessayer.',
                signinError: 'Échec de la connexion. Veuillez réessayer.',
                passwordResetError: 'Échec de l\'envoi de l\'email de réinitialisation du mot de passe.',
                invalidCredentials: 'Email ou mot de passe invalide',
                accountDisabled: 'Ce compte a été désactivé',
                tooManyRequests: 'Trop de tentatives échouées. Veuillez réessayer plus tard'
            },
            de: {
                // Language names
                english: 'English',
                spanish: 'Español',
                french: 'Français',
                german: 'Deutsch',
                italian: 'Italiano',
                portuguese: 'Português',

                // Header
                signupTitle: 'Konto Erstellen',
                signupSubtitle: 'Treten Sie SolTecSol bei und schalten Sie KI-gestützte Produktbeschreibungsgenerierung frei',
                backToApp: 'Zurück zur App',

                // Navigation
                signUp: 'Registrieren',
                signIn: 'Anmelden',

                // Form labels
                emailLabel: 'E-Mail-Adresse',
                passwordLabel: 'Passwort',
                confirmPasswordLabel: 'Passwort Bestätigen',

                // Placeholders
                emailPlaceholder: 'Geben Sie Ihre E-Mail-Adresse ein',
                passwordPlaceholder: 'Erstellen Sie ein sicheres Passwort',
                confirmPasswordPlaceholder: 'Bestätigen Sie Ihr Passwort',
                signinPasswordPlaceholder: 'Geben Sie Ihr Passwort ein',

                // Buttons
                createAccount: 'Konto Erstellen',
                signInButton: 'Anmelden',
                forgotPassword: 'Passwort vergessen?',

                // Validation messages
                emailRequired: 'E-Mail ist erforderlich',
                emailInvalid: 'Bitte geben Sie eine gültige E-Mail-Adresse ein',
                emailInUse: 'E-Mail-Adresse wird bereits verwendet',
                emailNotFound: 'Kein Konto mit dieser E-Mail-Adresse gefunden',
                passwordRequired: 'Passwort ist erforderlich',
                confirmPasswordRequired: 'Bitte bestätigen Sie Ihr Passwort',
                passwordMismatch: 'Passwörter stimmen nicht überein',
                passwordWeak: 'Schwach',
                passwordFair: 'Angemessen',
                passwordGood: 'Gut',
                passwordStrong: 'Stark',

                // Status messages
                verificationEmailSent: 'Konto erstellt! Bitte überprüfen Sie Ihre E-Mail, um Ihr Konto zu verifizieren.',
                emailNotVerified: 'Bitte verifizieren Sie Ihre E-Mail-Adresse bevor Sie sich anmelden.',
                passwordResetSent: 'Passwort-Reset-E-Mail gesendet. Bitte überprüfen Sie Ihren Posteingang.',
                signinSuccess: 'Anmeldung erfolgreich! Weiterleitung...',

                // Error messages
                signupError: 'Fehler beim Erstellen des Kontos. Bitte versuchen Sie es erneut.',
                signinError: 'Fehler beim Anmelden. Bitte versuchen Sie es erneut.',
                passwordResetError: 'Fehler beim Senden der Passwort-Reset-E-Mail.',
                invalidCredentials: 'Ungültige E-Mail oder Passwort',
                accountDisabled: 'Dieses Konto wurde deaktiviert',
                tooManyRequests: 'Zu viele fehlgeschlagene Versuche. Bitte versuchen Sie es später erneut'
            },
            it: {
                // Language names
                english: 'English',
                spanish: 'Español',
                french: 'Français',
                german: 'Deutsch',
                italian: 'Italiano',
                portuguese: 'Português',

                // Header
                signupTitle: 'Crea Account',
                signupSubtitle: 'Unisciti a SolTecSol e sblocca la generazione di descrizioni prodotto alimentata dall\'IA',
                backToApp: 'Torna all\'App',

                // Navigation
                signUp: 'Registrati',
                signIn: 'Accedi',

                // Form labels
                emailLabel: 'Indirizzo Email',
                passwordLabel: 'Password',
                confirmPasswordLabel: 'Conferma Password',

                // Placeholders
                emailPlaceholder: 'Inserisci il tuo indirizzo email',
                passwordPlaceholder: 'Crea una password sicura',
                confirmPasswordPlaceholder: 'Conferma la tua password',
                signinPasswordPlaceholder: 'Inserisci la tua password',

                // Buttons
                createAccount: 'Crea Account',
                signInButton: 'Accedi',
                forgotPassword: 'Password dimenticata?',

                // Validation messages
                emailRequired: 'L\'email è richiesta',
                emailInvalid: 'Per favore inserisci un indirizzo email valido',
                emailInUse: 'L\'indirizzo email è già in uso',
                emailNotFound: 'Nessun account trovato con questo indirizzo email',
                passwordRequired: 'La password è richiesta',
                confirmPasswordRequired: 'Per favore conferma la tua password',
                passwordMismatch: 'Le password non corrispondono',
                passwordWeak: 'Debole',
                passwordFair: 'Discreta',
                passwordGood: 'Buona',
                passwordStrong: 'Forte',

                // Status messages
                verificationEmailSent: 'Account creato! Per favore controlla la tua email per verificare il tuo account.',
                emailNotVerified: 'Per favore verifica il tuo indirizzo email prima di accedere.',
                passwordResetSent: 'Email di reset password inviata. Per favore controlla la tua casella di posta.',
                signinSuccess: 'Accesso riuscito! Reindirizzamento...',

                // Error messages
                signupError: 'Errore nella creazione dell\'account. Per favore riprova.',
                signinError: 'Errore nell\'accesso. Per favore riprova.',
                passwordResetError: 'Errore nell\'invio dell\'email di reset password.',
                invalidCredentials: 'Email o password non valide',
                accountDisabled: 'Questo account è stato disabilitato',
                tooManyRequests: 'Troppi tentativi falliti. Per favore riprova più tardi'
            },
            pt: {
                // Language names
                english: 'English',
                spanish: 'Español',
                french: 'Français',
                german: 'Deutsch',
                italian: 'Italiano',
                portuguese: 'Português',

                // Header
                signupTitle: 'Criar Conta',
                signupSubtitle: 'Junte-se ao SolTecSol e desbloqueie a geração de descrições de produtos alimentada por IA',
                backToApp: 'Voltar ao App',

                // Navigation
                signUp: 'Cadastrar',
                signIn: 'Entrar',

                // Form labels
                emailLabel: 'Endereço de Email',
                passwordLabel: 'Senha',
                confirmPasswordLabel: 'Confirmar Senha',

                // Placeholders
                emailPlaceholder: 'Digite seu endereço de email',
                passwordPlaceholder: 'Crie uma senha forte',
                confirmPasswordPlaceholder: 'Confirme sua senha',
                signinPasswordPlaceholder: 'Digite sua senha',

                // Buttons
                createAccount: 'Criar Conta',
                signInButton: 'Entrar',
                forgotPassword: 'Esqueceu a senha?',

                // Validation messages
                emailRequired: 'Email é obrigatório',
                emailInvalid: 'Por favor digite um endereço de email válido',
                emailInUse: 'Endereço de email já está em uso',
                emailNotFound: 'Nenhuma conta encontrada com este endereço de email',
                passwordRequired: 'Senha é obrigatória',
                confirmPasswordRequired: 'Por favor confirme sua senha',
                passwordMismatch: 'Senhas não coincidem',
                passwordWeak: 'Fraca',
                passwordFair: 'Razoável',
                passwordGood: 'Boa',
                passwordStrong: 'Forte',

                // Status messages
                verificationEmailSent: 'Conta criada! Por favor verifique seu email para verificar sua conta.',
                emailNotVerified: 'Por favor verifique seu endereço de email antes de entrar.',
                passwordResetSent: 'Email de redefinição de senha enviado. Por favor verifique sua caixa de entrada.',
                signinSuccess: 'Login bem-sucedido! Redirecionando...',

                // Error messages
                signupError: 'Falha ao criar conta. Por favor tente novamente.',
                signinError: 'Falha ao entrar. Por favor tente novamente.',
                passwordResetError: 'Falha ao enviar email de redefinição de senha.',
                invalidCredentials: 'Email ou senha inválidos',
                accountDisabled: 'Esta conta foi desabilitada',
                tooManyRequests: 'Muitas tentativas falharam. Por favor tente novamente mais tarde'
            }
        };

        let currentLanguage = 'en';

        function updateTranslations(language = currentLanguage) {
            const elements = document.querySelectorAll('[data-translate]');
            const langData = translations[language] || translations.en;

            elements.forEach(element => {
                const key = element.getAttribute('data-translate');
                if (langData[key]) {
                    element.textContent = langData[key];
                }
            });

            // Update placeholders
            const placeholderElements = document.querySelectorAll('[data-translate-placeholder]');
            placeholderElements.forEach(element => {
                const key = element.getAttribute('data-translate-placeholder');
                if (langData[key]) {
                    element.placeholder = langData[key];
                }
            });
        }

        function setupLanguageSelector() {
            const languageSelect = document.getElementById('languageSelect');
            if (languageSelect) {
                languageSelect.addEventListener('change', (event) => {
                    currentLanguage = event.target.value;
                    updateTranslations(currentLanguage);
                    // Save language preference
                    localStorage.setItem('soltecsol_language', currentLanguage);
                });

                // Load saved language preference
                const savedLanguage = localStorage.getItem('soltecsol_language');
                if (savedLanguage && translations[savedLanguage]) {
                    currentLanguage = savedLanguage;
                    languageSelect.value = currentLanguage;
                    updateTranslations(currentLanguage);
                }
            }
        }

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
            // Setup language selector
            setupLanguageSelector();

            // Update translations
            updateTranslations();

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

            // Setup modal checkbox handlers
            setupTosCheckbox();
            setupDpaCheckbox();

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

