        // Email validation
        function validateEmail(email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return emailRegex.test(email);
        }

        // Show message
        function showMessage(message, type = 'info') {
            const messageArea = document.getElementById('messageArea');
            messageArea.innerHTML = `<div class="message ${type}">${message}</div>`;
        }

        // Clear message
        function clearMessage() {
            const messageArea = document.getElementById('messageArea');
            messageArea.innerHTML = '';
        }

        // Show field error
        function showFieldError(fieldId, message) {
            const errorElement = document.getElementById(fieldId + 'Error');
            const inputElement = document.getElementById(fieldId);

            if (errorElement && inputElement) {
                errorElement.textContent = message;
                errorElement.classList.add('show');
                inputElement.classList.add('error');
            }
        }

        // Clear field error
        function clearFieldError(fieldId) {
            const errorElement = document.getElementById(fieldId + 'Error');
            const inputElement = document.getElementById(fieldId);

            if (errorElement && inputElement) {
                errorElement.classList.remove('show');
                inputElement.classList.remove('error');
            }
        }

        // Check user subscription status from Firestore
        async function checkUserStatus(userId) {
            try {
                // TODO: Replace with actual Firestore query
                // const userDoc = await getDoc(doc(db, 'users', userId));
                // const userData = userDoc.data();
                // return userData.status; // 'trial', 'starter', 'professional', 'enterprise'

                // Placeholder - will be implemented with Firestore
                console.log('Checking user status for:', userId);
                return 'starter'; // Default for now
            } catch (error) {
                console.error('Error checking user status:', error);
                return null;
            }
        }

        // Handle Sign In
        async function handleSignIn(event) {
            event.preventDefault();

            const email = document.getElementById('signinEmail').value.trim();
            const password = document.getElementById('signinPassword').value;

            const submitBtn = document.getElementById('signinSubmit');
            const buttonText = document.getElementById('signinButtonText');
            const spinner = document.getElementById('signinSpinner');

            // Clear previous errors
            clearMessage();
            clearFieldError('signinEmail');
            clearFieldError('signinPassword');

            let isValid = true;

            // Validate email
            if (!email) {
                showFieldError('signinEmail', 'Email is required');
                isValid = false;
            } else if (!validateEmail(email)) {
                showFieldError('signinEmail', 'Please enter a valid email address');
                isValid = false;
            }

            // Validate password
            if (!password) {
                showFieldError('signinPassword', 'Password is required');
                isValid = false;
            }

            if (!isValid) {
                return;
            }

            try {
                // Show loading state
                submitBtn.disabled = true;
                buttonText.style.display = 'none';
                spinner.style.display = 'inline-block';

                // Sign in with Firebase
                const userCredential = await window.firebaseSignInWithEmailAndPassword(window.firebaseAuth, email, password);
                const user = userCredential.user;

                if (!user.emailVerified) {
                    showMessage('Please verify your email address before signing in.', 'warning');
                    await window.firebaseAuth.signOut();
                    return;
                }

                // Check user subscription status
                const userStatus = await checkUserStatus(user.uid);

                // Block trial users
                if (userStatus === 'trial') {
                    showMessage('Trial users must sign in on the app page. Redirecting...', 'warning');
                    await window.firebaseAuth.signOut();
                    setTimeout(() => {
                        window.location.href = 'https://app.soltecsol.com';
                    }, 2000);
                    return;
                }

                // Allow subscribed users - redirect to user management
                if (userStatus === 'starter' || userStatus === 'professional' || userStatus === 'enterprise') {
                    showMessage('Sign in successful! Redirecting to dashboard...', 'success');
                    setTimeout(() => {
                        // TODO: Update with actual user management page URL
                        window.location.href = 'https://app.soltecsol.com/dashboard'; // Placeholder
                    }, 1500);
                } else {
                    showMessage('Unable to verify subscription status. Please contact support.', 'error');
                    await window.firebaseAuth.signOut();
                }

            } catch (error) {
                console.error('Sign in error:', error);

                let errorMessage = 'Failed to sign in. Please try again.';

                switch (error.code) {
                    case 'auth/user-not-found':
                    case 'auth/wrong-password':
                    case 'auth/invalid-credential':
                        errorMessage = 'Invalid email or password';
                        break;
                    case 'auth/user-disabled':
                        errorMessage = 'This account has been disabled';
                        break;
                    case 'auth/too-many-requests':
                        errorMessage = 'Too many failed attempts. Please try again later';
                        break;
                }

                showMessage(errorMessage, 'error');

            } finally {
                // Reset loading state
                submitBtn.disabled = false;
                buttonText.style.display = 'inline';
                spinner.style.display = 'none';
            }
        }

        // Handle Forgot Password
        async function handleForgotPassword() {
            const email = document.getElementById('signinEmail').value.trim();

            if (!email) {
                showFieldError('signinEmail', 'Please enter your email address');
                return;
            }

            if (!validateEmail(email)) {
                showFieldError('signinEmail', 'Please enter a valid email address');
                return;
            }

            try {
                await window.firebaseSendPasswordResetEmail(window.firebaseAuth, email);
                showMessage('Password reset email sent. Please check your inbox.', 'success');

            } catch (error) {
                console.error('Password reset error:', error);

                let errorMessage = 'Failed to send password reset email.';

                switch (error.code) {
                    case 'auth/user-not-found':
                        errorMessage = 'No account found with this email address';
                        break;
                    case 'auth/invalid-email':
                        errorMessage = 'Invalid email address';
                        break;
                }

                showMessage(errorMessage, 'error');
            }
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            const signinForm = document.getElementById('signinForm');
            const forgotPasswordBtn = document.getElementById('forgotPasswordBtn');

            if (signinForm) {
                signinForm.addEventListener('submit', handleSignIn);
            }

            if (forgotPasswordBtn) {
                forgotPasswordBtn.addEventListener('click', handleForgotPassword);
            }

            // Wait for Firebase to be ready
            if (window.firebaseAuth) {
                console.log('Firebase Auth ready for login page');
            } else {
                window.addEventListener('firebaseReady', () => {
                    console.log('Firebase Auth initialized for login page');
                });
            }
        });
