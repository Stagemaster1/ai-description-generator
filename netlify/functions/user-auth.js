const { initializeFirebase, getAuth, getFirestore } = require('../../firebase-config');

// Simple in-memory rate limiting (use Redis in production)
const rateLimitMap = new Map();

function isRateLimited(ip) {
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxAttempts = 5;
    
    const attempts = rateLimitMap.get(ip) || [];
    const recentAttempts = attempts.filter(time => now - time < windowMs);
    
    if (recentAttempts.length >= maxAttempts) {
        return true;
    }
    
    recentAttempts.push(now);
    rateLimitMap.set(ip, recentAttempts);
    return false;
}

exports.handler = async (event, context) => {
    const headers = {
        'Access-Control-Allow-Origin': 'https://ai-generator.soltecsol.com',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Credentials': 'true'
    };

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    // Check rate limit
    const clientIp = event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown';
    if (isRateLimited(clientIp)) {
        return {
            statusCode: 429,
            headers,
            body: JSON.stringify({
                success: false,
                message: 'Too many attempts. Please try again later.'
            })
        };
    }

    try {
        const { action, email, password } = JSON.parse(event.body || '{}');

        // Validate and sanitize inputs
        if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: 'Invalid request data.'
                })
            };
        }

        // Sanitize email
        const sanitizedEmail = email.trim().toLowerCase();
        if (sanitizedEmail.length > 254) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: 'Invalid email address.'
                })
            };
        }

        // CRITICAL: Email validation on backend
        if (!isValidEmail(sanitizedEmail)) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: 'Please enter a valid email address.'
                })
            };
        }

        initializeFirebase();
        const auth = getAuth();
        const db = getFirestore();

        switch (action) {
            case 'signup':
                return await handleSignup(auth, db, sanitizedEmail, password, headers);
            case 'login':
                return await handleLogin(auth, db, sanitizedEmail, password, headers);
            default:
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ success: false, message: 'Invalid action' })
                };
        }
    } catch (error) {
        console.error('Auth Error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({
                success: false,
                message: 'Authentication failed. Please try again.'
            })
        };
    }
};

function isValidEmail(email) {
    // Comprehensive email validation
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (!emailRegex.test(email)) {
        return false;
    }
    
    // Additional domain validation
    const emailParts = email.split('@');
    if (emailParts.length !== 2 || emailParts[1].indexOf('.') === -1) {
        return false;
    }
    
    return true;
}

async function handleSignup(auth, db, email, password, headers) {
    try {
        // Enforce password strength
        if (password.length < 8) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: 'Password must be at least 8 characters long.'
                })
            };
        }

        // Create Firebase user
        const userRecord = await auth.createUser({
            email: email,
            password: password
        });

        // Create user document in Firestore
        await db.collection('users').doc(userRecord.uid).set({
            email: email,
            createdAt: new Date(),
            monthlyUsage: 0,
            maxUsage: 5,
            subscriptionType: 'free',
            isSubscribed: false,
            lastActive: new Date()
        });

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                user: {
                    uid: userRecord.uid,
                    email: userRecord.email
                },
                message: 'Account created successfully!'
            })
        };
    } catch (error) {
        // Generic error messages to prevent information disclosure
        let errorMessage = 'Account creation failed. Please try again.';
        
        if (error.code === 'auth/email-already-exists') {
            errorMessage = 'An account with this email already exists.';
        } else if (error.code === 'auth/weak-password') {
            errorMessage = 'Password must be at least 8 characters long.';
        }

        return {
            statusCode: 400,
            headers,
            body: JSON.stringify({
                success: false,
                message: errorMessage
            })
        };
    }
}

async function handleLogin(auth, db, email, password, headers) {
    try {
        // CRITICAL: Use Firebase Admin SDK to verify user exists
        const userRecord = await auth.getUserByEmail(email);
        
        // Create custom token for verified user
        const customToken = await auth.createCustomToken(userRecord.uid);
        
        // Get user data from Firestore
        const userDoc = await db.collection('users').doc(userRecord.uid).get();
        const userData = userDoc.data();
        
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                customToken: customToken,
                user: {
                    uid: userRecord.uid,
                    email: userData.email,
                    subscriptionType: userData.subscriptionType || 'free',
                    monthlyUsage: userData.monthlyUsage || 0,
                    maxUsage: userData.maxUsage || 5
                },
                message: 'Login successful!'
            })
        };
    } catch (error) {
        // Generic error message to prevent user enumeration
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({
                success: false,
                message: 'Invalid credentials.'
            })
        };
    }
}