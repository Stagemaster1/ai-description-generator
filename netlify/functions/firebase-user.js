// Firebase User Management - Secure replacement for user.js
// Handles all user operations with Firebase Firestore

const { getFirestore } = require('./firebase-config');
const firebaseAuthMiddleware = require('./firebase-auth-middleware');

// SECURITY FIX: Rate limiting implementation
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 20; // 20 requests per minute for user operations

exports.handler = async (event, context) => {
    // Production-only CORS configuration
    const allowedOrigins = [
        'https://www.soltecsol.com',
        'https://ai-generator.soltecsol.com'
    ];

    const origin = event.headers.origin || event.headers.Origin || '';
    
    // Enhanced origin validation for different request types
    const isValidOrigin = () => {
        // Server-to-server requests (webhooks, APIs) may not have origin
        if (!origin) {
            // Allow server-to-server requests but verify other security measures
            const userAgent = event.headers['user-agent'] || '';
            const isPayPalWebhook = userAgent.includes('PayPal') || 
                                   event.headers['paypal-transmission-id'];
            
            // Allow webhooks and direct API calls
            return isPayPalWebhook || event.httpMethod !== 'GET';
        }
        
        return allowedOrigins.includes(origin);
    };

    // Apply origin validation
    if (!isValidOrigin()) {
        return {
            statusCode: 403,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                error: 'Origin not allowed',
                message: 'CORS policy violation' 
            })
        };
    }

    // Dynamic origin header setting
    const corsOrigin = origin && allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

    const headers = {
        'Access-Control-Allow-Origin': corsOrigin,
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, PayPal-Request-Id, X-CSRF-Token',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
        'Access-Control-Allow-Credentials': 'true',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    };

    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers,
            body: ''
        };
    }

    // SECURITY FIX: Rate limiting check
    const clientIP = event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown';
    if (!checkRateLimit(clientIP)) {
        return {
            statusCode: 429,
            headers: {
                ...headers,
                'Retry-After': '60'
            },
            body: JSON.stringify({ 
                error: 'Rate limit exceeded. Please try again later.',
                retryAfter: 60 
            })
        };
    }

    try {
        // SECURITY FIX: Add Firebase Authentication verification for sensitive operations
        const { action, userId, email, subscriptionData } = JSON.parse(event.body || '{}');
        
        // CRITICAL: Validate userId parameter format and structure
        if (userId && !isValidUserId(userId)) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'Invalid userId format',
                    message: 'userId must be a valid Firebase UID' 
                })
            };
        }
        
        // SESSION 4D4: Enhanced authentication using centralized middleware
        if (['get_user', 'create_user', 'increment_usage'].includes(action)) {
            // Use enhanced token validation from firebase-auth-middleware
            const authValidation = await firebaseAuthMiddleware.validateAuthorizationHeader(event.headers);
            if (!authValidation.valid) {
                return {
                    statusCode: authValidation.statusCode,
                    headers,
                    body: JSON.stringify({ 
                        error: authValidation.error,
                        ...(authValidation.code && { code: authValidation.code }),
                        ...(authValidation.emailVerified === false && { emailVerified: false })
                    })
                };
            }
            
            const authenticatedUser = authValidation.user;
            
            // SESSION 4D4: Enhanced user ID validation and matching
            if (userId && userId !== authenticatedUser.uid) {
                return {
                    statusCode: 403,
                    headers,
                    body: JSON.stringify({ 
                        error: 'Access denied: User ID mismatch',
                        code: 'USER_ID_MISMATCH',
                        message: 'Authenticated user does not match requested user ID'
                    })
                };
            }
            
            // SESSION 4D4: Additional security checks for cross-domain authentication
            if (!authenticatedUser.emailVerified) {
                return {
                    statusCode: 403,
                    headers,
                    body: JSON.stringify({ 
                        error: 'Email verification required for cross-domain access',
                        emailVerified: false,
                        code: 'EMAIL_NOT_VERIFIED',
                        message: 'Please verify your email address to continue using the service'
                    })
                };
            }
            
            // SESSION 4D4: Session age validation for enhanced security
            const currentTime = Math.floor(Date.now() / 1000);
            const authTime = authenticatedUser.authTime;
            const maxSessionAge = 24 * 60 * 60; // 24 hours max session
            
            if (currentTime - authTime > maxSessionAge) {
                return {
                    statusCode: 401,
                    headers,
                    body: JSON.stringify({ 
                        error: 'Session expired - re-authentication required',
                        code: 'SESSION_EXPIRED',
                        message: 'Your session has expired. Please sign in again for security.'
                    })
                };
            }
        }
        
        const db = getFirestore();

        switch (action) {
            case 'get_user':
                return await getUser(db, userId, headers);
            
            case 'create_user':
                return await createUser(db, userId, email, headers);
            
            case 'increment_usage':
                return await incrementUsage(db, userId, headers);
            
            case 'update_subscription':
                return await updateSubscription(db, userId, subscriptionData, headers);
            
            case 'reset_monthly_usage':
                return await resetMonthlyUsage(db, userId, headers);
            
            default:
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ error: 'Invalid action' })
                };
        }
    } catch (error) {
        console.error('Firebase User API Error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Internal server error',
                message: error.message 
            })
        };
    }
};

// CRITICAL: UserId validation function
function isValidUserId(userId) {
    // Firebase UIDs are typically 28 characters long and alphanumeric
    if (!userId || typeof userId !== 'string') {
        return false;
    }
    
    // Check length (Firebase UIDs are typically 28 characters)
    if (userId.length < 10 || userId.length > 128) {
        return false;
    }
    
    // Check for valid characters (alphanumeric and some special chars)
    const uidPattern = /^[a-zA-Z0-9_-]+$/;
    if (!uidPattern.test(userId)) {
        return false;
    }
    
    // Prevent common attack patterns
    const dangerousPatterns = [
        '../', '..\\', '<script', 'javascript:', 'data:',
        'null', 'undefined', 'admin', 'root', 'system'
    ];
    
    const lowerUserId = userId.toLowerCase();
    for (const pattern of dangerousPatterns) {
        if (lowerUserId.includes(pattern)) {
            return false;
        }
    }
    
    return true;
}

// Get user data from Firebase
async function getUser(db, userId, headers) {
    try {
        // CRITICAL: Additional userId validation at function level
        if (!userId || !isValidUserId(userId)) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    error: 'Valid userId is required' 
                })
            };
        }
        const userDoc = await db.collection('users').doc(userId).get();
        
        if (!userDoc.exists) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    error: 'User not found' 
                })
            };
        }

        const userData = userDoc.data();
        
        // Check if monthly usage should be reset (new billing period)
        const currentMonth = getCurrentBillingPeriod();
        if (userData.lastResetPeriod !== currentMonth && userData.subscriptionType !== 'free') {
            // Reset usage for new billing period
            await db.collection('users').doc(userId).update({
                monthlyUsage: 0,
                lastResetPeriod: currentMonth,
                lastActive: new Date().toISOString()
            });
            userData.monthlyUsage = 0;
            userData.lastResetPeriod = currentMonth;
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                user: userData
            })
        };
    } catch (error) {
        console.error('Get user error:', error);
        throw error;
    }
}

// Create new user in Firebase
async function createUser(db, userId, email, headers) {
    try {
        // CRITICAL: Enhanced userId validation for user creation
        if (!userId || !isValidUserId(userId)) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    error: 'Valid User ID from Firebase Authentication is required'
                })
            };
        }

        // SESSION 4D4: Enhanced registration rate limiting with IP validation
        const clientIP = event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown';
        if (!checkRegistrationRateLimit(clientIP)) {
            return {
                statusCode: 429,
                headers: {
                    ...headers,
                    'Retry-After': '3600'
                },
                body: JSON.stringify({
                    success: false,
                    error: 'Registration rate limit exceeded. Maximum 5 registration attempts per hour.',
                    retryAfter: 3600
                })
            };
        }

        // SESSION 4D4: Enhanced email validation with security and domain verification
        const emailValidation = await isValidEmail(email);
        if (!emailValidation.valid) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    error: emailValidation.error,
                    code: 'INVALID_EMAIL',
                    emailChecks: emailValidation.checks
                })
            };
        }
        
        // SESSION 4D4: Check for existing user with same email to prevent duplicates
        const existingEmailQuery = await db.collection('users').where('email', '==', email).limit(1).get();
        if (!existingEmailQuery.empty) {
            return {
                statusCode: 409,
                headers,
                body: JSON.stringify({
                    success: false,
                    error: 'Email address already registered',
                    code: 'EMAIL_ALREADY_EXISTS',
                    message: 'This email address is already associated with an account.'
                })
            };
        }

        const currentDate = new Date().toISOString();
        const currentMonth = getCurrentBillingPeriod();
        
        const userData = {
            id: userId, // Use Firebase UID
            email: email,
            monthlyUsage: 0,
            maxUsage: 3, // Updated from 5 to 3 for free users
            subscriptionType: 'free',
            isSubscribed: false,
            paypalSubscriptionId: null,
            lastResetPeriod: currentMonth,
            createdAt: currentDate,
            lastActive: currentDate,
            status: 'active'
        };

        await db.collection('users').doc(userId).set(userData);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                userId,
                user: userData
            })
        };
    } catch (error) {
        console.error('Create user error:', error);
        throw error;
    }
}

// Increment user usage count
async function incrementUsage(db, userId, headers) {
    try {
        // CRITICAL: Validate userId before processing
        if (!userId || !isValidUserId(userId)) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    error: 'Valid userId is required for usage tracking' 
                })
            };
        }
        const userDoc = await db.collection('users').doc(userId).get();
        
        if (!userDoc.exists) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    error: 'User not found' 
                })
            };
        }

        const userData = userDoc.data();
        const newUsage = (userData.monthlyUsage || 0) + 1;

        // Check usage limits
        if (newUsage > userData.maxUsage && userData.subscriptionType !== 'enterprise') {
            return {
                statusCode: 429,
                headers,
                body: JSON.stringify({
                    success: false,
                    error: 'Usage limit exceeded',
                    maxUsage: userData.maxUsage,
                    currentUsage: userData.monthlyUsage
                })
            };
        }

        // Update usage count
        await db.collection('users').doc(userId).update({
            monthlyUsage: newUsage,
            lastActive: new Date().toISOString()
        });

        const updatedData = { ...userData, monthlyUsage: newUsage };

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                user: updatedData,
                message: 'Usage incremented successfully'
            })
        };
    } catch (error) {
        console.error('Increment usage error:', error);
        throw error;
    }
}

// Update user subscription from PayPal webhook
async function updateSubscription(db, userId, subscriptionData, headers) {
    try {
        // CRITICAL: Validate userId for subscription updates
        if (!userId || !isValidUserId(userId)) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    error: 'Valid userId is required for subscription updates' 
                })
            };
        }
        const { 
            subscriptionType, 
            paypalSubscriptionId, 
            status,
            planId 
        } = subscriptionData;

        // Map plan IDs to subscription types and limits
        const planConfig = {
            [process.env.PAYPAL_STARTER_PLAN_ID]: { type: 'starter', maxUsage: 50 },
            [process.env.PAYPAL_PROFESSIONAL_PLAN_ID]: { type: 'professional', maxUsage: 200 },
            [process.env.PAYPAL_ENTERPRISE_PLAN_ID]: { type: 'enterprise', maxUsage: -1 } // unlimited
        };

        const config = planConfig[planId] || { type: 'free', maxUsage: 3 };

        const updateData = {
            subscriptionType: config.type,
            maxUsage: config.maxUsage,
            isSubscribed: status === 'ACTIVE',
            paypalSubscriptionId: paypalSubscriptionId,
            subscriptionStatus: status,
            lastActive: new Date().toISOString()
        };

        await db.collection('users').doc(userId).update(updateData);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                message: 'Subscription updated successfully',
                subscription: updateData
            })
        };
    } catch (error) {
        console.error('Update subscription error:', error);
        throw error;
    }
}

// Reset monthly usage (for admin or billing period reset)
async function resetMonthlyUsage(db, userId, headers) {
    try {
        // CRITICAL: Validate userId for usage reset
        if (!userId || !isValidUserId(userId)) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    success: false,
                    error: 'Valid userId is required for usage reset' 
                })
            };
        }
        await db.collection('users').doc(userId).update({
            monthlyUsage: 0,
            lastResetPeriod: getCurrentBillingPeriod(),
            lastActive: new Date().toISOString()
        });

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                message: 'Monthly usage reset successfully'
            })
        };
    } catch (error) {
        console.error('Reset usage error:', error);
        throw error;
    }
}

// SECURITY FIX: Remove insecure user ID generation
// User IDs should come from Firebase Authentication UIDs only
// This function is deprecated and should not be used

// SECURITY FIX: Proper email validation function with enhanced security
const dns = require('dns').promises;

// Domain whitelist for approved email providers
const approvedDomains = ['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com', 'protonmail.com', 'aol.com'];

// Registration rate limiting - 5 attempts per hour per IP
const registrationAttempts = new Map();

async function isValidEmail(email) {
    // SESSION 4D4: Enhanced email validation with detailed security checks
    const checks = {
        format: false,
        length: false,
        domain: false,
        mx: false,
        whitelist: false,
        security: false
    };
    
    if (!email || typeof email !== 'string') {
        return { 
            valid: false, 
            error: 'Email is required and must be a string',
            checks
        };
    }
    
    // CRITICAL: Security-approved email regex
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    
    // Basic length checks
    if (email.length < 3 || email.length > 320) {
        return { 
            valid: false, 
            error: 'Email length must be between 3 and 320 characters',
            checks
        };
    }
    checks.length = true;
    
    // Split into local and domain parts
    const parts = email.split('@');
    if (parts.length !== 2) {
        return { 
            valid: false, 
            error: 'Invalid email format',
            checks
        };
    }
    
    const [localPart, domainPart] = parts;
    
    // Local part validation (before @)
    if (localPart.length < 1 || localPart.length > 64) {
        return { 
            valid: false, 
            error: 'Email local part length invalid',
            checks
        };
    }
    
    // Domain part validation (after @)
    if (domainPart.length < 1 || domainPart.length > 255) {
        return { 
            valid: false, 
            error: 'Email domain part length invalid',
            checks
        };
    }
    
    // CRITICAL: TLD validation - minimum 2 characters
    const tldMatch = domainPart.match(/\.([a-zA-Z]{2,})$/);
    if (!tldMatch || tldMatch[1].length < 2) {
        return { 
            valid: false, 
            error: 'Domain must have a valid TLD with at least 2 characters',
            checks
        };
    }
    checks.domain = true;
    
    // Check against regex pattern
    if (!emailRegex.test(email)) {
        return { 
            valid: false, 
            error: 'Email format does not match security requirements',
            checks
        };
    }
    checks.format = true;
    
    // SESSION 4D4: Enhanced security pattern checks
    const securityPatterns = [
        /script/i, /javascript/i, /vbscript/i, /onload/i, /onerror/i,
        /<|>|\\|\||&|;/, // Potential injection characters
        /\.{2,}/, // Multiple consecutive dots
        /^\.|\.$/, // Leading or trailing dots
        /@.*@/ // Multiple @ symbols
    ];
    
    for (const pattern of securityPatterns) {
        if (pattern.test(email)) {
            return { 
                valid: false, 
                error: 'Email contains potentially unsafe characters',
                checks
            };
        }
    }
    checks.security = true;
    
    // CRITICAL: Domain whitelist enforcement
    if (!approvedDomains.includes(domainPart.toLowerCase())) {
        return { 
            valid: false, 
            error: 'Email domain not in approved list. Please use Gmail, Outlook, Yahoo, iCloud, ProtonMail, or AOL',
            checks
        };
    }
    checks.whitelist = true;
    
    // CRITICAL: DNS MX record verification
    try {
        const mxRecords = await dns.resolveMx(domainPart);
        if (!mxRecords || mxRecords.length === 0) {
            return { 
                valid: false, 
                error: 'Email domain does not have valid mail servers',
                checks
            };
        }
        checks.mx = true;
    } catch (error) {
        console.error('DNS MX lookup failed for domain:', domainPart, error);
        return { 
            valid: false, 
            error: 'Email domain cannot be verified',
            checks
        };
    }
    
    return { 
        valid: true, 
        error: null,
        checks
    };
}

// CRITICAL: Registration rate limiting function
function checkRegistrationRateLimit(clientIP) {
    const now = Date.now();
    const attempts = registrationAttempts.get(clientIP) || [];
    const validAttempts = attempts.filter(timestamp => now - timestamp < 3600000); // 1 hour
    
    if (validAttempts.length >= 5) {
        return false;
    }
    
    validAttempts.push(now);
    registrationAttempts.set(clientIP, validAttempts);
    return true;
}

// Clean up old registration attempts periodically
setInterval(() => {
    const now = Date.now();
    for (const [ip, attempts] of registrationAttempts.entries()) {
        const validAttempts = attempts.filter(timestamp => now - timestamp < 3600000);
        if (validAttempts.length === 0) {
            registrationAttempts.delete(ip);
        } else {
            registrationAttempts.set(ip, validAttempts);
        }
    }
}, 10 * 60 * 1000); // Clean every 10 minutes

function getCurrentBillingPeriod() {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

// SECURITY FIX: Rate limiting function
function checkRateLimit(clientIP) {
    const now = Date.now();
    const userRequests = rateLimitMap.get(clientIP) || [];
    
    // Remove requests outside the current window
    const validRequests = userRequests.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
    
    // Check if user has exceeded rate limit
    if (validRequests.length >= RATE_LIMIT_MAX_REQUESTS) {
        return false;
    }
    
    // Add current request timestamp
    validRequests.push(now);
    rateLimitMap.set(clientIP, validRequests);
    
    return true;
}

// Clean up old entries periodically
setInterval(() => {
    const now = Date.now();
    for (const [ip, requests] of rateLimitMap.entries()) {
        const validRequests = requests.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
        if (validRequests.length === 0) {
            rateLimitMap.delete(ip);
        } else {
            rateLimitMap.set(ip, validRequests);
        }
    }
}, 5 * 60 * 1000);
