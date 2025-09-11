// Firebase Authentication Middleware
// Centralized authentication framework for all endpoints
// SESSION 4D1 Implementation - Authentication Framework

const { getAuth, getFirestore } = require('../../firebase-config');
const securityLogger = require('./security-logger');

/**
 * Firebase Authentication Middleware
 * Provides centralized authentication validation for all endpoints
 */
class FirebaseAuthMiddleware {
    constructor() {
        this.rateLimitMap = new Map();
        this.usedTokens = new Map(); // Token replay prevention
        this.RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
        this.MAX_REQUESTS_PER_MINUTE = 30;
        this.TOKEN_REPLAY_WINDOW = 60 * 60 * 1000; // 1 hour token replay window
    }

    /**
     * Verify Firebase ID Token
     * @param {string} idToken - Firebase ID token
     * @returns {Object} Validation result with user data or error
     */
    async verifyIdToken(idToken) {
        try {
            if (!idToken || typeof idToken !== 'string') {
                return {
                    valid: false,
                    error: 'Invalid token format',
                    statusCode: 401
                };
            }

            const auth = getAuth();
            const decodedToken = await auth.verifyIdToken(idToken, true); // checkRevoked = true
            
            // SECURITY FIX: Token replay attack prevention - Check FIRST before validation
            const tokenClaims = decodedToken;
            const tokenId = tokenClaims.jti || tokenClaims.iat.toString();
            
            if (await this.isTokenReplayed(tokenId)) {
                securityLogger.logSuspiciousActivity({
                    activityType: 'TOKEN_REPLAY_ATTACK',
                    description: 'Attempted to reuse already consumed token',
                    userId: decodedToken.uid || 'unknown',
                    additionalData: { tokenId: tokenId }
                });
                return { 
                    valid: false, 
                    error: 'Token replay detected - security violation',
                    statusCode: 401
                };
            }
            
            // SECURITY FIX: Token audience validation
            if (decodedToken.aud !== process.env.FIREBASE_PROJECT_ID) {
                return { valid: false, error: 'Invalid token audience', statusCode: 401 };
            }
            
            // SECURITY FIX: Auth time vs session validation
            const currentTime = Math.floor(Date.now() / 1000);
            const authTime = decodedToken.auth_time;
            const maxSessionAge = 24 * 60 * 60; // 24 hours max session
            
            if (currentTime - authTime > maxSessionAge) {
                return { 
                    valid: false, 
                    error: 'Session expired - re-authentication required',
                    statusCode: 401
                };
            }

            // CRITICAL: Enforce email verification
            if (!decodedToken.email_verified) {
                return {
                    valid: false,
                    error: 'Email verification required',
                    statusCode: 403,
                    emailVerified: false
                };
            }

            // Additional token validation
            if (!decodedToken.uid || !decodedToken.email) {
                return {
                    valid: false,
                    error: 'Invalid token payload',
                    statusCode: 401
                };
            }

            // CRITICAL FIX: Record token usage BEFORE returning success to prevent replay
            await this.recordTokenUsage(tokenId);

            const user = {
                uid: decodedToken.uid,
                email: decodedToken.email,
                emailVerified: decodedToken.email_verified,
                authTime: decodedToken.auth_time,
                iat: decodedToken.iat,
                exp: decodedToken.exp
            };

            // Log successful authentication
            securityLogger.logAuthSuccess({
                userId: user.uid,
                email: user.email,
                method: 'firebase_token'
            });

            return {
                valid: true,
                user: user
            };
            
        } catch (error) {
            console.error('Firebase token verification failed:', error);

            // Log token validation failure
            securityLogger.logTokenValidationFailure({
                tokenType: 'firebase_id_token',
                reason: error.code || 'unknown_error',
                error: error.message,
                tokenExpired: error.code === 'auth/id-token-expired'
            });

            // Handle specific Firebase errors
            if (error.code === 'auth/id-token-expired') {
                return {
                    valid: false,
                    error: 'Authentication token expired',
                    statusCode: 401,
                    code: 'TOKEN_EXPIRED'
                };
            }

            if (error.code === 'auth/id-token-revoked') {
                return {
                    valid: false,
                    error: 'Authentication token revoked',
                    statusCode: 401,
                    code: 'TOKEN_REVOKED'
                };
            }

            if (error.code === 'auth/invalid-id-token') {
                return {
                    valid: false,
                    error: 'Invalid authentication token',
                    statusCode: 401,
                    code: 'INVALID_TOKEN'
                };
            }

            return {
                valid: false,
                error: 'Authentication failed',
                statusCode: 401
            };
        }
    }

    /**
     * Extract and validate authorization header
     * @param {Object} headers - Request headers
     * @returns {Object} Token validation result
     */
    async validateAuthorizationHeader(headers) {
        try {
            const authHeader = headers.authorization || headers.Authorization;
            
            if (!authHeader) {
                return {
                    valid: false,
                    error: 'Authorization header missing',
                    statusCode: 401
                };
            }

            if (!authHeader.startsWith('Bearer ')) {
                return {
                    valid: false,
                    error: 'Invalid authorization format. Expected: Bearer <token>',
                    statusCode: 401
                };
            }

            const idToken = authHeader.substring(7); // Remove 'Bearer ' prefix
            
            if (!idToken || idToken.length < 10) {
                return {
                    valid: false,
                    error: 'Invalid token length',
                    statusCode: 401
                };
            }

            return await this.verifyIdToken(idToken);

        } catch (error) {
            console.error('Authorization header validation failed:', error);
            return {
                valid: false,
                error: 'Authorization validation failed',
                statusCode: 500
            };
        }
    }

    /**
     * Validate user subscription and increment usage
     * @param {string} userId - User ID
     * @returns {Object} Subscription validation result
     */
    async validateUserSubscription(userId) {
        try {
            if (!userId || typeof userId !== 'string') {
                return {
                    valid: false,
                    error: 'Invalid user ID',
                    currentUsage: 0,
                    maxUsage: 0,
                    subscriptionType: 'unknown'
                };
            }

            const db = getFirestore();
            const userDoc = await db.collection('users').doc(userId).get();
            
            if (!userDoc.exists) {
                return {
                    valid: false,
                    error: 'User not found in database',
                    currentUsage: 0,
                    maxUsage: 0,
                    subscriptionType: 'unknown'
                };
            }

            const userData = userDoc.data();
            const currentUsage = userData.monthlyUsage || 0;
            const maxUsage = userData.maxUsage || 3;
            const subscriptionType = userData.subscriptionType || 'free';
            const isSubscribed = userData.isSubscribed || false;
            const subscriptionStatus = userData.subscriptionStatus;

            // Check if monthly usage should be reset (new billing period)
            const currentMonth = this.getCurrentBillingPeriod();
            let actualUsage = currentUsage;
            
            if (userData.lastResetPeriod !== currentMonth && subscriptionType !== 'free') {
                // Reset usage for new billing period for paid subscribers
                await db.collection('users').doc(userId).update({
                    monthlyUsage: 0,
                    lastResetPeriod: currentMonth,
                    lastActive: new Date().toISOString()
                });
                actualUsage = 0;
            }

            // Check subscription status for paid plans
            if (subscriptionType !== 'free') {
                if (!isSubscribed || (subscriptionStatus && subscriptionStatus !== 'ACTIVE')) {
                    // Log subscription failure
                    securityLogger.logSubscriptionFailure({
                        userId: userId,
                        subscriptionType: subscriptionType,
                        currentUsage: actualUsage,
                        maxUsage: maxUsage,
                        reason: 'inactive_subscription'
                    });

                    return {
                        valid: false,
                        error: 'Subscription is not active. Please renew your subscription to continue.',
                        currentUsage: actualUsage,
                        maxUsage: maxUsage,
                        subscriptionType: subscriptionType
                    };
                }
            }

            // Check usage limits (unlimited for enterprise)
            if (subscriptionType !== 'enterprise' && actualUsage >= maxUsage) {
                // Log subscription failure
                securityLogger.logSubscriptionFailure({
                    userId: userId,
                    subscriptionType: subscriptionType,
                    currentUsage: actualUsage,
                    maxUsage: maxUsage,
                    reason: 'usage_limit_exceeded'
                });

                return {
                    valid: false,
                    error: subscriptionType === 'free' 
                        ? 'Free usage limit reached. Upgrade to a paid plan for more generations.'
                        : 'Monthly usage limit reached. Your usage will reset at the beginning of your next billing cycle.',
                    currentUsage: actualUsage,
                    maxUsage: maxUsage,
                    subscriptionType: subscriptionType
                };
            }

            // Validation successful - increment usage
            const newUsage = actualUsage + 1;
            await db.collection('users').doc(userId).update({
                monthlyUsage: newUsage,
                lastActive: new Date().toISOString()
            });

            return {
                valid: true,
                currentUsage: newUsage,
                maxUsage: maxUsage,
                subscriptionType: subscriptionType
            };

        } catch (error) {
            console.error('Subscription validation error:', error);
            return {
                valid: false,
                error: 'Unable to verify subscription status. Please try again.',
                currentUsage: 0,
                maxUsage: 0,
                subscriptionType: 'unknown'
            };
        }
    }

    /**
     * Rate limiting check
     * @param {string} clientIP - Client IP address
     * @returns {Object} Rate limit result
     */
    checkRateLimit(clientIP) {
        try {
            const now = Date.now();
            const userRequests = this.rateLimitMap.get(clientIP) || [];
            
            // Remove requests outside the current window
            const validRequests = userRequests.filter(timestamp => now - timestamp < this.RATE_LIMIT_WINDOW);
            
            // Check if user has exceeded rate limit
            if (validRequests.length >= this.MAX_REQUESTS_PER_MINUTE) {
                // Log rate limit exceeded
                securityLogger.logRateLimitExceeded({
                    clientIP: clientIP,
                    requestCount: validRequests.length,
                    timeWindow: this.RATE_LIMIT_WINDOW / 1000
                });

                return { 
                    allowed: false, 
                    retryAfter: 60,
                    remainingRequests: 0
                };
            }
            
            // Add current request timestamp
            validRequests.push(now);
            this.rateLimitMap.set(clientIP, validRequests);
            
            return { 
                allowed: true,
                remainingRequests: this.MAX_REQUESTS_PER_MINUTE - validRequests.length
            };

        } catch (error) {
            console.error('Rate limit check failed:', error);
            // Allow request on error to avoid breaking functionality
            return { allowed: true, remainingRequests: this.MAX_REQUESTS_PER_MINUTE };
        }
    }

    /**
     * SESSION 4D6: Create comprehensive secure headers with CSP and advanced security
     * @param {string} origin - Request origin
     * @param {Object} options - Header options
     * @returns {Object} Comprehensive security headers
     */
    createSecureHeaders(origin = '', options = {}) {
        const allowedOrigins = [
            'https://www.soltecsol.com',
            'https://ai-generator.soltecsol.com'
        ];

        const allowedOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

        // SESSION 4D6: Comprehensive Content Security Policy
        const cspDirectives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://www.paypal.com https://js.paypal.com https://www.paypalobjects.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "img-src 'self' data: https: blob:",
            "font-src 'self' https://fonts.gstatic.com",
            "connect-src 'self' https://api.openai.com https://www.paypal.com https://api.paypal.com https://api.sandbox.paypal.com",
            "media-src 'self'",
            "object-src 'none'",
            "child-src 'self'",
            "worker-src 'self'",
            "manifest-src 'self'",
            "form-action 'self' https://www.paypal.com",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "upgrade-insecure-requests"
        ];

        // SESSION 4D6: Advanced security headers suite
        const securityHeaders = {
            // CORS Headers
            'Access-Control-Allow-Origin': allowedOrigin,
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Max-Age': '86400', // 24 hours
            
            // Content Security Policy
            'Content-Security-Policy': cspDirectives.join('; '),
            
            // Basic Security Headers
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            
            // HSTS with enhanced configuration
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            
            // Enhanced Referrer Policy
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            
            // Permissions Policy (Feature Policy replacement)
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(self), usb=()',
            
            // Cache Control for sensitive endpoints
            'Cache-Control': 'no-store, no-cache, must-revalidate, private',
            'Pragma': 'no-cache',
            'Expires': '0',
            
            // Additional Security Headers
            'X-DNS-Prefetch-Control': 'off',
            'X-Download-Options': 'noopen',
            'X-Permitted-Cross-Domain-Policies': 'none',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-site',
            
            // Server identification removal
            'Server': 'SolTecSol-AI-Generator/1.0'
        };

        // Override specific headers based on options
        if (options.webhook) {
            // For webhooks, allow more restrictive CSP and different CORS
            securityHeaders['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none';";
            securityHeaders['Access-Control-Allow-Origin'] = options.webhookOrigin || '*';
            securityHeaders['Access-Control-Allow-Credentials'] = 'false';
        }

        if (options.allowCredentials === false) {
            securityHeaders['Access-Control-Allow-Credentials'] = 'false';
        }

        if (options.contentType) {
            securityHeaders['Content-Type'] = options.contentType;
        }

        return securityHeaders;
    }

    /**
     * Comprehensive authentication middleware
     * @param {Object} event - Netlify function event
     * @param {Object} options - Middleware options
     * @returns {Object} Authentication result
     */
    async authenticateRequest(event, options = {}) {
        const {
            requireAuth = true,
            requireSubscription = true,
            requireAdmin = false,
            allowedMethods = ['POST'],
            rateLimit = true
        } = options;

        try {
            const clientIP = event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown';
            const origin = event.headers.origin || event.headers.Origin || '';
            const headers = this.createSecureHeaders(origin);

            // Handle preflight requests
            if (event.httpMethod === 'OPTIONS') {
                return {
                    success: true,
                    response: {
                        statusCode: 200,
                        headers,
                        body: ''
                    }
                };
            }

            // Validate HTTP method
            if (!allowedMethods.includes(event.httpMethod)) {
                return {
                    success: false,
                    response: {
                        statusCode: 405,
                        headers,
                        body: JSON.stringify({ 
                            error: 'Method not allowed',
                            allowed: allowedMethods
                        })
                    }
                };
            }

            // Rate limiting check
            if (rateLimit) {
                const rateLimitCheck = this.checkRateLimit(clientIP);
                if (!rateLimitCheck.allowed) {
                    return {
                        success: false,
                        response: {
                            statusCode: 429,
                            headers: {
                                ...headers,
                                'Retry-After': rateLimitCheck.retryAfter.toString(),
                                'X-RateLimit-Limit': this.MAX_REQUESTS_PER_MINUTE.toString(),
                                'X-RateLimit-Remaining': '0',
                                'X-RateLimit-Reset': (Date.now() + this.RATE_LIMIT_WINDOW).toString()
                            },
                            body: JSON.stringify({
                                error: 'Rate limit exceeded',
                                retryAfter: rateLimitCheck.retryAfter,
                                message: `Too many requests. Limit: ${this.MAX_REQUESTS_PER_MINUTE} per minute.`
                            })
                        }
                    };
                }
            }

            let user = null;
            let subscription = null;
            let adminData = null;

            // Authentication validation
            if (requireAuth) {
                const authValidation = await this.validateAuthorizationHeader(event.headers);
                if (!authValidation.valid) {
                    return {
                        success: false,
                        response: {
                            statusCode: authValidation.statusCode,
                            headers,
                            body: JSON.stringify({
                                error: authValidation.error,
                                ...(authValidation.code && { code: authValidation.code }),
                                ...(authValidation.emailVerified === false && { emailVerified: false })
                            })
                        }
                    };
                }
                user = authValidation.user;

                // SESSION 4D3: Admin role validation
                if (requireAdmin) {
                    const adminValidation = await this.validateAdminRole(user.uid, user.email);
                    if (!adminValidation.valid) {
                        return {
                            success: false,
                            response: {
                                statusCode: adminValidation.statusCode,
                                headers,
                                body: JSON.stringify({
                                    error: adminValidation.error,
                                    code: 'INSUFFICIENT_PRIVILEGES'
                                })
                            }
                        };
                    }
                    adminData = adminValidation.adminData;
                }

                // Subscription validation
                if (requireSubscription) {
                    const subscriptionValidation = await this.validateUserSubscription(user.uid);
                    if (!subscriptionValidation.valid) {
                        return {
                            success: false,
                            response: {
                                statusCode: 403,
                                headers,
                                body: JSON.stringify({
                                    error: subscriptionValidation.error,
                                    currentUsage: subscriptionValidation.currentUsage,
                                    maxUsage: subscriptionValidation.maxUsage,
                                    subscriptionType: subscriptionValidation.subscriptionType
                                })
                            }
                        };
                    }
                    subscription = subscriptionValidation;
                }
            }

            return {
                success: true,
                headers,
                user,
                subscription,
                clientIP
            };

        } catch (error) {
            console.error('Authentication middleware error:', error);
            return {
                success: false,
                response: {
                    statusCode: 500,
                    headers: this.createSecureHeaders(),
                    body: JSON.stringify({
                        error: 'Authentication service unavailable',
                        message: 'Please try again later.'
                    })
                }
            };
        }
    }

    /**
     * Get current billing period for subscription management
     * @returns {string} Current billing period (YYYY-MM format)
     */
    getCurrentBillingPeriod() {
        const now = new Date();
        return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    }

    /**
     * Check if token has been used before (replay attack prevention)
     * @param {string} tokenId - Token identifier (jti or iat)
     * @returns {boolean} True if token was already used
     */
    async isTokenReplayed(tokenId) {
        try {
            if (!tokenId || typeof tokenId !== 'string') {
                console.warn('Invalid token ID provided for replay check');
                return true; // Fail secure - reject invalid token IDs
            }
            
            const tokenRecord = this.usedTokens.get(tokenId);
            if (!tokenRecord) {
                return false; // Token not used before
            }
            
            // Check if token record is still within the replay window
            const now = Date.now();
            const isWithinWindow = (now - tokenRecord) < this.TOKEN_REPLAY_WINDOW;
            
            if (!isWithinWindow) {
                // Token record is old, remove it and allow
                this.usedTokens.delete(tokenId);
                return false;
            }
            
            return true; // Token was used within the replay window
        } catch (error) {
            console.error('Token replay check failed:', error);
            securityLogger.logOperationFailure({
                operation: 'token_replay_check',
                error: error.message,
                endpoint: 'firebase-auth-middleware'
            });
            return true; // Fail secure - reject on error
        }
    }
    
    /**
     * Record token usage to prevent replay attacks
     * @param {string} tokenId - Token identifier (jti or iat)
     */
    async recordTokenUsage(tokenId) {
        try {
            if (!tokenId || typeof tokenId !== 'string') {
                console.warn('Invalid token ID provided for usage recording');
                return;
            }
            
            const now = Date.now();
            this.usedTokens.set(tokenId, now);
            
            // Log token usage for security monitoring
            securityLogger.log('DEBUG', 'TOKEN_USAGE_RECORDED', {
                tokenId: tokenId.substring(0, 8) + '...', // Partial token ID for logging
                timestamp: new Date(now).toISOString(),
                usedTokensCount: this.usedTokens.size
            });
            
        } catch (error) {
            console.error('Token usage recording failed:', error);
            securityLogger.logOperationFailure({
                operation: 'token_usage_recording',
                error: error.message,
                endpoint: 'firebase-auth-middleware'
            });
        }
    }

    /**
     * SESSION 4D3: Enhanced RBAC - Validate admin role for user
     * @param {string} userId - User ID
     * @param {string} email - User email
     * @returns {Object} Admin validation result
     */
    async validateAdminRole(userId, email) {
        try {
            if (!userId || !email) {
                return {
                    valid: false,
                    error: 'Invalid user credentials',
                    statusCode: 401
                };
            }

            const db = getFirestore();
            
            // Check if user has admin role in Firestore
            const userDoc = await db.collection('users').doc(userId).get();
            
            if (!userDoc.exists) {
                return {
                    valid: false,
                    error: 'User not found in database',
                    statusCode: 404
                };
            }

            const userData = userDoc.data();
            
            // SECURITY: Check for admin role
            if (userData.role !== 'admin' && userData.isAdmin !== true) {
                // Log unauthorized admin access attempt
                securityLogger.logUnauthorizedAdminAccess({
                    userId: userId,
                    email: email,
                    attemptedResource: 'admin_endpoint',
                    userRole: userData.role || 'none',
                    timestamp: new Date().toISOString()
                });

                return {
                    valid: false,
                    error: 'Insufficient privileges - admin access required',
                    statusCode: 403
                };
            }

            // SECURITY: Additional admin verification checks
            const adminEmail = process.env.ADMIN_EMAIL;
            if (adminEmail && email !== adminEmail) {
                securityLogger.logUnauthorizedAdminAccess({
                    userId: userId,
                    email: email,
                    expectedEmail: adminEmail,
                    reason: 'email_mismatch',
                    timestamp: new Date().toISOString()
                });

                return {
                    valid: false,
                    error: 'Admin email verification failed',
                    statusCode: 403
                };
            }

            // Log successful admin access
            securityLogger.logAdminAccess({
                userId: userId,
                email: email,
                timestamp: new Date().toISOString()
            });

            return {
                valid: true,
                adminData: {
                    userId: userId,
                    email: email,
                    role: userData.role,
                    isAdmin: userData.isAdmin,
                    adminSince: userData.adminSince
                }
            };

        } catch (error) {
            console.error('Admin role validation error:', error);
            
            securityLogger.logAdminValidationError({
                userId: userId,
                email: email,
                error: error.message,
                timestamp: new Date().toISOString()
            });

            return {
                valid: false,
                error: 'Admin validation service unavailable',
                statusCode: 500
            };
        }
    }

    /**
     * Clean up old rate limit entries and used tokens
     */
    cleanup() {
        try {
            const now = Date.now();
            
            // Clean rate limit entries
            for (const [ip, requests] of this.rateLimitMap.entries()) {
                const validRequests = requests.filter(timestamp => now - timestamp < this.RATE_LIMIT_WINDOW);
                if (validRequests.length === 0) {
                    this.rateLimitMap.delete(ip);
                } else {
                    this.rateLimitMap.set(ip, validRequests);
                }
            }
            
            // Clean old token records
            for (const [tokenId, timestamp] of this.usedTokens.entries()) {
                if (now - timestamp > this.TOKEN_REPLAY_WINDOW) {
                    this.usedTokens.delete(tokenId);
                }
            }
        } catch (error) {
            console.error('Cleanup failed:', error);
        }
    }
}

// Export singleton instance
const firebaseAuthMiddleware = new FirebaseAuthMiddleware();

// Periodic cleanup
setInterval(() => {
    firebaseAuthMiddleware.cleanup();
}, 5 * 60 * 1000); // Clean every 5 minutes

module.exports = firebaseAuthMiddleware;