// Cross-Domain Server-Side Validation Module
// Provides consistent authentication validation across all endpoints
// SESSION 4B Implementation - Server Side

const { getAuth } = require('./firebase-config');
const jwt = require('jsonwebtoken');

// SECURITY: Domain validation for cross-domain requests
const ALLOWED_DOMAINS = [
    'https://www.soltecsol.com',
    'https://ai-generator.soltecsol.com'
];

// SECURITY: Cookie configuration constants
const COOKIE_NAMES = {
    AUTH_COOKIE: 'soltecsol_auth_token',
    CSRF_COOKIE: 'soltecsol_csrf_token'
};

// Cross-domain authentication validator class
class CrossDomainValidator {
    constructor() {
        this.rateLimitMap = new Map();
        this.RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
        this.MAX_REQUESTS_PER_MINUTE = 30;
    }

    // Validate origin for cross-domain requests
    validateOrigin(origin) {
        if (!origin) {
            // Allow server-to-server requests (webhooks, etc.)
            return { valid: true, allowedOrigin: ALLOWED_DOMAINS[0] };
        }

        const isValidOrigin = ALLOWED_DOMAINS.includes(origin);
        return {
            valid: isValidOrigin,
            allowedOrigin: isValidOrigin ? origin : ALLOWED_DOMAINS[0]
        };
    }

    // Create secure CORS headers
    createCORSHeaders(allowedOrigin, includeCredentials = true) {
        const headers = {
            'Access-Control-Allow-Origin': allowedOrigin,
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        };

        if (includeCredentials) {
            headers['Access-Control-Allow-Credentials'] = 'true';
        }

        return headers;
    }

    // Rate limiting check
    checkRateLimit(clientIP) {
        const now = Date.now();
        const userRequests = this.rateLimitMap.get(clientIP) || [];
        
        // Remove requests outside the current window
        const validRequests = userRequests.filter(timestamp => now - timestamp < this.RATE_LIMIT_WINDOW);
        
        // Check if user has exceeded rate limit
        if (validRequests.length >= this.MAX_REQUESTS_PER_MINUTE) {
            return { allowed: false, retryAfter: 60 };
        }
        
        // Add current request timestamp
        validRequests.push(now);
        this.rateLimitMap.set(clientIP, validRequests);
        
        return { allowed: true };
    }

    // Validate Firebase authentication token
    async validateFirebaseToken(authHeader) {
        try {
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return {
                    valid: false,
                    error: 'Missing or invalid authorization header',
                    statusCode: 401
                };
            }

            const idToken = authHeader.substring(7);
            const auth = getAuth();
            const decodedToken = await auth.verifyIdToken(idToken, true); // checkRevoked = true

            // CRITICAL: Enforce email verification for cross-domain access
            if (!decodedToken.email_verified) {
                return {
                    valid: false,
                    error: 'Email verification required for cross-domain access',
                    statusCode: 403,
                    emailVerified: false
                };
            }

            return {
                valid: true,
                user: {
                    uid: decodedToken.uid,
                    email: decodedToken.email,
                    emailVerified: decodedToken.email_verified,
                    authTime: decodedToken.auth_time
                }
            };

        } catch (error) {
            console.error('Firebase token validation failed:', error);

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

            return {
                valid: false,
                error: 'Invalid authentication token',
                statusCode: 401
            };
        }
    }

    // Validate cross-domain cookie authentication
    validateCookieAuth(cookieHeader) {
        try {
            if (!cookieHeader) {
                return {
                    valid: false,
                    error: 'No authentication cookies found',
                    statusCode: 401
                };
            }

            const authCookie = this.extractCookieValue(cookieHeader, COOKIE_NAMES.AUTH_COOKIE);
            
            if (!authCookie) {
                return {
                    valid: false,
                    error: 'Authentication cookie missing',
                    statusCode: 401
                };
            }

            // Verify auth token structure (simplified for demo)
            const userInfo = this.verifyAuthToken(authCookie);
            if (!userInfo) {
                return {
                    valid: false,
                    error: 'Invalid authentication cookie',
                    statusCode: 401
                };
            }

            // CRITICAL: Re-verify email verification status
            if (!userInfo.email_verified) {
                return {
                    valid: false,
                    error: 'Email verification required',
                    statusCode: 403,
                    emailVerified: false
                };
            }

            return {
                valid: true,
                user: userInfo
            };

        } catch (error) {
            console.error('Cookie authentication validation failed:', error);
            return {
                valid: false,
                error: 'Cookie validation failed',
                statusCode: 401
            };
        }
    }

    // Validate CSRF token for secure operations
    validateCSRFToken(requestHeaders, cookieHeader) {
        const csrfHeaderToken = requestHeaders['x-csrf-token'] || requestHeaders['X-CSRF-Token'];
        const csrfCookieToken = this.extractCookieValue(cookieHeader, COOKIE_NAMES.CSRF_COOKIE);

        if (!csrfHeaderToken || !csrfCookieToken) {
            return {
                valid: false,
                error: 'CSRF token missing',
                statusCode: 403
            };
        }

        if (csrfHeaderToken !== csrfCookieToken) {
            return {
                valid: false,
                error: 'CSRF token mismatch',
                statusCode: 403
            };
        }

        return { valid: true };
    }

    // Extract cookie value from cookie string
    extractCookieValue(cookieHeader, cookieName) {
        if (!cookieHeader) return null;
        
        const cookies = cookieHeader.split(';');
        for (const cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === cookieName) {
                return value;
            }
        }
        return null;
    }

    // Verify authentication token
    verifyAuthToken(token) {
        try {
            // CRITICAL: Verify signature
            const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithm: 'HS256' });
            return {
                uid: payload.uid,
                email: payload.email,
                email_verified: payload.email_verified
            };
        } catch (error) {
            console.error('Token verification failed:', error);
            return null;
        }
    }

    // Comprehensive validation method for endpoints
    async validateRequest(event, options = {}) {
        const {
            requireAuth = true,
            requireCSRF = false,
            allowedMethods = ['GET', 'POST'],
            rateLimit = true
        } = options;

        const clientIP = event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown';
        const origin = event.headers.origin || event.headers.Origin || '';
        
        // Validate origin
        const originValidation = this.validateOrigin(origin);
        if (!originValidation.valid && origin) {
            return {
                valid: false,
                response: {
                    statusCode: 403,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        error: 'Origin not allowed',
                        message: 'CORS policy violation'
                    })
                }
            };
        }

        const headers = this.createCORSHeaders(originValidation.allowedOrigin);

        // Handle preflight requests
        if (event.httpMethod === 'OPTIONS') {
            return {
                valid: true,
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
                valid: false,
                response: {
                    statusCode: 405,
                    headers,
                    body: JSON.stringify({ error: 'Method not allowed' })
                }
            };
        }

        // Rate limiting check
        if (rateLimit) {
            const rateLimitCheck = this.checkRateLimit(clientIP);
            if (!rateLimitCheck.allowed) {
                return {
                    valid: false,
                    response: {
                        statusCode: 429,
                        headers: {
                            ...headers,
                            'Retry-After': rateLimitCheck.retryAfter.toString()
                        },
                        body: JSON.stringify({
                            error: 'Rate limit exceeded',
                            retryAfter: rateLimitCheck.retryAfter
                        })
                    }
                };
            }
        }

        let user = null;

        // Authentication validation
        if (requireAuth) {
            const authHeader = event.headers.authorization || event.headers.Authorization;
            
            // Try Firebase token first
            if (authHeader) {
                const tokenValidation = await this.validateFirebaseToken(authHeader);
                if (!tokenValidation.valid) {
                    return {
                        valid: false,
                        response: {
                            statusCode: tokenValidation.statusCode,
                            headers,
                            body: JSON.stringify({
                                error: tokenValidation.error,
                                ...(tokenValidation.code && { code: tokenValidation.code }),
                                ...(tokenValidation.emailVerified === false && { emailVerified: false })
                            })
                        }
                    };
                }
                user = tokenValidation.user;
            } else {
                // Try cookie authentication
                const cookieValidation = this.validateCookieAuth(event.headers.cookie);
                if (!cookieValidation.valid) {
                    return {
                        valid: false,
                        response: {
                            statusCode: cookieValidation.statusCode,
                            headers,
                            body: JSON.stringify({
                                error: cookieValidation.error,
                                ...(cookieValidation.emailVerified === false && { emailVerified: false })
                            })
                        }
                    };
                }
                user = cookieValidation.user;
            }
        }

        // CSRF validation for state-changing operations
        if (requireCSRF && ['POST', 'PUT', 'DELETE'].includes(event.httpMethod)) {
            const csrfValidation = this.validateCSRFToken(event.headers, event.headers.cookie);
            if (!csrfValidation.valid) {
                return {
                    valid: false,
                    response: {
                        statusCode: csrfValidation.statusCode,
                        headers,
                        body: JSON.stringify({ error: csrfValidation.error })
                    }
                };
            }
        }

        return {
            valid: true,
            headers,
            user,
            clientIP
        };
    }

    // Clean up old rate limit entries
    cleanup() {
        const now = Date.now();
        for (const [ip, requests] of this.rateLimitMap.entries()) {
            const validRequests = requests.filter(timestamp => now - timestamp < this.RATE_LIMIT_WINDOW);
            if (validRequests.length === 0) {
                this.rateLimitMap.delete(ip);
            } else {
                this.rateLimitMap.set(ip, validRequests);
            }
        }
    }
}

// Export singleton instance
const validator = new CrossDomainValidator();

// Periodic cleanup
setInterval(() => {
    validator.cleanup();
}, 5 * 60 * 1000); // Clean every 5 minutes

module.exports = validator;
