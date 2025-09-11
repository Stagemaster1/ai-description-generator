// Cross-Domain Authentication Module for SolTecSol
// Handles secure authentication between www.soltecsol.com and ai-generator.soltecsol.com
// SESSION 4B Implementation

const { getAuth } = require('../../firebase-config');
const jwt = require('jsonwebtoken');
const firebaseAuthMiddleware = require('./firebase-auth-middleware');

// SECURITY: Domain whitelist for cross-domain authentication
const ALLOWED_DOMAINS = [
    'https://www.soltecsol.com',
    'https://ai-generator.soltecsol.com'
];

// SECURITY: Cookie configuration for cross-domain authentication
const COOKIE_CONFIG = {
    // Primary authentication cookie
    AUTH_COOKIE: {
        name: 'soltecsol_auth_token',
        domain: '.soltecsol.com', // Works across all subdomains
        httpOnly: true,
        secure: true,
        sameSite: 'Lax', // Allows cross-subdomain requests
        maxAge: 3600, // 1 hour
        path: '/'
    },
    // CSRF protection cookie
    CSRF_COOKIE: {
        name: 'soltecsol_csrf_token',
        domain: '.soltecsol.com',
        httpOnly: false, // Needs to be accessible by JavaScript for CSRF header
        secure: true,
        sameSite: 'Strict', // Strict CSRF protection
        maxAge: 3600, // 1 hour
        path: '/'
    }
};

// SESSION 4D4: Enhanced rate limiting for cross-domain authentication
const authAttempts = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const MAX_AUTH_ATTEMPTS = 5; // 5 attempts per minute per IP
const FAILED_AUTH_LOCKOUT = 15 * 60 * 1000; // 15 minute lockout after too many failures
const failedAttempts = new Map(); // Track failed authentication attempts

exports.handler = async (event, context) => {
    // SESSION 4D4: Use centralized middleware for initial request processing
    const middlewareResult = await firebaseAuthMiddleware.authenticateRequest(event, {
        requireAuth: false, // Handle auth within each action
        requireSubscription: false,
        allowedMethods: ['POST', 'OPTIONS'],
        rateLimit: true
    });
    
    if (!middlewareResult.success) {
        return middlewareResult.response;
    }
    
    const headers = middlewareResult.headers;
    const clientIP = middlewareResult.clientIP;

    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers,
            body: ''
        };
    }

    // Only allow POST requests for authentication
    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    try {
        // SESSION 4D4: Enhanced security checks before processing
        if (!checkAuthRateLimit(clientIP)) {
            return {
                statusCode: 429,
                headers: {
                    ...headers,
                    'Retry-After': '60'
                },
                body: JSON.stringify({ 
                    error: 'Too many authentication attempts. Please try again later.',
                    retryAfter: 60,
                    code: 'RATE_LIMIT_EXCEEDED'
                })
            };
        }
        
        // SESSION 4D4: Check for failed authentication lockout
        if (isIPLocked(clientIP)) {
            return {
                statusCode: 429,
                headers: {
                    ...headers,
                    'Retry-After': '900' // 15 minutes
                },
                body: JSON.stringify({ 
                    error: 'IP temporarily locked due to multiple failed authentication attempts.',
                    retryAfter: 900,
                    code: 'IP_LOCKED'
                })
            };
        }

        const { action, idToken, csrfToken } = JSON.parse(event.body || '{}');

        switch (action) {
            case 'authenticate':
                return await authenticateUser(idToken, csrfToken, headers, clientIP);
            case 'verify':
                return await verifyAuthentication(event.headers, headers);
            case 'verify_admin': // SESSION 4D4: RBAC integration for cross-domain admin access
                return await verifyAdminAuthentication(event.headers, headers);
            case 'logout':
                return await logoutUser(headers);
            case 'refresh': // SESSION 4D4: Add token refresh capability
                return await refreshAuthentication(event.headers, headers);
            default:
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ 
                        error: 'Invalid action',
                        validActions: ['authenticate', 'verify', 'verify_admin', 'logout', 'refresh']
                    })
                };
        }
    } catch (error) {
        console.error('Cross-domain auth error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Authentication service temporarily unavailable',
                message: 'Please try again later' 
            })
        };
    }
};

// SESSION 4D4: Enhanced authenticate user with comprehensive validation
async function authenticateUser(idToken, csrfToken, headers, clientIP) {
    try {
        if (!idToken) {
            recordFailedAuthentication(clientIP, 'missing_token');
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'ID token required',
                    code: 'MISSING_TOKEN'
                })
            };
        }

        // SESSION 4D4: Use enhanced token validation from middleware
        const tokenValidation = await firebaseAuthMiddleware.verifyIdToken(idToken);
        if (!tokenValidation.valid) {
            recordFailedAuthentication(clientIP, tokenValidation.error);
            return {
                statusCode: tokenValidation.statusCode,
                headers,
                body: JSON.stringify({ 
                    error: tokenValidation.error,
                    code: tokenValidation.code || 'TOKEN_VALIDATION_FAILED',
                    ...(tokenValidation.emailVerified === false && { emailVerified: false })
                })
            };
        }
        
        const decodedToken = tokenValidation.user;
        
        // SESSION 4D4: Additional cross-domain specific validations
        if (!decodedToken.emailVerified) {
            recordFailedAuthentication(clientIP, 'email_not_verified');
            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({ 
                    error: 'Email verification required for cross-domain authentication',
                    emailVerified: false,
                    code: 'EMAIL_NOT_VERIFIED',
                    message: 'Please verify your email address before accessing the AI generator'
                })
            };
        }
        
        // SESSION 4D4: Session age validation for cross-domain security
        const currentTime = Math.floor(Date.now() / 1000);
        const authTime = decodedToken.authTime;
        const maxCrossDomainSessionAge = 12 * 60 * 60; // 12 hours for cross-domain
        
        if (currentTime - authTime > maxCrossDomainSessionAge) {
            recordFailedAuthentication(clientIP, 'session_too_old');
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ 
                    error: 'Session too old for cross-domain authentication',
                    code: 'SESSION_TOO_OLD',
                    message: 'Please sign in again for enhanced cross-domain security'
                })
            };
        }

        // Generate secure tokens with enhanced payload
        const authToken = generateSecureAuthToken(decodedToken);
        const newCsrfToken = generateCSRFToken();

        // Set secure cross-domain cookies
        const cookieHeaders = [
            ...headers,
            createCookieHeader(COOKIE_CONFIG.AUTH_COOKIE, authToken),
            createCookieHeader(COOKIE_CONFIG.CSRF_COOKIE, newCsrfToken)
        ];

        // Clear failed attempts on successful authentication
        clearFailedAttempts(clientIP);
        
        // Log successful authentication with enhanced details
        console.log(`[SESSION 4D4] Cross-domain authentication successful for user: ${decodedToken.uid} from IP: ${clientIP} at ${new Date().toISOString()}`);

        return {
            statusCode: 200,
            headers: cookieHeaders,
            body: JSON.stringify({
                success: true,
                user: {
                    uid: decodedToken.uid,
                    email: decodedToken.email,
                    emailVerified: decodedToken.emailVerified
                },
                csrfToken: newCsrfToken,
                sessionInfo: {
                    authTime: decodedToken.authTime,
                    validUntil: currentTime + (12 * 60 * 60), // 12 hour validity
                    domain: 'cross-domain'
                },
                message: 'Cross-domain authentication successful'
            })
        };
    } catch (error) {
        console.error('[SESSION 4D4] Authentication failed:', error);
        recordFailedAuthentication(clientIP, error.code || 'unknown_error');
        
        if (error.code === 'auth/id-token-expired') {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ 
                    error: 'Token expired', 
                    code: 'TOKEN_EXPIRED',
                    message: 'Please refresh your authentication token'
                })
            };
        }

        if (error.code === 'auth/id-token-revoked') {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ 
                    error: 'Token revoked',
                    code: 'TOKEN_REVOKED',
                    message: 'Please sign in again'
                })
            };
        }

        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ 
                error: 'Invalid authentication token',
                code: 'AUTHENTICATION_FAILED',
                message: 'Authentication failed'
            })
        };
    }
}

// SESSION 4D4: Enhanced verify existing authentication across domains
async function verifyAuthentication(requestHeaders, responseHeaders) {
    try {
        const authCookie = extractCookieValue(requestHeaders.cookie, COOKIE_CONFIG.AUTH_COOKIE.name);
        const csrfCookie = extractCookieValue(requestHeaders.cookie, COOKIE_CONFIG.CSRF_COOKIE.name);

        if (!authCookie) {
            return {
                statusCode: 401,
                headers: responseHeaders,
                body: JSON.stringify({ 
                    error: 'No authentication found',
                    authenticated: false,
                    code: 'NO_AUTH_COOKIE'
                })
            };
        }

        // SESSION 4D4: Enhanced token verification with comprehensive checks
        const userInfo = verifyAuthToken(authCookie);
        if (!userInfo) {
            return {
                statusCode: 401,
                headers: responseHeaders,
                body: JSON.stringify({ 
                    error: 'Invalid authentication token',
                    authenticated: false,
                    code: 'INVALID_AUTH_TOKEN'
                })
            };
        }
        
        // SESSION 4D4: Check token expiration with buffer
        const currentTime = Math.floor(Date.now() / 1000);
        const tokenBuffer = 5 * 60; // 5 minute buffer before expiration
        
        if (userInfo.exp && (currentTime + tokenBuffer) > userInfo.exp) {
            return {
                statusCode: 401,
                headers: responseHeaders,
                body: JSON.stringify({ 
                    error: 'Authentication token near expiration',
                    authenticated: false,
                    code: 'TOKEN_NEAR_EXPIRY',
                    refreshRequired: true
                })
            };
        }

        // CRITICAL: Re-verify email verification status
        if (!userInfo.email_verified) {
            return {
                statusCode: 403,
                headers: responseHeaders,
                body: JSON.stringify({ 
                    error: 'Email verification required',
                    authenticated: false,
                    emailVerified: false,
                    code: 'EMAIL_NOT_VERIFIED'
                })
            };
        }
        
        // SESSION 4D4: Cross-domain session age validation
        const sessionAge = currentTime - userInfo.iat;
        const maxCrossDomainAge = 12 * 60 * 60; // 12 hours
        
        if (sessionAge > maxCrossDomainAge) {
            return {
                statusCode: 401,
                headers: responseHeaders,
                body: JSON.stringify({ 
                    error: 'Cross-domain session expired',
                    authenticated: false,
                    code: 'CROSS_DOMAIN_SESSION_EXPIRED',
                    refreshRequired: true
                })
            };
        }

        return {
            statusCode: 200,
            headers: responseHeaders,
            body: JSON.stringify({
                authenticated: true,
                user: {
                    uid: userInfo.uid,
                    email: userInfo.email,
                    emailVerified: userInfo.email_verified
                },
                csrfToken: csrfCookie,
                sessionInfo: {
                    age: sessionAge,
                    validUntil: userInfo.exp,
                    refreshRecommended: sessionAge > (8 * 60 * 60) // Recommend refresh after 8 hours
                }
            })
        };
    } catch (error) {
        console.error('[SESSION 4D4] Authentication verification failed:', error);
        return {
            statusCode: 401,
            headers: responseHeaders,
            body: JSON.stringify({ 
                error: 'Authentication verification failed',
                authenticated: false,
                code: 'VERIFICATION_ERROR'
            })
        };
    }
}

// SESSION 4D4: RBAC integration - Verify admin authentication across domains
async function verifyAdminAuthentication(requestHeaders, responseHeaders) {
    try {
        // First verify regular authentication
        const authResult = await verifyAuthentication(requestHeaders, responseHeaders);
        
        if (authResult.statusCode !== 200) {
            return authResult; // Return authentication failure
        }
        
        const authData = JSON.parse(authResult.body);
        const user = authData.user;
        
        // Use firebase-auth-middleware for admin role validation
        const adminValidation = await firebaseAuthMiddleware.validateAdminRole(user.uid, user.email);
        
        if (!adminValidation.valid) {
            return {
                statusCode: adminValidation.statusCode,
                headers: responseHeaders,
                body: JSON.stringify({
                    authenticated: true, // User is authenticated
                    authorized: false, // But not authorized as admin
                    error: adminValidation.error,
                    code: 'INSUFFICIENT_ADMIN_PRIVILEGES',
                    user: {
                        uid: user.uid,
                        email: user.email,
                        emailVerified: user.emailVerified
                    }
                })
            };
        }
        
        // Admin verification successful
        return {
            statusCode: 200,
            headers: responseHeaders,
            body: JSON.stringify({
                authenticated: true,
                authorized: true,
                isAdmin: true,
                user: {
                    uid: user.uid,
                    email: user.email,
                    emailVerified: user.emailVerified
                },
                adminData: adminValidation.adminData,
                csrfToken: authData.csrfToken,
                sessionInfo: authData.sessionInfo
            })
        };
        
    } catch (error) {
        console.error('[SESSION 4D4] Admin authentication verification failed:', error);
        return {
            statusCode: 500,
            headers: responseHeaders,
            body: JSON.stringify({ 
                authenticated: false,
                authorized: false,
                error: 'Admin authentication verification failed',
                code: 'ADMIN_VERIFICATION_ERROR'
            })
        };
    }
}

// SESSION 4D4: Enhanced refresh authentication for cross-domain
async function refreshAuthentication(requestHeaders, responseHeaders) {
    try {
        const authCookie = extractCookieValue(requestHeaders.cookie, COOKIE_CONFIG.AUTH_COOKIE.name);
        
        if (!authCookie) {
            return {
                statusCode: 401,
                headers: responseHeaders,
                body: JSON.stringify({ 
                    error: 'No authentication found for refresh',
                    code: 'NO_AUTH_FOR_REFRESH'
                })
            };
        }
        
        // Verify current token (even if near expiry)
        const userInfo = verifyAuthToken(authCookie, { ignoreExpiration: false });
        if (!userInfo) {
            return {
                statusCode: 401,
                headers: responseHeaders,
                body: JSON.stringify({ 
                    error: 'Invalid token for refresh',
                    code: 'INVALID_REFRESH_TOKEN'
                })
            };
        }
        
        // SESSION 4D4: Enhanced token refresh with role preservation
        const newAuthToken = generateSecureAuthToken({
            uid: userInfo.uid,
            email: userInfo.email,
            email_verified: userInfo.email_verified,
            // Preserve any admin/role information from original token
            ...(userInfo.isAdmin && { isAdmin: userInfo.isAdmin }),
            ...(userInfo.role && { role: userInfo.role })
        });
        const newCsrfToken = generateCSRFToken();
        
        // Set refreshed cross-domain cookies
        const cookieHeaders = [
            ...responseHeaders,
            createCookieHeader(COOKIE_CONFIG.AUTH_COOKIE, newAuthToken),
            createCookieHeader(COOKIE_CONFIG.CSRF_COOKIE, newCsrfToken)
        ];
        
        console.log(`[SESSION 4D4] Authentication refreshed for user: ${userInfo.uid}`);
        
        return {
            statusCode: 200,
            headers: cookieHeaders,
            body: JSON.stringify({
                success: true,
                user: {
                    uid: userInfo.uid,
                    email: userInfo.email,
                    emailVerified: userInfo.email_verified
                },
                csrfToken: newCsrfToken,
                message: 'Authentication refreshed successfully'
            })
        };
    } catch (error) {
        console.error('[SESSION 4D4] Authentication refresh failed:', error);
        return {
            statusCode: 500,
            headers: responseHeaders,
            body: JSON.stringify({ 
                error: 'Authentication refresh failed',
                code: 'REFRESH_ERROR'
            })
        };
    }
}

// Logout user and clear cross-domain cookies
async function logoutUser(headers) {
    const cookieHeaders = [
        ...headers,
        createCookieHeader(COOKIE_CONFIG.AUTH_COOKIE, '', { expired: true }),
        createCookieHeader(COOKIE_CONFIG.CSRF_COOKIE, '', { expired: true })
    ];

    return {
        statusCode: 200,
        headers: cookieHeaders,
        body: JSON.stringify({
            success: true,
            message: 'Logged out successfully'
        })
    };
}

// SESSION 4D4: Enhanced secure headers with RBAC and cross-domain protection
function createSecureHeaders(event) {
    const origin = event.headers.origin || event.headers.Origin || '';
    const isValidOrigin = ALLOWED_DOMAINS.includes(origin);
    
    return {
        'Access-Control-Allow-Origin': isValidOrigin ? origin : ALLOWED_DOMAINS[0],
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token, X-Admin-Token',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Credentials': 'true',
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        // SESSION 4D4: Enhanced security headers for RBAC
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'X-Cross-Domain-Auth': 'soltecsol-v4d4',
        'Cache-Control': 'no-store, no-cache, must-revalidate, private'
    };
}

// SESSION 4D4: Enhanced secure authentication token generation with RBAC support
function generateSecureAuthToken(decodedFirebaseToken) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        uid: decodedFirebaseToken.uid,
        email: decodedFirebaseToken.email,
        email_verified: decodedFirebaseToken.email_verified,
        iat: now,
        exp: now + (12 * 60 * 60), // SESSION 4D4: 12 hour validity for cross-domain
        iss: 'soltecsol-cross-domain-auth-v4d4',
        aud: 'soltecsol-cross-domain',
        jti: require('crypto').randomBytes(16).toString('hex'), // SESSION 4D4: Unique token ID
        crossDomain: true,
        securityLevel: 'enhanced',
        // SESSION 4D4: RBAC support in cross-domain tokens
        ...(decodedFirebaseToken.isAdmin && { isAdmin: decodedFirebaseToken.isAdmin }),
        ...(decodedFirebaseToken.role && { role: decodedFirebaseToken.role })
    };

    // CRITICAL: Use cryptographically signed JWT with enhanced algorithm
    return jwt.sign(payload, process.env.JWT_SECRET, { 
        algorithm: 'HS256',
        noTimestamp: false
    });
}

// Generate CSRF token
function generateCSRFToken() {
    return require('crypto').randomBytes(32).toString('hex');
}

// SESSION 4D4: Enhanced authentication token verification
function verifyAuthToken(token, options = {}) {
    try {
        // SESSION 4D4: Enhanced verification options
        const verifyOptions = {
            algorithms: ['HS256'],
            issuer: ['soltecsol-cross-domain-auth', 'soltecsol-cross-domain-auth-v4d4'],
            audience: 'soltecsol-cross-domain',
            ignoreExpiration: options.ignoreExpiration || false
        };
        
        // CRITICAL: Verify signature with enhanced options
        const payload = jwt.verify(token, process.env.JWT_SECRET, verifyOptions);
        
        // SESSION 4D4: Additional payload validation
        if (!payload.uid || !payload.email) {
            console.error('[SESSION 4D4] Token missing required fields');
            return null;
        }
        
        // SESSION 4D4: Cross-domain specific validation
        if (payload.crossDomain !== true) {
            console.error('[SESSION 4D4] Token not marked for cross-domain use');
            return null;
        }
        
        return payload;
    } catch (error) {
        console.error('[SESSION 4D4] Token verification failed:', error.message);
        return null;
    }
}

// Create cookie header string
function createCookieHeader(cookieConfig, value, options = {}) {
    const { name, domain, httpOnly, secure, sameSite, maxAge, path } = cookieConfig;
    
    let cookieString = `${name}=${value}; Domain=${domain}; Path=${path};`;
    
    if (options.expired) {
        cookieString += ' Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT;';
    } else {
        cookieString += ` Max-Age=${maxAge};`;
    }
    
    if (httpOnly) cookieString += ' HttpOnly;';
    if (secure) cookieString += ' Secure;';
    if (sameSite) cookieString += ` SameSite=${sameSite};`;

    return ['Set-Cookie', cookieString];
}

// Extract cookie value from cookie string
function extractCookieValue(cookieHeader, cookieName) {
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

// SESSION 4D4: Enhanced rate limiting for authentication attempts
function checkAuthRateLimit(clientIP) {
    const now = Date.now();
    const attempts = authAttempts.get(clientIP) || [];
    const validAttempts = attempts.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
    
    if (validAttempts.length >= MAX_AUTH_ATTEMPTS) {
        return false;
    }
    
    validAttempts.push(now);
    authAttempts.set(clientIP, validAttempts);
    return true;
}

// SESSION 4D4: Check if IP is locked due to failed authentication attempts
function isIPLocked(clientIP) {
    const failedData = failedAttempts.get(clientIP);
    if (!failedData) return false;
    
    const now = Date.now();
    
    // Check if lockout period has expired
    if (failedData.lockedUntil && now > failedData.lockedUntil) {
        failedAttempts.delete(clientIP);
        return false;
    }
    
    return failedData.lockedUntil && now < failedData.lockedUntil;
}

// SESSION 4D4: Record failed authentication attempt
function recordFailedAuthentication(clientIP, reason) {
    const now = Date.now();
    const failedData = failedAttempts.get(clientIP) || { count: 0, attempts: [] };
    
    // Clean old attempts (older than 1 hour)
    failedData.attempts = failedData.attempts.filter(attempt => 
        now - attempt.timestamp < (60 * 60 * 1000)
    );
    
    // Add new failed attempt
    failedData.attempts.push({ timestamp: now, reason });
    failedData.count = failedData.attempts.length;
    
    // Lock IP if too many failures (10 failures in 1 hour = 15 minute lockout)
    if (failedData.count >= 10) {
        failedData.lockedUntil = now + FAILED_AUTH_LOCKOUT;
        console.log(`[SESSION 4D4] IP ${clientIP} locked for 15 minutes due to ${failedData.count} failed authentication attempts`);
    }
    
    failedAttempts.set(clientIP, failedData);
}

// SESSION 4D4: Clear failed attempts on successful authentication
function clearFailedAttempts(clientIP) {
    failedAttempts.delete(clientIP);
}

// SESSION 4D4: Enhanced cleanup for authentication attempts and failed logins
setInterval(() => {
    const now = Date.now();
    
    // Clean rate limit attempts
    for (const [ip, attempts] of authAttempts.entries()) {
        const validAttempts = attempts.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
        if (validAttempts.length === 0) {
            authAttempts.delete(ip);
        } else {
            authAttempts.set(ip, validAttempts);
        }
    }
    
    // Clean expired failed authentication records
    for (const [ip, failedData] of failedAttempts.entries()) {
        // Remove if lockout has expired and no recent failures
        if (failedData.lockedUntil && now > failedData.lockedUntil) {
            const recentFailures = failedData.attempts.filter(attempt => 
                now - attempt.timestamp < (60 * 60 * 1000) // 1 hour
            );
            
            if (recentFailures.length === 0) {
                failedAttempts.delete(ip);
            } else {
                failedData.attempts = recentFailures;
                failedData.count = recentFailures.length;
                failedData.lockedUntil = null;
                failedAttempts.set(ip, failedData);
            }
        }
    }
}, 5 * 60 * 1000); // Clean every 5 minutes