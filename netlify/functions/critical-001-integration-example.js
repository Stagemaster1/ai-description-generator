// CRITICAL-001 INTEGRATION EXAMPLE
// Shows how to integrate the Fail-Safe Authentication Check with existing systems
// Production-ready integration patterns for CRITICAL-001 vulnerability fix

const FailSafeAuthenticationCheck = require('./fail-safe-auth-check-critical-001');
const DistributedTokenReplayPrevention = require('./distributed-token-replay-prevention');
const securityLogger = require('./security-logger');

/**
 * CRITICAL-001 INTEGRATION EXAMPLE
 *
 * This example shows how to integrate the fail-safe authentication check
 * with existing authentication middleware and token replay prevention systems.
 *
 * KEY INTEGRATION POINTS:
 * 1. Replace existing verifyIdToken calls with fail-safe version
 * 2. Maintain compatibility with existing subscription validation
 * 3. Integrate with distributed token replay prevention
 * 4. Ensure fail-safe behavior throughout the authentication chain
 */

class Critical001Integration {
    constructor() {
        // Initialize the fail-safe authentication check
        this.failSafeAuth = new FailSafeAuthenticationCheck();

        // Initialize existing token replay prevention (for compatibility)
        this.tokenReplayPrevention = new DistributedTokenReplayPrevention();

        console.log('CRITICAL-001 Integration initialized with fail-safe authentication');
    }

    /**
     * EXAMPLE 1: Enhanced Firebase Authentication Middleware Integration
     *
     * This shows how to replace the existing verifyIdToken method in
     * enhanced-firebase-auth-middleware.js with the fail-safe version
     */
    async enhancedVerifyIdToken(idToken, ipAddress = null, userAgent = null) {
        const requestContext = {
            ipAddress,
            userAgent,
            timestamp: Date.now()
        };

        try {
            console.log('CRITICAL-001: Using fail-safe authentication for token verification');

            // CRITICAL-001 FIX: Use fail-safe authentication instead of direct Firebase verification
            const authResult = await this.failSafeAuth.performFailSafeAuthentication(idToken, requestContext);

            if (!authResult.authenticated) {
                // Log the authentication failure with proper context
                await this.logAuthenticationFailure(authResult, requestContext);

                return {
                    valid: false,
                    error: authResult.error,
                    statusCode: authResult.statusCode,
                    securityRisk: authResult.securityRisk,
                    responseTime: authResult.operationTime,
                    failSafe: true,
                    reason: authResult.reason
                };
            }

            // CRITICAL-001 FIX: Authentication successful - additional security validation
            const enhancedValidation = await this.performEnhancedSecurityValidation(authResult, requestContext);

            if (!enhancedValidation.valid) {
                return {
                    valid: false,
                    error: enhancedValidation.error,
                    statusCode: enhancedValidation.statusCode,
                    securityRisk: enhancedValidation.securityRisk,
                    responseTime: authResult.operationTime,
                    failSafe: true
                };
            }

            // Log successful authentication
            await this.logSuccessfulAuthentication(authResult, requestContext);

            return {
                valid: true,
                user: authResult.user,
                statusCode: 200,
                securityRisk: authResult.securityRisk,
                responseTime: authResult.operationTime,
                performanceCompliant: authResult.performanceCompliant,
                failSafe: true,
                securityContext: authResult.securityContext
            };

        } catch (error) {
            // CRITICAL-001 FIX: Comprehensive error handling with fail-safe behavior
            await securityLogger.logOperationFailure({
                operation: 'enhanced_fail_safe_token_verification',
                error: error.message,
                requestContext,
                endpoint: 'critical-001-integration'
            });

            return {
                valid: false,
                error: 'Authentication service error',
                statusCode: 500,
                securityRisk: 'CRITICAL',
                failSafe: true,
                systemError: true
            };
        }
    }

    /**
     * EXAMPLE 2: Integration with existing Firebase Auth Middleware
     *
     * This shows how to integrate with the existing firebase-auth-middleware.js
     * authenticateRequest method
     */
    async authenticateRequestWithFailSafe(event, options = {}) {
        const {
            requireAuth = false,
            requireSubscription = false,
            requireAdmin = false,
            allowedMethods = ['GET', 'POST'],
            rateLimit = false
        } = options;

        try {
            // Extract client information
            const clientIP = this.extractClientIP(event);
            const userAgent = event.headers['user-agent'] || event.headers['User-Agent'];
            const origin = event.headers.origin || event.headers.Origin;

            console.log(`CRITICAL-001: Processing request with fail-safe authentication [${event.httpMethod}]`);

            // Method validation
            if (!allowedMethods.includes(event.httpMethod)) {
                return {
                    success: false,
                    response: {
                        statusCode: 405,
                        headers: this.createSecureHeaders(origin),
                        body: JSON.stringify({
                            error: 'Method not allowed',
                            allowedMethods
                        })
                    }
                };
            }

            // CORS preflight handling
            if (event.httpMethod === 'OPTIONS') {
                return {
                    success: true,
                    response: {
                        statusCode: 200,
                        headers: this.createSecureHeaders(origin),
                        body: ''
                    }
                };
            }

            const headers = this.createSecureHeaders(origin);
            let user = null;
            let subscription = null;

            // CRITICAL-001 FIX: Authentication with fail-safe check
            if (requireAuth) {
                const authHeader = event.headers.authorization || event.headers.Authorization;

                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    return {
                        success: false,
                        response: {
                            statusCode: 401,
                            headers,
                            body: JSON.stringify({
                                error: 'Authorization header missing or invalid format',
                                expectedFormat: 'Bearer <token>'
                            })
                        }
                    };
                }

                const idToken = authHeader.substring(7);

                // CRITICAL-001 FIX: Use fail-safe authentication
                const authResult = await this.enhancedVerifyIdToken(idToken, clientIP, userAgent);

                if (!authResult.valid) {
                    return {
                        success: false,
                        response: {
                            statusCode: authResult.statusCode,
                            headers,
                            body: JSON.stringify({
                                error: authResult.error,
                                securityRisk: authResult.securityRisk,
                                failSafe: authResult.failSafe,
                                ...(authResult.reason && { reason: authResult.reason })
                            })
                        }
                    };
                }

                user = authResult.user;

                // Subscription validation (if required)
                if (requireSubscription) {
                    const subscriptionResult = await this.validateUserSubscriptionFailSafe(user.uid);

                    if (!subscriptionResult.valid) {
                        return {
                            success: false,
                            response: {
                                statusCode: 403,
                                headers,
                                body: JSON.stringify({
                                    error: subscriptionResult.error,
                                    currentUsage: subscriptionResult.currentUsage,
                                    maxUsage: subscriptionResult.maxUsage,
                                    subscriptionType: subscriptionResult.subscriptionType
                                })
                            }
                        };
                    }

                    subscription = subscriptionResult;
                }
            }

            return {
                success: true,
                headers,
                user,
                subscription,
                clientIP,
                failSafeEnabled: true
            };

        } catch (error) {
            // CRITICAL-001 FIX: Fail-safe error handling
            console.error('CRITICAL-001: Request authentication error:', error);

            return {
                success: false,
                response: {
                    statusCode: 500,
                    headers: this.createSecureHeaders(),
                    body: JSON.stringify({
                        error: 'Authentication service error',
                        failSafe: true
                    })
                }
            };
        }
    }

    /**
     * EXAMPLE 3: Integration with existing endpoint (e.g., generate.js)
     *
     * This shows how to replace the existing authentication call in endpoints
     */
    async handleGenerateRequest(event, context) {
        console.log('CRITICAL-001: Processing generate request with fail-safe authentication');

        // CRITICAL-001 FIX: Use fail-safe authentication instead of existing middleware
        const authResult = await this.authenticateRequestWithFailSafe(event, {
            requireAuth: true,
            requireSubscription: true,
            allowedMethods: ['POST', 'OPTIONS'],
            rateLimit: true
        });

        if (!authResult.success) {
            return authResult.response;
        }

        const { headers, user, subscription, clientIP } = authResult;

        try {
            // Continue with the existing generate logic...
            const { productUrl, productInfo, brandTone, userId } = JSON.parse(event.body);

            // CRITICAL-001 FIX: Enhanced user ID validation with fail-safe
            const userValidation = await this.validateUserIdWithFailSafe(userId, user.uid, clientIP);

            if (!userValidation.valid) {
                return {
                    statusCode: userValidation.statusCode,
                    headers,
                    body: JSON.stringify({
                        error: userValidation.error,
                        securityRisk: userValidation.securityRisk,
                        failSafe: true
                    })
                };
            }

            // Continue with generation logic...
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    message: 'Generation request processed with fail-safe authentication',
                    userId: user.uid,
                    failSafeEnabled: true
                })
            };

        } catch (error) {
            console.error('CRITICAL-001: Generate request error:', error);

            return {
                statusCode: 500,
                headers,
                body: JSON.stringify({
                    error: 'Request processing error',
                    failSafe: true
                })
            };
        }
    }

    /**
     * CRITICAL-001 FIX: Enhanced security validation with fail-safe behavior
     */
    async performEnhancedSecurityValidation(authResult, requestContext) {
        try {
            // Additional behavioral analysis if available
            if (requestContext.ipAddress && authResult.user) {
                const behavioralRisk = await this.assessBehavioralRisk(
                    authResult.user.uid,
                    requestContext.ipAddress
                );

                if (behavioralRisk.riskLevel === 'HIGH') {
                    await securityLogger.logSuspiciousActivity({
                        activityType: 'HIGH_RISK_AUTHENTICATION',
                        userId: authResult.user.uid,
                        ipAddress: requestContext.ipAddress,
                        riskFactors: behavioralRisk.factors
                    });

                    return {
                        valid: false,
                        error: 'Additional security verification required',
                        statusCode: 403,
                        securityRisk: 'HIGH'
                    };
                }
            }

            return {
                valid: true,
                securityLevel: authResult.user.securityLevel
            };

        } catch (error) {
            // CRITICAL-001 FIX: Fail secure on enhanced validation error
            return {
                valid: false,
                error: 'Security validation error',
                statusCode: 500,
                securityRisk: 'CRITICAL'
            };
        }
    }

    /**
     * CRITICAL-001 FIX: Fail-safe user ID validation
     */
    async validateUserIdWithFailSafe(requestedUserId, authenticatedUserId, clientIP) {
        if (!requestedUserId || !authenticatedUserId) {
            return {
                valid: false,
                error: 'User identification error',
                statusCode: 400,
                securityRisk: 'HIGH'
            };
        }

        if (requestedUserId !== authenticatedUserId) {
            // CRITICAL-001 FIX: Log suspicious activity
            await securityLogger.logSuspiciousActivity({
                activityType: 'USER_ID_MISMATCH',
                description: 'Request user ID does not match authenticated user',
                authenticatedUserId,
                requestedUserId,
                clientIP,
                severity: 'HIGH'
            });

            return {
                valid: false,
                error: 'Access denied: User identification mismatch',
                statusCode: 403,
                securityRisk: 'CRITICAL'
            };
        }

        return {
            valid: true
        };
    }

    /**
     * CRITICAL-001 FIX: Fail-safe subscription validation
     */
    async validateUserSubscriptionFailSafe(userId) {
        try {
            // Use existing subscription validation logic but with fail-safe wrapper
            const { getFirestore } = require('./firebase-config');
            const db = getFirestore();

            const userDoc = await db.collection('users').doc(userId).get();

            if (!userDoc.exists) {
                return {
                    valid: false,
                    error: 'User not found',
                    currentUsage: 0,
                    maxUsage: 0,
                    subscriptionType: 'unknown'
                };
            }

            const userData = userDoc.data();
            const currentUsage = userData.monthlyUsage || 0;
            const maxUsage = userData.maxUsage || 3;
            const subscriptionType = userData.subscriptionType || 'free';

            // Check usage limits
            if (subscriptionType !== 'enterprise' && currentUsage >= maxUsage) {
                return {
                    valid: false,
                    error: subscriptionType === 'free'
                        ? 'Free usage limit reached. Upgrade to continue.'
                        : 'Monthly usage limit reached.',
                    currentUsage,
                    maxUsage,
                    subscriptionType
                };
            }

            // Increment usage
            const newUsage = currentUsage + 1;
            await db.collection('users').doc(userId).update({
                monthlyUsage: newUsage,
                lastActive: new Date().toISOString()
            });

            return {
                valid: true,
                currentUsage: newUsage,
                maxUsage,
                subscriptionType
            };

        } catch (error) {
            // CRITICAL-001 FIX: Fail secure on subscription validation error
            console.error('CRITICAL-001: Subscription validation error:', error);

            return {
                valid: false,
                error: 'Subscription validation error',
                currentUsage: 0,
                maxUsage: 0,
                subscriptionType: 'unknown'
            };
        }
    }

    /**
     * Helper methods for integration
     */
    extractClientIP(event) {
        return event.headers['x-forwarded-for'] ||
               event.headers['X-Forwarded-For'] ||
               event.headers['x-real-ip'] ||
               event.headers['X-Real-IP'] ||
               'unknown';
    }

    createSecureHeaders(origin = '') {
        const allowedOrigins = [
            'https://www.soltecsol.com',
            'https://ai-generator.soltecsol.com',
            'https://app.soltecsol.com'
        ];

        const allowedOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

        return {
            'Access-Control-Allow-Origin': allowedOrigin,
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Credentials': 'true',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        };
    }

    async assessBehavioralRisk(userId, ipAddress) {
        // Simple behavioral risk assessment
        // In production, this would integrate with the existing behavioral analysis
        return {
            riskLevel: 'LOW',
            factors: [],
            score: 0.1
        };
    }

    async logAuthenticationFailure(authResult, requestContext) {
        await securityLogger.logOperationFailure({
            operation: 'fail_safe_authentication',
            reason: authResult.reason,
            securityRisk: authResult.securityRisk,
            clientIP: requestContext.ipAddress,
            responseTime: authResult.operationTime,
            endpoint: 'critical-001-integration'
        });
    }

    async logSuccessfulAuthentication(authResult, requestContext) {
        await securityLogger.log('INFO', 'FAIL_SAFE_AUTH_SUCCESS', {
            userId: authResult.user.uid,
            securityLevel: authResult.user.securityLevel,
            responseTime: authResult.operationTime,
            performanceCompliant: authResult.performanceCompliant,
            clientIP: requestContext.ipAddress
        });
    }

    /**
     * Health check for the integrated system
     */
    async healthCheck() {
        try {
            const failSafeHealth = await this.failSafeAuth.healthCheck();

            return {
                status: failSafeHealth.status,
                components: {
                    failSafeAuthentication: failSafeHealth,
                    integration: { status: 'HEALTHY' }
                },
                timestamp: new Date().toISOString(),
                version: 'CRITICAL-001-INTEGRATION-1.0'
            };

        } catch (error) {
            return {
                status: 'UNHEALTHY',
                error: error.message,
                timestamp: new Date().toISOString(),
                version: 'CRITICAL-001-INTEGRATION-1.0'
            };
        }
    }
}

module.exports = Critical001Integration;

// USAGE EXAMPLES:

/*
// Example 1: Replace existing authentication in endpoints
const Critical001Integration = require('./critical-001-integration-example');
const integration = new Critical001Integration();

exports.handler = async (event, context) => {
    return await integration.handleGenerateRequest(event, context);
};

// Example 2: Use in existing middleware
const integration = new Critical001Integration();

// Replace this:
// const authResult = await firebaseAuthMiddleware.authenticateRequest(event, options);

// With this:
const authResult = await integration.authenticateRequestWithFailSafe(event, options);

// Example 3: Direct fail-safe authentication
const integration = new Critical001Integration();
const authResult = await integration.enhancedVerifyIdToken(idToken, ipAddress, userAgent);

if (!authResult.valid) {
    // Handle authentication failure with fail-safe behavior
    return { statusCode: authResult.statusCode, body: JSON.stringify({ error: authResult.error }) };
}

// Continue with authenticated request processing
*/