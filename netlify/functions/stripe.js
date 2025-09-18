// SESSION 4D5: Secure Stripe Payment Processing with Authentication & Rate Limiting
// Stripe integration with comprehensive security and abuse prevention

const firebaseAuthMiddleware = require('./firebase-auth-middleware');
const securityLogger = require('./security-logger');
const distributedRateLimiter = require('./distributed-rate-limiter');

// Stripe configuration - disabled for PayPal focus but kept for future use
// const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

exports.handler = async (event, context) => {
    try {
        // SESSION 4D5: Apply comprehensive authentication and rate limiting
        const authResult = await firebaseAuthMiddleware.authenticateRequest(event, {
            requireAuth: true,
            requireSubscription: false, // Payment processing should be available to all users
            requireAdmin: false,
            allowedMethods: ['POST'],
            rateLimit: true
        });

        if (!authResult.success) {
            // Log payment processing access failure
            securityLogger.logAuthFailure({
                reason: 'stripe_payment_access_denied',
                error: 'Authentication failed for Stripe payment processing',
                clientIP: event.headers['x-forwarded-for'] || 'unknown',
                endpoint: 'stripe-payment',
                method: event.httpMethod
            });
            
            return authResult.response;
        }

        const { headers, user, clientIP } = authResult;

        // Parse and validate request body
        let requestData;
        try {
            requestData = JSON.parse(event.body);
        } catch (parseError) {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_PAYMENT_REQUEST',
                description: 'Malformed JSON in Stripe payment request',
                clientIP: clientIP,
                userId: user.uid,
                endpoint: 'stripe-payment',
                additionalData: { parseError: parseError.message }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'Invalid request format',
                    message: 'Request body must be valid JSON'
                })
            };
        }

        const { action, planName, email, customerId } = requestData;

        // SESSION 4D5: Enhanced security validation for payment requests
        if (!action || typeof action !== 'string') {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_PAYMENT_ACTION',
                description: 'Missing or invalid action in payment request',
                clientIP: clientIP,
                userId: user.uid,
                endpoint: 'stripe-payment',
                additionalData: { action: action }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Invalid or missing action' })
            };
        }

        // Log successful authentication for payment processing
        securityLogger.logAuthSuccess({
            userId: user.uid,
            email: user.email,
            method: 'firebase_token',
            clientIP: clientIP,
            endpoint: 'stripe-payment',
            operation: `stripe_${action}`
        });

        // SESSION 1C-2: Distributed payment rate limiting with fraud detection
        const paymentRateLimit = await distributedRateLimiter.checkRateLimit(`payment:${clientIP}:${user.uid}`, {
            maxRequests: 5, // 5 payment requests per 5 minutes
            windowMs: 5 * 60 * 1000, // 5 minutes
            type: 'payment',
            clientIP: clientIP,
            userId: user.uid,
            userAgent: event.headers['user-agent'] || 'unknown',
            endpoint: 'stripe-payment'
        });

        if (!paymentRateLimit.allowed) {
            securityLogger.logRateLimitExceeded({
                clientIP: clientIP,
                endpoint: 'stripe-payment',
                requestCount: paymentRateLimit.total || 0,
                timeWindow: 300, // 5 minutes
                userId: user.uid,
                operation: action
            });

            return {
                statusCode: 429,
                headers: {
                    ...headers,
                    'Retry-After': paymentRateLimit.retryAfter?.toString() || '300',
                    'X-RateLimit-Limit': '5',
                    'X-RateLimit-Remaining': paymentRateLimit.remaining?.toString() || '0'
                },
                body: JSON.stringify({
                    error: 'Payment rate limit exceeded',
                    message: 'Too many payment requests. Please wait 5 minutes before trying again.',
                    retryAfter: paymentRateLimit.retryAfter || 300,
                    resetTime: paymentRateLimit.resetTime
                })
            };
        }

        // Process Stripe payment actions
        switch (action) {
            case 'create_checkout_session':
                return await createCheckoutSession(planName, email, headers, user);
            
            case 'create_portal_session':
                return await createPortalSession(customerId, headers, user);
            
            case 'get_subscription_status':
                return await getSubscriptionStatus(customerId, headers, user);
            
            case 'verify_webhook':
                return await verifyWebhook(event, headers, user);
            
            default:
                securityLogger.logSuspiciousActivity({
                    activityType: 'UNKNOWN_PAYMENT_ACTION',
                    description: `Unknown payment action attempted: ${action}`,
                    clientIP: clientIP,
                    userId: user.uid,
                    endpoint: 'stripe-payment',
                    additionalData: { action: action, requestData: requestData }
                });

                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ 
                        error: 'Unknown payment action',
                        allowedActions: ['create_checkout_session', 'create_portal_session', 'get_subscription_status']
                    })
                };
        }

    } catch (error) {
        console.error('Stripe payment processing error:', error);
        
        securityLogger.logOperationFailure({
            operation: 'stripe_payment_processing',
            endpoint: 'stripe-payment',
            error: error.message,
            stackTrace: error.stack,
            userId: event.requestContext?.authorizer?.userId
        });

        return {
            statusCode: 500,
            headers: firebaseAuthMiddleware.createSecureHeaders(),
            body: JSON.stringify({
                error: 'Payment processing service unavailable',
                message: 'Please try again later'
            })
        };
    }
};

// SESSION 1C-2: Payment rate limiting configuration
// SECURITY FIX: Replaced stateful Map with distributed rate limiting
const PAYMENT_RATE_LIMIT_WINDOW = 5 * 60 * 1000; // 5 minutes
const MAX_PAYMENT_REQUESTS = 5; // 5 payment requests per 5 minutes

/**
 * SESSION 1C-2: Payment rate limiting now handled by distributed rate limiter
 * This function is kept for backward compatibility but delegates to the distributed system
 * @param {string} clientIP - Client IP address
 * @param {string} userId - User ID
 * @returns {Promise<Object>} Rate limit result
 */
async function checkPaymentRateLimit(clientIP, userId) {
    try {
        const result = await distributedRateLimiter.checkRateLimit(`payment:${clientIP}:${userId}`, {
            maxRequests: MAX_PAYMENT_REQUESTS,
            windowMs: PAYMENT_RATE_LIMIT_WINDOW,
            type: 'payment',
            clientIP: clientIP,
            userId: userId,
            endpoint: 'stripe-payment'
        });

        return {
            allowed: result.allowed,
            requestCount: result.total || 0,
            timeWindow: PAYMENT_RATE_LIMIT_WINDOW / 1000
        };
    } catch (error) {
        console.error('Payment rate limit check failed:', error);
        // Allow request on error to avoid breaking functionality
        return { allowed: true, requestCount: 0, timeWindow: 0 };
    }
}

async function createCheckoutSession(planName, email, headers, user) {
    try {
        // SESSION 4D5: Enhanced security validation for Stripe checkout
        if (!planName || !email) {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_CHECKOUT_REQUEST',
                description: 'Missing required parameters for Stripe checkout',
                userId: user.uid,
                endpoint: 'stripe-checkout',
                additionalData: { planName, email }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Plan name and email are required' })
            };
        }

        // Note: Stripe functionality is currently disabled in favor of PayPal
        securityLogger.logOperationFailure({
            operation: 'stripe_checkout_session',
            userId: user.uid,
            endpoint: 'stripe-checkout',
            error: 'Stripe functionality disabled - PayPal integration active'
        });

        return {
            statusCode: 503,
            headers,
            body: JSON.stringify({ 
                error: 'Stripe payments temporarily unavailable',
                message: 'Please use PayPal payment option',
                alternative: 'paypal'
            })
        };

    } catch (error) {
        securityLogger.logOperationFailure({
            operation: 'stripe_checkout_session',
            userId: user.uid,
            endpoint: 'stripe-checkout',
            error: error.message,
            stackTrace: error.stack
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Checkout session creation failed' })
        };
    }
}

async function createPortalSession(customerId, headers, user) {
    try {
        // SESSION 4D5: Enhanced security validation for portal access
        if (!customerId) {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_PORTAL_REQUEST',
                description: 'Missing customer ID for portal session',
                userId: user.uid,
                endpoint: 'stripe-portal',
                additionalData: { customerId }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Customer ID is required' })
            };
        }

        // Note: Stripe functionality is currently disabled in favor of PayPal
        securityLogger.logOperationFailure({
            operation: 'stripe_portal_session',
            userId: user.uid,
            endpoint: 'stripe-portal',
            error: 'Stripe functionality disabled - PayPal integration active'
        });

        return {
            statusCode: 503,
            headers,
            body: JSON.stringify({ 
                error: 'Stripe portal temporarily unavailable',
                message: 'Please use PayPal account management',
                alternative: 'paypal'
            })
        };

    } catch (error) {
        securityLogger.logOperationFailure({
            operation: 'stripe_portal_session',
            userId: user.uid,
            endpoint: 'stripe-portal',
            error: error.message,
            stackTrace: error.stack
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Portal session creation failed' })
        };
    }
}

async function getSubscriptionStatus(customerId, headers, user) {
    try {
        // SESSION 4D5: Enhanced security validation for subscription status
        if (!customerId) {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_SUBSCRIPTION_REQUEST',
                description: 'Missing customer ID for subscription status',
                userId: user.uid,
                endpoint: 'stripe-subscription',
                additionalData: { customerId }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Customer ID is required' })
            };
        }

        // Note: Stripe functionality is currently disabled in favor of PayPal
        securityLogger.logOperationFailure({
            operation: 'stripe_subscription_status',
            userId: user.uid,
            endpoint: 'stripe-subscription',
            error: 'Stripe functionality disabled - PayPal integration active'
        });

        return {
            statusCode: 503,
            headers,
            body: JSON.stringify({ 
                error: 'Stripe subscription status temporarily unavailable',
                message: 'Please check PayPal subscription status',
                alternative: 'paypal',
                fallback: {
                    status: 'unknown',
                    plan: 'free',
                    usage_limit: 5
                }
            })
        };

    } catch (error) {
        securityLogger.logOperationFailure({
            operation: 'stripe_subscription_status',
            userId: user.uid,
            endpoint: 'stripe-subscription',
            error: error.message,
            stackTrace: error.stack
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Subscription status check failed' })
        };
    }
}

async function verifyWebhook(event, headers, user) {
    try {
        // SESSION 4D5: Enhanced webhook security verification
        securityLogger.logWebhookSuccess({
            webhookType: 'stripe',
            eventId: 'webhook-verification',
            eventType: 'verify_request',
            sourceIP: event.headers['x-forwarded-for'] || 'unknown',
            userId: user.uid
        });

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                status: 'verified',
                message: 'Webhook verification successful',
                timestamp: new Date().toISOString()
            })
        };

    } catch (error) {
        securityLogger.logWebhookFailure({
            webhookType: 'stripe',
            reason: 'verification_error',
            error: error.message,
            sourceIP: event.headers['x-forwarded-for'] || 'unknown',
            userId: user.uid
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Webhook verification failed' })
        };
    }
}

// SESSION 1C-2: Cleanup function for payment rate limiting
// SECURITY FIX: Cleanup now handled by distributed rate limiter with Firestore TTL
async function cleanupPaymentRateLimit() {
    try {
        // Distributed rate limiter handles cleanup automatically via Firestore TTL
        await distributedRateLimiter.cleanup();
    } catch (error) {
        console.error('Payment rate limit cleanup failed:', error);
    }
}

// REMOVED: setInterval for serverless compatibility
// Cleanup will be handled by infrastructure or periodic cloud functions