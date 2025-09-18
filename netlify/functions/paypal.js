// SESSION 4D5: Secure PayPal Payment Processing with Authentication & Rate Limiting
// PayPal REST API integration with comprehensive security and abuse prevention

const fetch = require('node-fetch');
const dns = require('dns').promises;
const firebaseAuthMiddleware = require('./firebase-auth-middleware');
const securityLogger = require('./security-logger');
const distributedRateLimiter = require('./distributed-rate-limiter');

// CRITICAL: Domain whitelist for approved email providers
const approvedDomains = ['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com', 'protonmail.com', 'aol.com'];

// SESSION 1C-2: PayPal-specific rate limiting configuration
// SECURITY FIX: Replaced stateful Map with distributed rate limiting
const PAYPAL_RATE_LIMIT_WINDOW = 5 * 60 * 1000; // 5 minutes
const MAX_PAYPAL_REQUESTS = 3; // 3 PayPal requests per 5 minutes (stricter than general payments)

/**
 * SESSION 1C-2: Check PayPal-specific rate limiting using distributed system
 * @param {string} clientIP - Client IP address
 * @param {string} userId - User ID
 * @param {Object} options - Additional options
 * @returns {Promise<Object>} Rate limit result
 */
async function checkPayPalRateLimit(clientIP, userId, options = {}) {
    try {
        const key = `paypal:${clientIP}:${userId}`;

        const result = await distributedRateLimiter.checkRateLimit(key, {
            maxRequests: MAX_PAYPAL_REQUESTS,
            windowMs: PAYPAL_RATE_LIMIT_WINDOW,
            type: 'payment_paypal',
            clientIP: clientIP,
            userId: userId,
            userAgent: options.userAgent || 'unknown',
            endpoint: options.endpoint || 'paypal-payment'
        });

        return {
            allowed: result.allowed,
            requestCount: result.total || 0,
            timeWindow: PAYPAL_RATE_LIMIT_WINDOW / 1000,
            retryAfter: result.retryAfter,
            remaining: result.remaining
        };

    } catch (error) {
        console.error('PayPal rate limit check failed:', error);
        // Allow request on error to avoid breaking functionality
        return { allowed: true, requestCount: 0, timeWindow: 0 };
    }
}

// CRITICAL: Enhanced email validation function for PayPal operations
async function isValidEmailForPayPal(email, userId = 'unknown') {
    if (!email || typeof email !== 'string') {
        return { valid: false, error: 'Email is required and must be a string' };
    }
    
    // CRITICAL: Security-approved email regex
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    
    // Basic length checks
    if (email.length < 3 || email.length > 320) {
        securityLogger.logSuspiciousActivity({
            activityType: 'INVALID_EMAIL_LENGTH',
            description: `Email length validation failed: ${email.length} characters`,
            userId: userId,
            endpoint: 'paypal-email-validation',
            additionalData: { emailLength: email.length }
        });
        return { valid: false, error: 'Email length must be between 3 and 320 characters' };
    }
    
    // Split into local and domain parts
    const parts = email.split('@');
    if (parts.length !== 2) {
        securityLogger.logSuspiciousActivity({
            activityType: 'MALFORMED_EMAIL',
            description: 'Email does not contain exactly one @ symbol',
            userId: userId,
            endpoint: 'paypal-email-validation',
            additionalData: { email: email.substring(0, 50) }
        });
        return { valid: false, error: 'Invalid email format' };
    }
    
    const [localPart, domainPart] = parts;
    
    // Local part validation (before @)
    if (localPart.length < 1 || localPart.length > 64) {
        return { valid: false, error: 'Email local part length invalid' };
    }
    
    // Domain part validation (after @)
    if (domainPart.length < 1 || domainPart.length > 255) {
        return { valid: false, error: 'Email domain part length invalid' };
    }
    
    // CRITICAL: TLD validation - minimum 2 characters
    const tldMatch = domainPart.match(/\.([a-zA-Z]{2,})$/);
    if (!tldMatch || tldMatch[1].length < 2) {
        return { valid: false, error: 'Domain must have a valid TLD with at least 2 characters' };
    }
    
    // Check against regex pattern
    if (!emailRegex.test(email)) {
        securityLogger.logSuspiciousActivity({
            activityType: 'EMAIL_REGEX_FAILURE',
            description: 'Email failed regex validation',
            userId: userId,
            endpoint: 'paypal-email-validation',
            additionalData: { emailDomain: domainPart }
        });
        return { valid: false, error: 'Email format does not match security requirements' };
    }
    
    // CRITICAL: Domain whitelist enforcement
    if (!approvedDomains.includes(domainPart.toLowerCase())) {
        securityLogger.logSuspiciousActivity({
            activityType: 'UNAPPROVED_EMAIL_DOMAIN',
            description: `Email domain not in approved list: ${domainPart}`,
            userId: userId,
            endpoint: 'paypal-email-validation',
            additionalData: { 
                domain: domainPart,
                approvedDomains: approvedDomains
            }
        });
        return { valid: false, error: 'Email domain not in approved list. Please use Gmail, Outlook, Yahoo, iCloud, ProtonMail, or AOL' };
    }
    
    // CRITICAL: DNS MX record verification
    try {
        const mxRecords = await dns.resolveMx(domainPart);
        if (!mxRecords || mxRecords.length === 0) {
            securityLogger.logSuspiciousActivity({
                activityType: 'EMAIL_NO_MX_RECORDS',
                description: `Email domain has no MX records: ${domainPart}`,
                userId: userId,
                endpoint: 'paypal-email-validation',
                additionalData: { domain: domainPart }
            });
            return { valid: false, error: 'Email domain does not have valid mail servers' };
        }
    } catch (error) {
        console.error('DNS MX lookup failed for domain:', domainPart, error);
        securityLogger.logSuspiciousActivity({
            activityType: 'EMAIL_DNS_FAILURE',
            description: `DNS MX lookup failed for domain: ${domainPart}`,
            userId: userId,
            endpoint: 'paypal-email-validation',
            additionalData: { 
                domain: domainPart,
                error: error.message
            }
        });
        return { valid: false, error: 'Email domain cannot be verified' };
    }
    
    return { valid: true, error: null };
}

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_BASE_URL = process.env.PAYPAL_MODE === process.env.PAYPAL_LIVE_VALUE 
  ? 'https://api.paypal.com' 
  : 'https://api.test.paypal.com';

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
            // Log PayPal payment access failure
            securityLogger.logAuthFailure({
                reason: 'paypal_payment_access_denied',
                error: 'Authentication failed for PayPal payment processing',
                clientIP: event.headers['x-forwarded-for'] || 'unknown',
                endpoint: 'paypal-payment',
                method: event.httpMethod
            });
            
            return authResult.response;
        }

        const { headers, user, clientIP } = authResult;

        // SESSION 1C-2: PayPal-specific distributed rate limiting (stricter than general)
        const paypalRateLimit = await checkPayPalRateLimit(clientIP, user.uid, {
            userAgent: event.headers['user-agent'],
            endpoint: 'paypal-payment'
        });
        if (!paypalRateLimit.allowed) {
            securityLogger.logRateLimitExceeded({
                clientIP: clientIP,
                endpoint: 'paypal-payment',
                requestCount: paypalRateLimit.requestCount,
                timeWindow: paypalRateLimit.timeWindow,
                userId: user.uid,
                rateLimitType: 'paypal_specific'
            });

            return {
                statusCode: 429,
                headers: {
                    ...headers,
                    'Retry-After': '300', // 5 minutes for PayPal operations
                    'X-RateLimit-Limit': MAX_PAYPAL_REQUESTS.toString(),
                    'X-RateLimit-Remaining': '0'
                },
                body: JSON.stringify({
                    error: 'PayPal rate limit exceeded',
                    message: `Too many PayPal requests. Limit: ${MAX_PAYPAL_REQUESTS} per 5 minutes.`,
                    retryAfter: 300
                })
            };
        }

        // Parse and validate request body
        let requestData;
        try {
            requestData = JSON.parse(event.body);
        } catch (parseError) {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_PAYPAL_REQUEST',
                description: 'Malformed JSON in PayPal payment request',
                clientIP: clientIP,
                userId: user.uid,
                endpoint: 'paypal-payment',
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

        const { action, planName, email, orderID } = requestData;

        // SESSION 4D5: Enhanced security validation for PayPal requests
        if (!action || typeof action !== 'string') {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_PAYPAL_ACTION',
                description: 'Missing or invalid action in PayPal request',
                clientIP: clientIP,
                userId: user.uid,
                endpoint: 'paypal-payment',
                additionalData: { action: action }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Invalid or missing action' })
            };
        }

        // Log successful authentication for PayPal processing
        securityLogger.logAuthSuccess({
            userId: user.uid,
            email: user.email,
            method: 'firebase_token',
            clientIP: clientIP,
            endpoint: 'paypal-payment',
            operation: `paypal_${action}`
        });

        // CRITICAL: Validate email for all PayPal operations that use email
        if (email && !email.includes('@example.com') && !email.includes('@test.com')) {
            const emailValidation = await isValidEmailForPayPal(email, user.uid);
            if (!emailValidation.valid) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({
                        error: `Email validation failed: ${emailValidation.error}`
                    })
                };
            }
        }

        // SESSION 4D5: Environment validation for PayPal
        if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
            securityLogger.logConfigIssue({
                component: 'paypal-payment',
                issue: 'PayPal credentials not configured',
                severity: 'CRITICAL',
                recommendation: 'Configure PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET'
            });
            
            return {
                statusCode: 500,
                headers,
                body: JSON.stringify({ 
                    error: 'PayPal service unavailable',
                    message: 'Payment service temporarily unavailable'
                })
            };
        }

        // Process PayPal payment actions
        switch (action) {
            case 'create_subscription':
                return await createSubscription(planName, email, headers, user);
            
            case 'capture_order':
                return await captureOrder(orderID, headers, user);
            
            case 'get_subscription_status':
                return await getSubscriptionStatus(email, headers, user);
            
            case 'get_plan_ids':
                return await getPlanIds(headers, user);
            
            default:
                securityLogger.logSuspiciousActivity({
                    activityType: 'UNKNOWN_PAYPAL_ACTION',
                    description: `Unknown PayPal action attempted: ${action}`,
                    clientIP: clientIP,
                    userId: user.uid,
                    endpoint: 'paypal-payment',
                    additionalData: { action: action, requestData: requestData }
                });

                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ 
                        error: 'Unknown PayPal action',
                        allowedActions: ['create_subscription', 'capture_order', 'get_subscription_status', 'get_plan_ids']
                    })
                };
        }

    } catch (error) {
        console.error('PayPal payment processing error:', error);
        
        securityLogger.logOperationFailure({
            operation: 'paypal_payment_processing',
            endpoint: 'paypal-payment',
            error: error.message,
            stackTrace: error.stack,
            userId: event.requestContext?.authorizer?.userId
        });

        return {
            statusCode: 500,
            headers: firebaseAuthMiddleware.createSecureHeaders(),
            body: JSON.stringify({
                error: 'PayPal payment processing service unavailable',
                message: 'Please try again later'
            })
        };
    }
};

async function getPayPalAccessToken(user = null) {
    try {
        // SESSION 4D5: Enhanced security for PayPal token acquisition
        if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
            const error = 'PayPal credentials not configured';
            if (user) {
                securityLogger.logConfigIssue({
                    component: 'paypal-auth',
                    issue: error,
                    severity: 'CRITICAL',
                    recommendation: 'Configure PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET',
                    userId: user.uid
                });
            }
            throw new Error(error);
        }

        const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');
        
        const response = await fetch(`${PAYPAL_BASE_URL}/v1/oauth2/token`, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'grant_type=client_credentials'
        });

        if (!response.ok) {
            const errorData = await response.json();
            if (user) {
                securityLogger.logOperationFailure({
                    operation: 'paypal_token_acquisition',
                    userId: user.uid,
                    endpoint: 'paypal-auth',
                    error: `PayPal token request failed: ${response.status}`,
                    additionalData: { 
                        status: response.status,
                        paypalError: errorData
                    }
                });
            }
            throw new Error(`PayPal authentication failed: ${response.status}`);
        }

        const data = await response.json();
        
        if (!data.access_token) {
            if (user) {
                securityLogger.logOperationFailure({
                    operation: 'paypal_token_acquisition',
                    userId: user.uid,
                    endpoint: 'paypal-auth',
                    error: 'PayPal access token not received'
                });
            }
            throw new Error('PayPal access token not received');
        }

        return data.access_token;

    } catch (error) {
        console.error('PayPal access token error:', error);
        if (user) {
            securityLogger.logOperationFailure({
                operation: 'paypal_token_acquisition',
                userId: user.uid,
                endpoint: 'paypal-auth',
                error: error.message,
                stackTrace: error.stack
            });
        }
        throw error;
    }
}

async function createSubscription(planName, email, headers, user) {
    try {
        // SESSION 4D5: Enhanced security validation for subscription creation
        if (!planName || !email) {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_SUBSCRIPTION_REQUEST',
                description: 'Missing required parameters for PayPal subscription',
                userId: user.uid,
                endpoint: 'paypal-create-subscription',
                additionalData: { planName, email }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Plan name and email are required' })
            };
        }

        console.log('Creating subscription for plan:', planName, 'email:', email, 'user:', user.uid);
        
        const plans = {
            starter: {
                plan_id: process.env.PAYPAL_STARTER_PLAN_ID,
                amount: '19.99'
            },
            professional: {
                plan_id: process.env.PAYPAL_PROFESSIONAL_PLAN_ID,
                amount: '49.99'
            },
            enterprise: {
                plan_id: process.env.PAYPAL_ENTERPRISE_PLAN_ID,
                amount: '99.99'
            }
        };

        const plan = plans[planName];
        if (!plan) {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_PAYPAL_PLAN',
                description: `Invalid PayPal plan requested: ${planName}`,
                userId: user.uid,
                endpoint: 'paypal-create-subscription',
                additionalData: { 
                    planName: planName,
                    availablePlans: Object.keys(plans)
                }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'Invalid plan name',
                    availablePlans: Object.keys(plans)
                })
            };
        }

        // SESSION 4D5: Validate plan configuration
        if (!plan.plan_id) {
            securityLogger.logConfigIssue({
                component: 'paypal-plans',
                issue: `Plan ID not configured for ${planName}`,
                severity: 'HIGH',
                recommendation: `Configure PAYPAL_${planName.toUpperCase()}_PLAN_ID environment variable`
            });

            return {
                statusCode: 500,
                headers,
                body: JSON.stringify({ error: 'Payment plan configuration unavailable' })
            };
        }

        console.log('Using plan ID:', plan.plan_id);

        const accessToken = await getPayPalAccessToken(user);

        const subscriptionData = {
            plan_id: plan.plan_id,
            subscriber: {
                email_address: email || 'test@example.com',
            },
            application_context: {
                brand_name: 'SolTecSol AI Description Generator',
                locale: 'en-US',
                shipping_preference: 'NO_SHIPPING',
                user_action: 'SUBSCRIBE_NOW',
                return_url: `${process.env.SITE_URL}/success`,
                cancel_url: `${process.env.SITE_URL}/cancel`
            }
        };

        const response = await fetch(`${PAYPAL_BASE_URL}/v1/billing/subscriptions`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Prefer': 'return=representation'
            },
            body: JSON.stringify(subscriptionData)
        });

        const subscription = await response.json();
        console.log('PayPal API Response:', {
            status: response.status,
            statusText: response.statusText,
            data: subscription
        });

        if (response.ok) {
            // Find the approval URL
            const approvalUrl = subscription.links.find(link => link.rel === 'approve')?.href;
            
            // Log successful subscription creation
            securityLogger.logOperationSuccess({
                operation: 'paypal_subscription_creation',
                userId: user.uid,
                endpoint: 'paypal-create-subscription',
                resourcesAccessed: [`subscription_${subscription.id}`, `plan_${planName}`]
            });

            return {
                statusCode: 200,
                headers: {
                    ...headers,
                    'Cache-Control': 'private, no-cache, no-store, must-revalidate'
                },
                body: JSON.stringify({ 
                    subscription_id: subscription.id,
                    approval_url: approvalUrl,
                    status: subscription.status,
                    timestamp: new Date().toISOString()
                })
            };
        } else {
            console.error('PayPal subscription creation failed:', subscription);
            
            securityLogger.logOperationFailure({
                operation: 'paypal_subscription_creation',
                userId: user.uid,
                endpoint: 'paypal-create-subscription',
                error: subscription.message || 'PayPal API error',
                additionalData: { 
                    paypalError: subscription,
                    planName: planName,
                    email: email
                }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: subscription.message || 'Failed to create subscription',
                    timestamp: new Date().toISOString()
                })
            };
        }

    } catch (error) {
        console.error('Subscription creation error:', error);
        
        securityLogger.logOperationFailure({
            operation: 'paypal_subscription_creation',
            userId: user.uid,
            endpoint: 'paypal-create-subscription',
            error: error.message,
            stackTrace: error.stack
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Subscription creation failed',
                message: 'Please try again later'
            })
        };
    }
}

async function captureOrder(orderID, headers, user) {
    try {
        // SESSION 4D5: Enhanced security validation for order capture
        if (!orderID || typeof orderID !== 'string') {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_ORDER_CAPTURE',
                description: 'Missing or invalid order ID for PayPal capture',
                userId: user.uid,
                endpoint: 'paypal-capture-order',
                additionalData: { orderID }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Valid order ID is required' })
            };
        }

        const accessToken = await getPayPalAccessToken(user);

        const response = await fetch(`${PAYPAL_BASE_URL}/v2/checkout/orders/${orderID}/capture`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            }
        });

        const captureData = await response.json();

        if (response.ok) {
            // Log successful order capture
            securityLogger.logOperationSuccess({
                operation: 'paypal_order_capture',
                userId: user.uid,
                endpoint: 'paypal-capture-order',
                resourcesAccessed: [`order_${orderID}`]
            });

            return {
                statusCode: 200,
                headers: {
                    ...headers,
                    'Cache-Control': 'private, no-cache, no-store, must-revalidate'
                },
                body: JSON.stringify({
                    ...captureData,
                    timestamp: new Date().toISOString()
                })
            };
        } else {
            securityLogger.logOperationFailure({
                operation: 'paypal_order_capture',
                userId: user.uid,
                endpoint: 'paypal-capture-order',
                error: captureData.message || 'PayPal capture failed',
                additionalData: { 
                    orderID: orderID,
                    paypalError: captureData
                }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: captureData.message || 'Order capture failed',
                    timestamp: new Date().toISOString()
                })
            };
        }

    } catch (error) {
        console.error('Order capture error:', error);
        
        securityLogger.logOperationFailure({
            operation: 'paypal_order_capture',
            userId: user.uid,
            endpoint: 'paypal-capture-order',
            error: error.message,
            stackTrace: error.stack
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Order capture failed',
                message: 'Please try again later'
            })
        };
    }
}

async function getSubscriptionStatus(email, headers, user) {
    try {
        // SESSION 4D5: Enhanced security validation for subscription status
        if (!email) {
            securityLogger.logSuspiciousActivity({
                activityType: 'INVALID_SUBSCRIPTION_STATUS_REQUEST',
                description: 'Missing email for PayPal subscription status',
                userId: user.uid,
                endpoint: 'paypal-subscription-status',
                additionalData: { email }
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Email is required' })
            };
        }

        // Log subscription status check
        securityLogger.logOperationSuccess({
            operation: 'paypal_subscription_status_check',
            userId: user.uid,
            endpoint: 'paypal-subscription-status',
            resourcesAccessed: [`email_${email}`]
        });

        // In a real implementation, you would query your database for the user's subscription
        // For now, return a basic response with enhanced security headers
        return {
            statusCode: 200,
            headers: {
                ...headers,
                'Cache-Control': 'private, no-cache, no-store, must-revalidate'
            },
            body: JSON.stringify({
                status: 'active',
                plan: 'free',
                usage_limit: 5,
                timestamp: new Date().toISOString(),
                note: 'Basic subscription status - integrate with database for full functionality'
            })
        };

    } catch (error) {
        console.error('Subscription status error:', error);
        
        securityLogger.logOperationFailure({
            operation: 'paypal_subscription_status_check',
            userId: user.uid,
            endpoint: 'paypal-subscription-status',
            error: error.message,
            stackTrace: error.stack
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Subscription status check failed',
                message: 'Please try again later'
            })
        };
    }
}

async function getPlanIds(headers, user) {
    try {
        // SESSION 4D5: Enhanced security for plan ID access
        console.log('Plan IDs request - Environment variables:', {
            starter: process.env.PAYPAL_STARTER_PLAN_ID,
            professional: process.env.PAYPAL_PROFESSIONAL_PLAN_ID,
            enterprise: process.env.PAYPAL_ENTERPRISE_PLAN_ID
        });

        // SESSION 4D5: Validate plan configuration
        const plans = {
            starter: process.env.PAYPAL_STARTER_PLAN_ID,
            professional: process.env.PAYPAL_PROFESSIONAL_PLAN_ID,
            enterprise: process.env.PAYPAL_ENTERPRISE_PLAN_ID
        };

        const missingPlans = Object.entries(plans).filter(([name, id]) => !id).map(([name]) => name);
        
        if (missingPlans.length > 0) {
            securityLogger.logConfigIssue({
                component: 'paypal-plan-ids',
                issue: `Missing plan IDs: ${missingPlans.join(', ')}`,
                severity: 'HIGH',
                recommendation: 'Configure all PayPal plan ID environment variables',
                userId: user.uid
            });
        }

        // Log successful plan ID access
        securityLogger.logOperationSuccess({
            operation: 'paypal_plan_ids_access',
            userId: user.uid,
            endpoint: 'paypal-plan-ids',
            resourcesAccessed: Object.keys(plans)
        });
        
        return {
            statusCode: 200,
            headers: {
                ...headers,
                'Cache-Control': 'private, no-cache, no-store, must-revalidate'
            },
            body: JSON.stringify({
                ...plans,
                timestamp: new Date().toISOString(),
                configured: Object.keys(plans).filter(name => plans[name]).length,
                total: Object.keys(plans).length
            })
        };

    } catch (error) {
        console.error('Plan IDs access error:', error);
        
        securityLogger.logOperationFailure({
            operation: 'paypal_plan_ids_access',
            userId: user.uid,
            endpoint: 'paypal-plan-ids',
            error: error.message,
            stackTrace: error.stack
        });

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Plan IDs access failed',
                message: 'Please try again later'
            })
        };
    }
}

// SESSION 4D5: Cleanup function for PayPal rate limiting
function cleanupPayPalRateLimit() {
    try {
        const now = Date.now();
        
        // SESSION 1C-2: PayPal rate limit cleanup now handled by distributed rate limiter
        await distributedRateLimiter.cleanup();
        console.log('PayPal rate limit cleanup completed via distributed system');
    } catch (error) {
        console.error('PayPal rate limit cleanup failed:', error);
    }
}

// REMOVED: setInterval for serverless compatibility
// Cleanup will be handled by infrastructure or periodic cloud functions
