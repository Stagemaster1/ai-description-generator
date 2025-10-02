// SESSION 4D5: Secure PayPal Configuration with Authentication & Rate Limiting
// Returns PayPal Client ID only to authenticated users with rate limiting protection

const firebaseAuthMiddleware = require('./firebase-auth-middleware');
const securityLogger = require('./security-logger');

exports.handler = async (event, context) => {
    try {
        // SESSION 4D5: Apply comprehensive authentication and rate limiting
        const authResult = await firebaseAuthMiddleware.authenticateRequest(event, {
            requireAuth: true,
            requireSubscription: false, // Allow all authenticated users to get config
            requireAdmin: false,
            allowedMethods: ['GET'],
            rateLimit: true
        });

        if (!authResult.success) {
            // Log payment config access failure
            securityLogger.logAuthFailure({
                reason: 'payment_config_access_denied',
                error: 'Authentication failed for PayPal config access',
                clientIP: event.headers['x-forwarded-for'] || 'unknown',
                endpoint: 'paypal-config',
                method: event.httpMethod
            });
            
            return authResult.response;
        }

        const { headers, user, clientIP } = authResult;

        // SESSION 4D5: Enhanced security logging for payment config access
        securityLogger.logAuthSuccess({
            userId: user.uid,
            email: user.email,
            method: 'firebase_token',
            clientIP: clientIP,
            endpoint: 'paypal-config',
            operation: 'get_paypal_client_id'
        });

        // SESSION 4D5: Validate environment configuration
        if (!process.env.PAYPAL_CLIENT_ID) {
            securityLogger.logConfigIssue({
                component: 'paypal-config',
                issue: 'PAYPAL_CLIENT_ID environment variable not configured',
                severity: 'CRITICAL',
                recommendation: 'Configure PAYPAL_CLIENT_ID in environment variables'
            });
            
            return {
                statusCode: 500,
                headers,
                body: JSON.stringify({ 
                    error: 'PayPal configuration unavailable',
                    message: 'Service temporarily unavailable'
                })
            };
        }

        // SESSION 4D5: Return PayPal Client ID and Plan IDs for authenticated users only
        return {
            statusCode: 200,
            headers: {
                ...headers,
                'Cache-Control': 'private, no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            },
            body: JSON.stringify({
                clientId: process.env.PAYPAL_CLIENT_ID,
                starterPlanId: process.env.PAYPAL_STARTER_PLAN_ID,
                professionalPlanId: process.env.PAYPAL_PROFESSIONAL_PLAN_ID,
                enterprisePlanId: process.env.PAYPAL_ENTERPRISE_PLAN_ID,
                starterAnnualPlanId: process.env.PAYPAL_STARTER_ANNUAL_PLAN_ID,
                professionalAnnualPlanId: process.env.PAYPAL_PROFESSIONAL_ANNUAL_PLAN_ID,
                enterpriseAnnualPlanId: process.env.PAYPAL_ENTERPRISE_ANNUAL_PLAN_ID,
                timestamp: new Date().toISOString()
            })
        };

    } catch (error) {
        console.error('PayPal config error:', error);
        
        securityLogger.logOperationFailure({
            operation: 'get_paypal_config',
            endpoint: 'paypal-config',
            error: error.message,
            stackTrace: error.stack
        });

        return {
            statusCode: 500,
            headers: firebaseAuthMiddleware.createSecureHeaders(),
            body: JSON.stringify({
                error: 'PayPal configuration service unavailable',
                message: 'Please try again later'
            })
        };
    }
};