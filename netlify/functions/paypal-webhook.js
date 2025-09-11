// PayPal Webhook Handler - Secure Firebase Integration
// Handles PayPal subscription events and stores data securely in Firebase

const { getFirestore } = require('../../firebase-config');
const crypto = require('crypto');
const fetch = require('node-fetch');
const securityLogger = require('./security-logger');
const firebaseAuthMiddleware = require('./firebase-auth-middleware');

exports.handler = async (event, context) => {
    // SESSION 4D6: Enhanced comprehensive security headers for PayPal webhook
    const origin = event.headers.origin || event.headers.Origin || '';
    const allowedOrigins = [
        'https://www.paypal.com',
        'https://www.sandbox.paypal.com',
        'https://api.paypal.com',
        'https://api.sandbox.paypal.com'
    ];
    
    // For webhooks, we usually don't get an Origin header, but if we do, validate it
    const corsOrigin = origin && allowedOrigins.includes(origin) ? origin : '*';
    
    // SESSION 4D6: Use enhanced security headers from middleware
    const headers = firebaseAuthMiddleware.createSecureHeaders('', {
        webhook: true,
        webhookOrigin: corsOrigin,
        contentType: 'application/json'
    });
    
    // Override specific headers for PayPal webhook requirements
    headers['Access-Control-Allow-Headers'] = 'Content-Type, PayPal-Request-Id, PayPal-Transmission-Id, PayPal-Auth-Algo, PayPal-Transmission-Time, PayPal-Cert-Id, PayPal-Signature';
    headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS';

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    try {
        // Verify PayPal webhook signature for security
        const clientIP = event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown';
        const isValid = await verifyPayPalWebhook(event);
        
        if (!isValid) {
            console.error('Invalid PayPal webhook signature');
            
            // Log webhook verification failure
            securityLogger.logWebhookFailure({
                webhookType: 'paypal',
                reason: 'signature_verification_failed',
                sourceIP: clientIP,
                headers: Object.keys(event.headers),
                bodyHash: crypto.createHash('sha256').update(event.body).digest('hex')
            });

            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ error: 'Unauthorized' })
            };
        }

        const webhookEvent = JSON.parse(event.body);
        const eventType = webhookEvent.event_type;

        console.log('PayPal Webhook Event:', eventType);

        // Log successful webhook verification
        securityLogger.logWebhookSuccess({
            webhookType: 'paypal',
            eventId: webhookEvent.id,
            eventType: eventType,
            sourceIP: clientIP,
            transmissionId: event.headers['paypal-transmission-id'] || 'unknown'
        });

        const db = getFirestore();

        switch (eventType) {
            case 'BILLING.SUBSCRIPTION.CREATED':
                return await handleSubscriptionCreated(db, webhookEvent, headers);
                
            case 'BILLING.SUBSCRIPTION.ACTIVATED':
                return await handleSubscriptionActivated(db, webhookEvent, headers);
                
            case 'BILLING.SUBSCRIPTION.CANCELLED':
                return await handleSubscriptionCancelled(db, webhookEvent, headers);
                
            case 'BILLING.SUBSCRIPTION.SUSPENDED':
                return await handleSubscriptionSuspended(db, webhookEvent, headers);
                
            case 'PAYMENT.SALE.COMPLETED':
                return await handlePaymentCompleted(db, webhookEvent, headers);
                
            default:
                console.log('Unhandled webhook event:', eventType);
                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({ message: 'Event received but not processed' })
                };
        }
    } catch (error) {
        console.error('PayPal Webhook Error:', error);
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

// SECURITY: Enhanced PayPal webhook signature verification
async function verifyPayPalWebhook(event) {
    try {
        // Get PayPal webhook ID from environment with enhanced validation
        const webhookId = process.env.PAYPAL_WEBHOOK_ID;
        const clientId = process.env.PAYPAL_CLIENT_ID;
        const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
        
        // CRITICAL: Strict credential validation - NEVER bypass webhook verification
        if (!webhookId || !clientId || !clientSecret) {
            console.error('PayPal webhook credentials incomplete');
            return false; // Always fail without proper credentials
        }

        // SECURITY FIX: Comprehensive PayPal webhook signature verification
        const headers = event.headers;
        const body = event.body;
        
        // Normalize header names (case-insensitive)
        const normalizedHeaders = {};
        Object.keys(headers).forEach(key => {
            normalizedHeaders[key.toLowerCase()] = headers[key];
        });
        
        // Required PayPal webhook headers
        const authAlgo = normalizedHeaders['paypal-auth-algo'];
        const transmission_id = normalizedHeaders['paypal-transmission-id'];
        const cert_id = normalizedHeaders['paypal-cert-id'];
        const transmission_time = normalizedHeaders['paypal-transmission-time'];
        const webhook_signature = normalizedHeaders['paypal-signature'];
        
        // CRITICAL: Validate all required headers are present
        const requiredHeaders = {
            'paypal-auth-algo': authAlgo,
            'paypal-transmission-id': transmission_id,
            'paypal-cert-id': cert_id,
            'paypal-transmission-time': transmission_time,
            'paypal-signature': webhook_signature
        };
        
        const missingHeaders = Object.entries(requiredHeaders)
            .filter(([key, value]) => !value)
            .map(([key]) => key);
            
        if (missingHeaders.length > 0) {
            console.error('Missing required PayPal webhook headers:', missingHeaders);
            return false;
        }
        
        // SECURITY: Validate header formats
        if (!/^[A-Z0-9]+$/.test(cert_id)) {
            console.error('Invalid PayPal cert ID format');
            return false;
        }
        
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(transmission_time)) {
            console.error('Invalid PayPal transmission time format');
            return false;
        }
        
        // SECURITY: Timestamp validation to prevent replay attacks
        const transmissionTime = new Date(transmission_time);
        const now = new Date();
        const timeDiff = Math.abs(now - transmissionTime);
        const maxTimeDiff = 5 * 60 * 1000; // 5 minutes tolerance
        
        if (isNaN(transmissionTime.getTime())) {
            console.error('Invalid PayPal transmission time');
            return false;
        }
        
        if (timeDiff > maxTimeDiff) {
            console.error('PayPal webhook transmission time outside acceptable window', {
                transmissionTime: transmission_time,
                currentTime: now.toISOString(),
                timeDiffMs: timeDiff,
                maxAllowedMs: maxTimeDiff
            });
            return false;
        }
        
        // SECURITY: Validate webhook event structure
        let webhookEvent;
        try {
            webhookEvent = JSON.parse(body);
        } catch (parseError) {
            console.error('Failed to parse PayPal webhook body:', parseError);
            return false;
        }
        
        // CRITICAL: Validate required webhook event fields
        const requiredFields = ['id', 'event_type', 'resource_type', 'summary'];
        const missingFields = requiredFields.filter(field => !webhookEvent[field]);
        
        if (missingFields.length > 0) {
            console.error('Invalid PayPal webhook event structure - missing fields:', missingFields);
            return false;
        }
        
        // SECURITY: Validate event type format
        if (!/^[A-Z_]+\.[A-Z_]+\.[A-Z_]+$/.test(webhookEvent.event_type)) {
            console.error('Invalid PayPal event type format:', webhookEvent.event_type);
            return false;
        }
        
        // SECURITY: Enhanced signature verification using PayPal's verification endpoint
        const verificationResult = await verifyWebhookWithPayPal(
            webhookEvent,
            webhookId,
            transmission_id,
            cert_id,
            transmission_time,
            webhook_signature,
            authAlgo
        );
        
        if (!verificationResult.valid) {
            console.error('PayPal webhook signature verification failed:', verificationResult.error);
            
            // Log detailed webhook failure
            securityLogger.logWebhookFailure({
                webhookType: 'paypal',
                reason: 'paypal_api_verification_failed',
                error: verificationResult.error,
                sourceIP: 'unknown', // Will be set by calling function
                headers: Object.keys(headers)
            });
            
            return false;
        }
        
        console.log('PayPal webhook verification passed for event:', {
            eventId: webhookEvent.id,
            eventType: webhookEvent.event_type,
            transmissionId: transmission_id
        });
        
        return true;
        
    } catch (error) {
        console.error('PayPal webhook verification error:', error);
        return false;
    }
}

// SECURITY: Verify webhook signature using PayPal's verification endpoint
async function verifyWebhookWithPayPal(webhookEvent, webhookId, transmissionId, certId, transmissionTime, signature, authAlgo) {
    try {
        const paypalAccessToken = await getPayPalAccessToken();
        if (!paypalAccessToken) {
            return { valid: false, error: 'Failed to get PayPal access token' };
        }
        
        const paypalMode = process.env.PAYPAL_MODE || 'sandbox';
        const baseURL = paypalMode === 'live' 
            ? 'https://api.paypal.com' 
            : 'https://api.sandbox.paypal.com';
        
        // Prepare verification request
        const verificationData = {
            auth_algo: authAlgo,
            cert_id: certId,
            transmission_id: transmissionId,
            transmission_time: transmissionTime,
            webhook_id: webhookId,
            webhook_event: webhookEvent
        };
        
        const response = await fetch(`${baseURL}/v1/notifications/verify-webhook-signature`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${paypalAccessToken}`,
                'Accept': 'application/json'
            },
            body: JSON.stringify(verificationData)
        });
        
        if (!response.ok) {
            const errorData = await response.text();
            return { 
                valid: false, 
                error: `PayPal verification request failed: ${response.status} - ${errorData}` 
            };
        }
        
        const verificationResponse = await response.json();
        
        if (verificationResponse.verification_status !== 'SUCCESS') {
            return {
                valid: false,
                error: `PayPal signature verification failed: ${verificationResponse.verification_status}`
            };
        }
        
        return { valid: true };
        
    } catch (error) {
        console.error('PayPal webhook verification API error:', error);
        return { 
            valid: false, 
            error: `Verification API error: ${error.message}` 
        };
    }
}

// Get PayPal access token for API verification
async function getPayPalAccessToken() {
    try {
        const clientId = process.env.PAYPAL_CLIENT_ID;
        const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
        const paypalMode = process.env.PAYPAL_MODE || 'sandbox';
        
        const baseURL = paypalMode === 'live' 
            ? 'https://api.paypal.com' 
            : 'https://api.sandbox.paypal.com';
        
        const auth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
        
        const response = await fetch(`${baseURL}/v1/oauth2/token`, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'grant_type=client_credentials'
        });
        
        if (!response.ok) {
            throw new Error(`PayPal token request failed: ${response.status}`);
        }
        
        const data = await response.json();
        return data.access_token;
        
    } catch (error) {
        console.error('Failed to get PayPal access token:', error);
        return null;
    }
}

// Handle subscription created event
async function handleSubscriptionCreated(db, webhookEvent, headers) {
    try {
        const subscription = webhookEvent.resource;
        const subscriberEmail = subscription.subscriber?.email_address;
        
        if (!subscriberEmail) {
            console.error('No subscriber email in webhook event');
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'No subscriber email' })
            };
        }

        // Create or update user in Firebase
        const userId = await createOrUpdateFirebaseUser(db, {
            email: subscriberEmail,
            paypalSubscriptionId: subscription.id,
            status: subscription.status,
            planId: subscription.plan_id
        });

        console.log('Subscription created for user:', userId);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                success: true, 
                message: 'Subscription created successfully',
                userId 
            })
        };
    } catch (error) {
        console.error('Handle subscription created error:', error);
        throw error;
    }
}

// Handle subscription activated event
async function handleSubscriptionActivated(db, webhookEvent, headers) {
    try {
        const subscription = webhookEvent.resource;
        
        // Find user by PayPal subscription ID
        const userQuery = await db.collection('users')
            .where('paypalSubscriptionId', '==', subscription.id)
            .limit(1)
            .get();

        if (userQuery.empty) {
            console.error('No user found for subscription:', subscription.id);
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ error: 'User not found' })
            };
        }

        const userDoc = userQuery.docs[0];
        const userData = userDoc.data();
        
        // Map plan ID to subscription type
        const subscriptionConfig = getSubscriptionConfig(subscription.plan_id);
        
        // Update user subscription status
        await db.collection('users').doc(userDoc.id).update({
            subscriptionType: subscriptionConfig.type,
            maxUsage: subscriptionConfig.maxUsage,
            isSubscribed: true,
            subscriptionStatus: 'ACTIVE',
            monthlyUsage: 0, // Reset usage on activation
            lastResetPeriod: getCurrentBillingPeriod(),
            lastActive: new Date().toISOString()
        });

        console.log('Subscription activated for user:', userDoc.id);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                success: true, 
                message: 'Subscription activated successfully',
                userId: userDoc.id
            })
        };
    } catch (error) {
        console.error('Handle subscription activated error:', error);
        throw error;
    }
}

// Handle subscription cancelled event
async function handleSubscriptionCancelled(db, webhookEvent, headers) {
    try {
        const subscription = webhookEvent.resource;
        
        // Find user by PayPal subscription ID
        const userQuery = await db.collection('users')
            .where('paypalSubscriptionId', '==', subscription.id)
            .limit(1)
            .get();

        if (userQuery.empty) {
            console.error('No user found for subscription:', subscription.id);
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ error: 'User not found' })
            };
        }

        const userDoc = userQuery.docs[0];
        
        // Update user to free plan
        await db.collection('users').doc(userDoc.id).update({
            subscriptionType: 'free',
            maxUsage: 3,
            isSubscribed: false,
            subscriptionStatus: 'CANCELLED',
            lastActive: new Date().toISOString()
        });

        console.log('Subscription cancelled for user:', userDoc.id);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                success: true, 
                message: 'Subscription cancelled successfully',
                userId: userDoc.id
            })
        };
    } catch (error) {
        console.error('Handle subscription cancelled error:', error);
        throw error;
    }
}

// Handle subscription suspended event
async function handleSubscriptionSuspended(db, webhookEvent, headers) {
    // Similar to cancelled but with suspended status
    return await handleSubscriptionCancelled(db, webhookEvent, headers);
}

// Handle payment completed event
async function handlePaymentCompleted(db, webhookEvent, headers) {
    try {
        console.log('Payment completed:', webhookEvent.resource.id);
        
        // Log payment for record keeping
        await db.collection('payments').add({
            paypalPaymentId: webhookEvent.resource.id,
            amount: webhookEvent.resource.amount,
            timestamp: new Date().toISOString(),
            status: 'completed'
        });

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                success: true, 
                message: 'Payment logged successfully'
            })
        };
    } catch (error) {
        console.error('Handle payment completed error:', error);
        throw error;
    }
}

// Create or update user in Firebase
async function createOrUpdateFirebaseUser(db, userData) {
    try {
        const { email, paypalSubscriptionId, status, planId } = userData;
        
        // Check if user already exists by email
        const existingUserQuery = await db.collection('users')
            .where('email', '==', email)
            .limit(1)
            .get();

        const subscriptionConfig = getSubscriptionConfig(planId);
        const currentDate = new Date().toISOString();
        
        if (!existingUserQuery.empty) {
            // Update existing user
            const userDoc = existingUserQuery.docs[0];
            await db.collection('users').doc(userDoc.id).update({
                paypalSubscriptionId,
                subscriptionType: subscriptionConfig.type,
                maxUsage: subscriptionConfig.maxUsage,
                subscriptionStatus: status,
                lastActive: currentDate
            });
            return userDoc.id;
        } else {
            // Create new user
            const userId = generateUserId();
            const newUserData = {
                id: userId,
                email,
                paypalSubscriptionId,
                subscriptionType: subscriptionConfig.type,
                maxUsage: subscriptionConfig.maxUsage,
                monthlyUsage: 0,
                isSubscribed: status === 'ACTIVE',
                subscriptionStatus: status,
                lastResetPeriod: getCurrentBillingPeriod(),
                createdAt: currentDate,
                lastActive: currentDate,
                status: 'active'
            };
            
            await db.collection('users').doc(userId).set(newUserData);
            return userId;
        }
    } catch (error) {
        console.error('Create or update Firebase user error:', error);
        throw error;
    }
}

// Get subscription configuration by plan ID
function getSubscriptionConfig(planId) {
    const planConfigs = {
        [process.env.PAYPAL_STARTER_PLAN_ID]: { type: 'starter', maxUsage: 50 },
        [process.env.PAYPAL_PROFESSIONAL_PLAN_ID]: { type: 'professional', maxUsage: 200 },
        [process.env.PAYPAL_ENTERPRISE_PLAN_ID]: { type: 'enterprise', maxUsage: -1 }
    };
    
    return planConfigs[planId] || { type: 'free', maxUsage: 3 };
}

// Utility functions
function generateUserId() {
    return 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function getCurrentBillingPeriod() {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}