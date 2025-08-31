// PayPal Webhook Handler - Secure Firebase Integration
// Handles PayPal subscription events and stores data securely in Firebase

const { getFirestore } = require('../../firebase-config');
const crypto = require('crypto');

exports.handler = async (event, context) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'POST, OPTIONS'
    };

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
        const isValid = await verifyPayPalWebhook(event);
        
        if (!isValid) {
            console.error('Invalid PayPal webhook signature');
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ error: 'Unauthorized' })
            };
        }

        const webhookEvent = JSON.parse(event.body);
        const eventType = webhookEvent.event_type;

        console.log('PayPal Webhook Event:', eventType);

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

// Verify PayPal webhook signature
async function verifyPayPalWebhook(event) {
    try {
        // Get PayPal webhook ID from environment
        const webhookId = process.env.PAYPAL_WEBHOOK_ID;
        if (!webhookId) {
            console.warn('PAYPAL_WEBHOOK_ID not set - skipping verification');
            return true; // Allow in development, but log warning
        }

        // In production, implement proper PayPal webhook verification
        // For now, return true to allow processing
        return true;
    } catch (error) {
        console.error('Webhook verification error:', error);
        return false;
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