// Firebase User Management - Secure replacement for user.js
// Handles all user operations with Firebase Firestore

const { getFirestore } = require('../../firebase-config');

exports.handler = async (event, context) => {
    // Enable CORS
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS'
    };

    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers,
            body: ''
        };
    }

    try {
        const db = getFirestore();
        const { action, userId, email, subscriptionData } = JSON.parse(event.body || '{}');

        switch (action) {
            case 'get_user':
                return await getUser(db, userId, headers);
            
            case 'create_user':
                return await createUser(db, email, headers);
            
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

// Get user data from Firebase
async function getUser(db, userId, headers) {
    try {
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
async function createUser(db, email, headers) {
    try {
        const userId = generateUserId();
        const currentDate = new Date().toISOString();
        const currentMonth = getCurrentBillingPeriod();
        
        const userData = {
            id: userId,
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

// Utility functions
function generateUserId() {
    return 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function getCurrentBillingPeriod() {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}