// SESSION 4D3: Firebase Admin Panel - Secure Firebase Auth + RBAC
// Enhanced with firebase-auth-middleware and proper admin role validation

const { getFirestore } = require('../../firebase-config');
const firebaseAuthMiddleware = require('./firebase-auth-middleware');

exports.handler = async (event, context) => {
    // SESSION 4D3: Use firebase-auth-middleware for secure admin authentication
    const authResult = await firebaseAuthMiddleware.authenticateRequest(event, {
        requireAuth: true,
        requireSubscription: false, // Admin endpoints don't need subscription validation
        requireAdmin: true, // CRITICAL: Require admin role
        allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
        rateLimit: true
    });

    // Handle authentication failures
    if (!authResult.success) {
        return authResult.response;
    }

    const { headers, user } = authResult;

    try {
        const db = getFirestore();
        const { action, userId, userData, filters } = JSON.parse(event.body || '{}');

        switch (action) {
            case 'get_all_users':
                return await getAllUsers(db, filters, headers);
                
            case 'get_user':
                return await getUser(db, userId, headers);
                
            case 'update_user':
                return await updateUser(db, userId, userData, headers);
                
            case 'delete_user':
                return await deleteUser(db, userId, headers);
                
            case 'reset_user_usage':
                return await resetUserUsage(db, userId, headers);
                
            case 'get_analytics':
                return await getAnalytics(db, headers);
                
            case 'get_recent_activities':
                return await getRecentActivities(db, headers);
                
            default:
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ error: 'Invalid action' })
                };
        }
    } catch (error) {
        console.error('Firebase Admin API Error:', error);
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

// Get all users with optional filtering
async function getAllUsers(db, filters = {}, headers) {
    try {
        let query = db.collection('users');

        // Apply filters
        if (filters.subscriptionType) {
            query = query.where('subscriptionType', '==', filters.subscriptionType);
        }
        
        if (filters.status) {
            query = query.where('status', '==', filters.status);
        }

        // Limit results for performance
        query = query.limit(filters.limit || 100);
        
        const snapshot = await query.get();
        const users = [];
        
        snapshot.forEach(doc => {
            const userData = doc.data();
            // Remove sensitive data for admin view
            delete userData.paypalSubscriptionId; // Keep this private unless needed
            users.push({
                id: doc.id,
                ...userData
            });
        });

        // SESSION 4D3: Log admin activity with user context
        await logAdminActivity(db, 'get_all_users', { 
            filtersApplied: filters,
            resultsCount: users.length,
            timestamp: new Date().toISOString()
        }, user);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                users,
                count: users.length
            })
        };
    } catch (error) {
        console.error('Get all users error:', error);
        throw error;
    }
}

// Get specific user by ID
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

        // SESSION 4D3: Log admin activity with user context
        await logAdminActivity(db, 'get_user', { 
            userId,
            timestamp: new Date().toISOString()
        }, user);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                user: {
                    id: userDoc.id,
                    ...userData
                }
            })
        };
    } catch (error) {
        console.error('Get user error:', error);
        throw error;
    }
}

// Update user data (admin override)
async function updateUser(db, userId, updateData, headers) {
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

        // Validate and sanitize update data
        const allowedFields = [
            'maxUsage', 'monthlyUsage', 'subscriptionType', 
            'status', 'isSubscribed', 'email'
        ];
        
        const sanitizedUpdate = {};
        for (const [key, value] of Object.entries(updateData)) {
            if (allowedFields.includes(key)) {
                sanitizedUpdate[key] = value;
            }
        }

        sanitizedUpdate.lastActive = new Date().toISOString();

        await db.collection('users').doc(userId).update(sanitizedUpdate);

        // SESSION 4D3: Log admin activity with user context
        await logAdminActivity(db, 'update_user', { 
            userId,
            changesApplied: sanitizedUpdate,
            timestamp: new Date().toISOString()
        }, user);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                message: 'User updated successfully',
                changes: sanitizedUpdate
            })
        };
    } catch (error) {
        console.error('Update user error:', error);
        throw error;
    }
}

// Delete user (admin only - use with caution)
async function deleteUser(db, userId, headers) {
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

        // Archive user data before deletion
        await db.collection('deleted_users').doc(userId).set({
            ...userData,
            deletedAt: new Date().toISOString(),
            deletedBy: 'admin'
        });

        // Delete user
        await db.collection('users').doc(userId).delete();

        // SESSION 4D3: Log admin activity with user context
        await logAdminActivity(db, 'delete_user', { 
            userId,
            userEmail: userData.email,
            timestamp: new Date().toISOString()
        }, user);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                message: 'User deleted successfully (archived)'
            })
        };
    } catch (error) {
        console.error('Delete user error:', error);
        throw error;
    }
}

// Reset user usage (admin compensation)
async function resetUserUsage(db, userId, headers) {
    try {
        await db.collection('users').doc(userId).update({
            monthlyUsage: 0,
            lastResetPeriod: getCurrentBillingPeriod(),
            lastActive: new Date().toISOString()
        });

        // SESSION 4D3: Log admin activity with user context
        await logAdminActivity(db, 'reset_user_usage', { 
            userId,
            reason: 'Admin compensation/reset',
            timestamp: new Date().toISOString()
        }, user);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                message: 'User usage reset successfully'
            })
        };
    } catch (error) {
        console.error('Reset user usage error:', error);
        throw error;
    }
}

// Get platform analytics
async function getAnalytics(db, headers) {
    try {
        const users = await db.collection('users').get();
        
        const analytics = {
            totalUsers: 0,
            activeUsers: 0,
            subscriptionBreakdown: {
                free: 0,
                starter: 0,
                professional: 0,
                enterprise: 0
            },
            totalUsageThisMonth: 0,
            avgUsagePerUser: 0
        };

        let totalUsage = 0;
        const currentMonth = getCurrentBillingPeriod();

        users.forEach(doc => {
            const user = doc.data();
            analytics.totalUsers++;
            
            if (user.lastActive && isActiveUser(user.lastActive)) {
                analytics.activeUsers++;
            }
            
            analytics.subscriptionBreakdown[user.subscriptionType] = 
                (analytics.subscriptionBreakdown[user.subscriptionType] || 0) + 1;
            
            if (user.lastResetPeriod === currentMonth) {
                totalUsage += user.monthlyUsage || 0;
            }
        });

        analytics.totalUsageThisMonth = totalUsage;
        analytics.avgUsagePerUser = analytics.totalUsers > 0 ? 
            Math.round(totalUsage / analytics.totalUsers * 100) / 100 : 0;

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                analytics
            })
        };
    } catch (error) {
        console.error('Get analytics error:', error);
        throw error;
    }
}

// Get recent activities log
async function getRecentActivities(db, headers) {
    try {
        const snapshot = await db.collection('admin_logs')
            .orderBy('timestamp', 'desc')
            .limit(50)
            .get();

        const activities = [];
        snapshot.forEach(doc => {
            activities.push({
                id: doc.id,
                ...doc.data()
            });
        });

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                activities
            })
        };
    } catch (error) {
        console.error('Get recent activities error:', error);
        throw error;
    }
}

// SESSION 4D3: Enhanced admin activity logging with user context
async function logAdminActivity(db, action, details, adminUser = null) {
    try {
        await db.collection('admin_logs').add({
            action,
            details,
            timestamp: new Date().toISOString(),
            adminId: adminUser ? adminUser.uid : 'unknown',
            adminEmail: adminUser ? adminUser.email : 'unknown',
            ip: 'tracked_by_middleware' // IP tracking handled by middleware
        });
    } catch (error) {
        console.error('Failed to log admin activity:', error);
        // Don't throw - logging failure shouldn't break the main operation
    }
}

// Utility functions
function getCurrentBillingPeriod() {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

function isActiveUser(lastActiveString) {
    const lastActive = new Date(lastActiveString);
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    return lastActive > thirtyDaysAgo;
}