// Secure User Management Endpoint with Firebase Authentication and Basic RBAC
// SESSION 4D2 Implementation - User Endpoint Security with Role Validation

const firebaseAuthMiddleware = require('./firebase-auth-middleware');
const securityLogger = require('./security-logger');
const { getFirestore } = require('./firebase-config');

// Basic RBAC role definitions
const USER_ROLES = {
  USER: 'user',
  ADMIN: 'admin',
  SYSTEM: 'system'
};

// Operation-to-role mapping for authorization
const OPERATION_PERMISSIONS = {
  'get_usage': [USER_ROLES.USER, USER_ROLES.ADMIN],
  'increment_usage': [USER_ROLES.USER, USER_ROLES.ADMIN],
  'reset_usage': [USER_ROLES.ADMIN], // Admin only
  'create_user': [USER_ROLES.USER, USER_ROLES.ADMIN],
  'get_all_users': [USER_ROLES.ADMIN], // Admin only
  'update_user_role': [USER_ROLES.ADMIN], // Admin only
  'delete_user': [USER_ROLES.ADMIN] // Admin only
};

// SECURITY FIX: Replace memory storage with Firebase Firestore persistence
// This prevents subscription manipulation and revenue bypass vulnerabilities

exports.handler = async (event, context) => {
  const startTime = Date.now();
  
  try {
    // SECURITY: Use Firebase Auth Middleware for comprehensive authentication
    const authResult = await firebaseAuthMiddleware.authenticateRequest(event, {
      requireAuth: true,
      requireSubscription: false, // User endpoint doesn't require active subscription
      allowedMethods: ['GET', 'POST', 'PUT'],
      rateLimit: true
    });

    // Handle authentication failure
    if (!authResult.success) {
      return authResult.response;
    }

    const { user, headers, clientIP } = authResult;

    // Parse request body with validation
    let requestData;
    try {
      requestData = JSON.parse(event.body || '{}');
    } catch (parseError) {
      securityLogger.logOperationFailure({
        operation: 'user_request_parsing',
        userId: user.uid,
        endpoint: 'user',
        error: 'Invalid JSON in request body',
        duration: Date.now() - startTime
      });

      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          success: false,
          error: 'Invalid JSON format in request body' 
        })
      };
    }

    const { action, userId, email, targetUserId, role } = requestData;

    // SECURITY: Validate action parameter
    if (!action || typeof action !== 'string') {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          success: false,
          error: 'Action parameter is required and must be a string' 
        })
      };
    }

    // SECURITY: Get user role for authorization
    const userRole = await getUserRole(user.uid);
    
    // SECURITY: Validate user has permission for requested operation
    if (!hasPermission(userRole, action)) {
      securityLogger.logAuthzFailure({
        userId: user.uid,
        email: user.email,
        reason: 'insufficient_permissions',
        requiredPermission: action,
        currentPermissions: [userRole],
        clientIP: clientIP,
        endpoint: 'user'
      });

      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ 
          success: false,
          error: 'Insufficient permissions for this operation',
          requiredRole: OPERATION_PERMISSIONS[action],
          currentRole: userRole
        })
      };
    }

    // SECURITY: Validate userId parameter if provided
    const effectiveUserId = userId || user.uid; // Use authenticated user ID if not specified
    if (effectiveUserId && !isValidUserId(effectiveUserId)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          success: false,
          error: 'Invalid userId format',
          message: 'userId must be a valid Firebase UID' 
        })
      };
    }

    // SECURITY: Additional authorization checks for user-specific operations
    if (userId && userId !== user.uid && userRole !== USER_ROLES.ADMIN) {
      securityLogger.logAuthzFailure({
        userId: user.uid,
        email: user.email,
        reason: 'unauthorized_user_access',
        requiredPermission: 'admin_access',
        currentPermissions: [userRole],
        clientIP: clientIP,
        endpoint: 'user'
      });

      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ 
          success: false,
          error: 'Access denied: Cannot access other user data without admin privileges' 
        })
      };
    }

    // Route to appropriate handler with role-based access control
    let result;
    switch (action) {
      case 'get_usage':
        result = await getUserUsage(effectiveUserId, user, headers);
        break;
      
      case 'increment_usage':
        result = await incrementUsage(effectiveUserId, user, headers);
        break;
      
      case 'reset_usage':
        result = await resetUsage(effectiveUserId, user, headers, userRole);
        break;
      
      case 'create_user':
        result = await createUser(user.uid, email || user.email, user, headers);
        break;

      case 'get_all_users':
        result = await getAllUsers(user, headers, userRole);
        break;

      case 'update_user_role':
        result = await updateUserRole(targetUserId, role, user, headers, userRole);
        break;

      case 'delete_user':
        result = await deleteUser(targetUserId, user, headers, userRole);
        break;
      
      default:
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ 
            success: false,
            error: 'Invalid action',
            supportedActions: Object.keys(OPERATION_PERMISSIONS)
          })
        };
    }

    // Log successful operation
    securityLogger.logOperationSuccess({
      operation: `user_${action}`,
      userId: user.uid,
      endpoint: 'user',
      duration: Date.now() - startTime,
      resourcesAccessed: ['users']
    });

    return result;

  } catch (error) {
    // Log operation failure
    securityLogger.logOperationFailure({
      operation: 'user_endpoint',
      userId: 'unknown',
      endpoint: 'user',
      error: error.message,
      duration: Date.now() - startTime,
      stackTrace: error.stack
    });

    console.error('User API Error:', error);
    return {
      statusCode: 500,
      headers: firebaseAuthMiddleware.createSecureHeaders(),
      body: JSON.stringify({ 
        success: false,
        error: 'Internal server error',
        message: 'An error occurred processing your request'
      })
    };
  }
};

/**
 * Get user role from Firestore or default to 'user'
 * @param {string} userId - User ID
 * @returns {string} User role
 */
async function getUserRole(userId) {
  try {
    const db = getFirestore();
    const userDoc = await db.collection('users').doc(userId).get();
    
    if (userDoc.exists) {
      const userData = userDoc.data();
      return userData.role || USER_ROLES.USER;
    }
    
    return USER_ROLES.USER; // Default role
  } catch (error) {
    console.error('Error getting user role:', error);
    return USER_ROLES.USER; // Default role on error
  }
}

/**
 * Check if user has permission for operation
 * @param {string} userRole - User's role
 * @param {string} operation - Requested operation
 * @returns {boolean} True if user has permission
 */
function hasPermission(userRole, operation) {
  const allowedRoles = OPERATION_PERMISSIONS[operation];
  if (!allowedRoles) {
    return false; // Operation not defined
  }
  return allowedRoles.includes(userRole);
}

/**
 * Validate userId format
 * @param {string} userId - User ID to validate
 * @returns {boolean} True if valid
 */
function isValidUserId(userId) {
  // Firebase UIDs are typically 28 characters long and alphanumeric
  if (!userId || typeof userId !== 'string') {
    return false;
  }
  
  // Check length (Firebase UIDs are typically 28 characters)
  if (userId.length < 10 || userId.length > 128) {
    return false;
  }
  
  // Check for valid characters (alphanumeric and some special chars)
  const uidPattern = /^[a-zA-Z0-9_-]+$/;
  if (!uidPattern.test(userId)) {
    return false;
  }
  
  // Prevent common attack patterns
  const dangerousPatterns = [
    '../', '..\\', '<script', 'javascript:', 'data:',
    'null', 'undefined'
  ];
  
  const lowerUserId = userId.toLowerCase();
  for (const pattern of dangerousPatterns) {
    if (lowerUserId.includes(pattern)) {
      return false;
    }
  }
  
  return true;
}

/**
 * Get user usage data from memory storage
 * @param {string} userId - User ID
 * @param {Object} authenticatedUser - Authenticated user object
 * @param {Object} headers - Response headers
 * @returns {Object} Response object
 */
async function getUserUsage(userId, authenticatedUser, headers) {
  try {
    // Additional userId validation at function level
    if (!userId || !isValidUserId(userId)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          success: false,
          error: 'Valid userId is required' 
        })
      };
    }

    // SECURITY FIX: Use Firestore for persistent user storage
    const db = getFirestore();
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    
    let userData;
    if (!userDoc.exists) {
      // Initialize new user in Firestore
      userData = {
        id: userId,
        email: authenticatedUser.email,
        monthlyUsage: 0,
        maxUsage: 5,
        subscriptionType: 'free',
        isSubscribed: false,
        role: USER_ROLES.USER,
        createdAt: new Date().toISOString(),
        lastActive: new Date().toISOString()
      };
      await userRef.set(userData);
    } else {
      userData = userDoc.data();
      // Update last active timestamp
      userData.lastActive = new Date().toISOString();
      await userRef.update({ lastActive: userData.lastActive });
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
    console.error('Get usage error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Failed to retrieve usage data'
      })
    };
  }
}

/**
 * Increment user usage count with validation
 * @param {string} userId - User ID
 * @param {Object} authenticatedUser - Authenticated user object
 * @param {Object} headers - Response headers
 * @returns {Object} Response object
 */
async function incrementUsage(userId, authenticatedUser, headers) {
  try {
    // Critical: Validate userId before processing
    if (!userId || !isValidUserId(userId)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          success: false,
          error: 'Valid userId is required for usage tracking' 
        })
      };
    }

    // SECURITY FIX: Use Firestore for persistent user storage
    const db = getFirestore();
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    
    let userData;
    if (!userDoc.exists) {
      // Initialize new user in Firestore
      userData = {
        id: userId,
        email: authenticatedUser.email,
        monthlyUsage: 0,
        maxUsage: 5,
        subscriptionType: 'free',
        isSubscribed: false,
        role: USER_ROLES.USER,
        createdAt: new Date().toISOString(),
        lastActive: new Date().toISOString()
      };
      await userRef.set(userData);
    } else {
      userData = userDoc.data();
    }
    
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

    // Increment usage and update timestamp in Firestore
    userData.monthlyUsage = newUsage;
    userData.lastActive = new Date().toISOString();
    await userRef.update({
      monthlyUsage: newUsage,
      lastActive: userData.lastActive
    });
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        user: userData,
        message: 'Usage incremented successfully'
      })
    };
  } catch (error) {
    console.error('Increment usage error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Failed to increment usage'
      })
    };
  }
}

/**
 * Reset user usage (admin function)
 * @param {string} userId - User ID
 * @param {Object} authenticatedUser - Authenticated user object
 * @param {Object} headers - Response headers
 * @param {string} userRole - User's role
 * @returns {Object} Response object
 */
async function resetUsage(userId, authenticatedUser, headers, userRole) {
  try {
    // SECURITY: Additional admin check
    if (userRole !== USER_ROLES.ADMIN) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Admin privileges required for usage reset'
        })
      };
    }

    // Critical: Validate userId for usage reset
    if (!userId || !isValidUserId(userId)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          success: false,
          error: 'Valid userId is required for usage reset' 
        })
      };
    }

    // SECURITY FIX: Reset usage in Firestore
    const db = getFirestore();
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    
    if (userDoc.exists) {
      await userRef.update({
        monthlyUsage: 0,
        lastActive: new Date().toISOString(),
        resetBy: authenticatedUser.uid,
        resetAt: new Date().toISOString()
      });
    }
    
    // Log admin action
    securityLogger.logOperationSuccess({
      operation: 'admin_usage_reset',
      userId: authenticatedUser.uid,
      endpoint: 'user',
      resourcesAccessed: [`user_${userId}`]
    });
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'Usage reset successfully',
        resetBy: authenticatedUser.email
      })
    };
  } catch (error) {
    console.error('Reset usage error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Failed to reset usage'
      })
    };
  }
}

/**
 * Create new user with Firebase UID
 * @param {string} userId - User ID
 * @param {string} email - User email
 * @param {Object} authenticatedUser - Authenticated user object
 * @param {Object} headers - Response headers
 * @returns {Object} Response object
 */
async function createUser(userId, email, authenticatedUser, headers) {
  try {
    // Critical: Enhanced userId validation for user creation
    if (!userId || !isValidUserId(userId)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Valid User ID from Firebase Authentication is required'
        })
      };
    }

    // Basic email validation
    if (email && !isValidEmail(email)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Valid email address is required'
        })
      };
    }

    const currentDate = new Date().toISOString();
    const currentMonth = getCurrentBillingPeriod();
    
    const userData = {
      id: userId, // Use Firebase UID
      email: email,
      monthlyUsage: 0,
      maxUsage: 5,
      subscriptionType: 'free',
      isSubscribed: false,
      role: USER_ROLES.USER, // Default role
      lastResetPeriod: currentMonth,
      createdAt: currentDate,
      lastActive: currentDate,
      status: 'active',
      createdBy: authenticatedUser.uid
    };

    // SECURITY FIX: Store user in Firestore
    const db = getFirestore();
    const userRef = db.collection('users').doc(userId);
    await userRef.set(userData);

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
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Failed to create user'
      })
    };
  }
}

/**
 * Get all users (admin only)
 * @param {Object} authenticatedUser - Authenticated user object
 * @param {Object} headers - Response headers
 * @param {string} userRole - User's role
 * @returns {Object} Response object
 */
async function getAllUsers(authenticatedUser, headers, userRole) {
  try {
    // SECURITY: Admin-only operation
    if (userRole !== USER_ROLES.ADMIN) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Admin privileges required'
        })
      };
    }

    // SECURITY FIX: Get all users from Firestore
    const db = getFirestore();
    const usersSnapshot = await db.collection('users').get();
    
    const sanitizedUsers = [];
    usersSnapshot.forEach(doc => {
      const user = doc.data();
      sanitizedUsers.push({
        id: user.id,
        email: user.email,
        monthlyUsage: user.monthlyUsage,
        maxUsage: user.maxUsage,
        subscriptionType: user.subscriptionType,
        isSubscribed: user.isSubscribed,
        role: user.role,
        status: user.status,
        createdAt: user.createdAt,
        lastActive: user.lastActive
      });
    });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        users: sanitizedUsers,
        total: sanitizedUsers.length
      })
    };
  } catch (error) {
    console.error('Get all users error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Failed to retrieve users'
      })
    };
  }
}

/**
 * Update user role (admin only)
 * @param {string} targetUserId - Target user ID
 * @param {string} role - New role
 * @param {Object} authenticatedUser - Authenticated user object
 * @param {Object} headers - Response headers
 * @param {string} userRole - User's role
 * @returns {Object} Response object
 */
async function updateUserRole(targetUserId, role, authenticatedUser, headers, userRole) {
  try {
    // SECURITY: Admin-only operation
    if (userRole !== USER_ROLES.ADMIN) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Admin privileges required'
        })
      };
    }

    // Validate target user ID and role
    if (!targetUserId || !isValidUserId(targetUserId)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Valid target userId is required'
        })
      };
    }

    if (!role || !Object.values(USER_ROLES).includes(role)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Valid role is required',
          validRoles: Object.values(USER_ROLES)
        })
      };
    }

    // SECURITY FIX: Check and update user role in Firestore
    const db = getFirestore();
    const userRef = db.collection('users').doc(targetUserId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return {
        statusCode: 404,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Target user not found'
        })
      };
    }

    const userData = userDoc.data();
    const oldRole = userData.role;
    
    // Update user role in Firestore
    await userRef.update({
      role: role,
      roleUpdatedBy: authenticatedUser.uid,
      roleUpdatedAt: new Date().toISOString()
    });

    // Log role change
    securityLogger.logOperationSuccess({
      operation: 'admin_role_update',
      userId: authenticatedUser.uid,
      endpoint: 'user',
      resourcesAccessed: [`user_${targetUserId}`]
    });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'User role updated successfully',
        targetUserId,
        oldRole,
        newRole: role,
        updatedBy: authenticatedUser.email
      })
    };
  } catch (error) {
    console.error('Update user role error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Failed to update user role'
      })
    };
  }
}

/**
 * Delete user (admin only)
 * @param {string} targetUserId - Target user ID
 * @param {Object} authenticatedUser - Authenticated user object
 * @param {Object} headers - Response headers
 * @param {string} userRole - User's role
 * @returns {Object} Response object
 */
async function deleteUser(targetUserId, authenticatedUser, headers, userRole) {
  try {
    // SECURITY: Admin-only operation
    if (userRole !== USER_ROLES.ADMIN) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Admin privileges required'
        })
      };
    }

    // Validate target user ID
    if (!targetUserId || !isValidUserId(targetUserId)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Valid target userId is required'
        })
      };
    }

    // SECURITY FIX: Check and delete user in Firestore
    const db = getFirestore();
    const userRef = db.collection('users').doc(targetUserId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return {
        statusCode: 404,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Target user not found'
        })
      };
    }

    // Prevent admin from deleting themselves
    if (targetUserId === authenticatedUser.uid) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Cannot delete your own user account'
        })
      };
    }

    // Store user info for logging
    const userData = userDoc.data();
    const deletedUserEmail = userData.email;

    // Delete user from Firestore
    await userRef.delete();

    // Log user deletion
    securityLogger.logOperationSuccess({
      operation: 'admin_user_deletion',
      userId: authenticatedUser.uid,
      endpoint: 'user',
      resourcesAccessed: [`user_${targetUserId}`]
    });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'User deleted successfully',
        deletedUserId: targetUserId,
        deletedUserEmail,
        deletedBy: authenticatedUser.email
      })
    };
  } catch (error) {
    console.error('Delete user error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Failed to delete user'
      })
    };
  }
}

/**
 * Email validation function
 * @param {string} email - Email to validate
 * @returns {boolean} True if valid
 */
function isValidEmail(email) {
  if (!email || typeof email !== 'string') {
    return false;
  }
  
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email) && email.length <= 320;
}

/**
 * Helper function to get current billing period
 * @returns {string} Current billing period
 */
function getCurrentBillingPeriod() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

// Export role constants for use in other modules
module.exports.USER_ROLES = USER_ROLES;
module.exports.OPERATION_PERMISSIONS = OPERATION_PERMISSIONS;
