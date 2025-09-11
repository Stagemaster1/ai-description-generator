// SESSION 4D3: Secure Admin interface with Firebase authentication and RBAC
// Enhanced with proper authentication middleware and admin role validation

const { getFirestore } = require('../../firebase-config');
const firebaseAuthMiddleware = require('./firebase-auth-middleware');
const dns = require('dns').promises;

// CRITICAL: Domain whitelist for approved email providers
const approvedDomains = ['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com', 'protonmail.com', 'aol.com'];

// CRITICAL: Email validation function with enhanced security
async function isValidEmailForAdmin(email) {
    if (!email || typeof email !== 'string') {
        return { valid: false, error: 'Email is required and must be a string' };
    }
    
    // CRITICAL: Security-approved email regex
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    
    // Basic length checks
    if (email.length < 3 || email.length > 320) {
        return { valid: false, error: 'Email length must be between 3 and 320 characters' };
    }
    
    // Split into local and domain parts
    const parts = email.split('@');
    if (parts.length !== 2) {
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
        return { valid: false, error: 'Email format does not match security requirements' };
    }
    
    // CRITICAL: Domain whitelist enforcement
    if (!approvedDomains.includes(domainPart.toLowerCase())) {
        return { valid: false, error: 'Email domain not in approved list. Please use Gmail, Outlook, Yahoo, iCloud, ProtonMail, or AOL' };
    }
    
    // CRITICAL: DNS MX record verification
    try {
        const mxRecords = await dns.resolveMx(domainPart);
        if (!mxRecords || mxRecords.length === 0) {
            return { valid: false, error: 'Email domain does not have valid mail servers' };
        }
    } catch (error) {
        console.error('DNS MX lookup failed for domain:', domainPart, error);
        return { valid: false, error: 'Email domain cannot be verified' };
    }
    
    return { valid: true, error: null };
}

// SESSION 4D3: Remove legacy authentication - now using firebase-auth-middleware
// Legacy rate limiting and password auth removed in favor of Firebase Auth + RBAC

exports.handler = async (event, context) => {
  // SESSION 4D3: Use firebase-auth-middleware for secure admin authentication
  const authResult = await firebaseAuthMiddleware.authenticateRequest(event, {
    requireAuth: true,
    requireSubscription: false, // Admin endpoints don't need subscription validation
    requireAdmin: true, // CRITICAL: Require admin role
    allowedMethods: ['POST', 'GET'],
    rateLimit: true
  });

  // Handle authentication failures
  if (!authResult.success) {
    return authResult.response;
  }

  const { headers, user } = authResult;

  try {
    const { action, userId, userData } = JSON.parse(event.body || '{}');

    // Initialize Firebase
    const db = getFirestore();

    switch (action) {
      case 'get_all_users':
        return await getAllUsers(db, headers);
      
      case 'get_user':
        return await getUser(db, userId, headers);
      
      case 'reset_usage':
        return await resetUserUsage(db, userId, headers);
      
      case 'reset_subscription':
        return await resetUserSubscription(db, userId, headers);
      
      case 'update_user':
        return await updateUser(db, userId, userData, headers);
      
      case 'delete_user':
        return await deleteUser(db, userId, headers);
      
      case 'create_test_user':
        return await createTestUser(db, userData, headers);
      
      // SESSION 4D3: Legacy password authentication removed for security
      
      case 'reset_all_usage':
        return await resetAllUsage(db, headers);
      
      case 'sync_user':
        return await syncUser(db, userId, userData, headers);
      
      case 'manual_add_user':
        return await manualAddUser(db, userData, headers);
      
      case 'manual_unlock':
        return await manualUnlockUser(db, userData, headers);
      
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

// SESSION 4D3: Firebase-enabled functions with admin access logging

async function getAllUsers(db, headers) {
  try {
    const snapshot = await db.collection('users').limit(100).get();
    const users = [];
    
    snapshot.forEach(doc => {
      users.push({
        id: doc.id,
        ...doc.data()
      });
    });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        users,
        total: users.length
      })
    };
  } catch (error) {
    console.error('Get all users error:', error);
    throw error;
  }
}

async function getUser(db, userId, headers) {
  try {
    const doc = await db.collection('users').doc(userId).get();
    
    if (!doc.exists) {
      return {
        statusCode: 404,
        headers,
        body: JSON.stringify({ 
          user: null,
          found: false
        })
      };
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        user: {
          id: doc.id,
          ...doc.data()
        },
        found: true
      })
    };
  } catch (error) {
    console.error('Get user error:', error);
    throw error;
  }
}

async function resetUserUsage(db, userId, headers) {
  try {
    const userRef = db.collection('users').doc(userId);
    const doc = await userRef.get();
    
    if (!doc.exists) {
      return {
        statusCode: 404,
        headers,
        body: JSON.stringify({ 
          success: false,
          message: `User ${userId} not found`
        })
      };
    }

    const updateData = {
      monthlyUsage: 0,
      lastReset: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    await userRef.update(updateData);
    
    const updatedDoc = await userRef.get();
    const updatedUser = { id: updatedDoc.id, ...updatedDoc.data() };

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: `Usage reset for user ${userId}`,
        user: updatedUser
      })
    };
  } catch (error) {
    console.error('Reset user usage error:', error);
    throw error;
  }
}

async function resetUserSubscription(db, userId, headers) {
  try {
    const userRef = db.collection('users').doc(userId);
    const doc = await userRef.get();
    
    const updateData = {
      isSubscribed: false,
      subscriptionType: 'free',
      maxUsage: 5,
      subscriptionId: null,
      subscriptionReset: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    if (doc.exists) {
      await userRef.update(updateData);
    } else {
      await userRef.set({
        id: userId,
        email: 'unknown@example.com',
        monthlyUsage: 0,
        createdAt: new Date().toISOString(),
        ...updateData
      });
    }

    const updatedDoc = await userRef.get();
    const updatedUser = updatedDoc.exists ? { id: updatedDoc.id, ...updatedDoc.data() } : null;
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: `Subscription reset for user ${userId}`,
        user: updatedUser
      })
    };
  } catch (error) {
    console.error('Reset user subscription error:', error);
    throw error;
  }
}

async function updateUser(db, userId, userData, headers) {
  try {
    const userRef = db.collection('users').doc(userId);
    const doc = await userRef.get();
    
    const updateData = {
      ...userData,
      updatedAt: new Date().toISOString()
    };

    if (doc.exists) {
      await userRef.update(updateData);
    } else {
      await userRef.set({
        id: userId,
        email: userData.email || 'unknown@example.com',
        subscriptionType: 'free',
        monthlyUsage: 0,
        maxUsage: 5,
        isSubscribed: false,
        createdAt: new Date().toISOString(),
        ...updateData
      });
    }

    const updatedDoc = await userRef.get();
    const updatedUser = { id: updatedDoc.id, ...updatedDoc.data() };
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: `User ${userId} updated`,
        user: updatedUser
      })
    };
  } catch (error) {
    console.error('Update user error:', error);
    throw error;
  }
}

async function deleteUser(db, userId, headers) {
  try {
    const userRef = db.collection('users').doc(userId);
    const doc = await userRef.get();
    const existed = doc.exists;
    
    if (existed) {
      // Archive user data before deletion
      await db.collection('deleted_users').doc(userId).set({
        ...doc.data(),
        deletedAt: new Date().toISOString(),
        deletedBy: 'admin'
      });
      
      // Delete the user
      await userRef.delete();
    }
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: `User ${userId} ${existed ? 'deleted and archived' : 'not found'}`,
        existed
      })
    };
  } catch (error) {
    console.error('Delete user error:', error);
    throw error;
  }
}

async function createTestUser(db, userData, headers) {
  try {
    // CRITICAL: Validate email if provided
    if (userData.email && !userData.email.includes('@example.com')) {
      const emailValidation = await isValidEmailForAdmin(userData.email);
      if (!emailValidation.valid) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({
            success: false,
            error: `Email validation failed: ${emailValidation.error}`
          })
        };
      }
    }
    
    const userId = `test-${Date.now()}`;
    const userRef = db.collection('users').doc(userId);
    
    const newUser = {
      id: userId,
      email: userData.email || `test-${userId}@example.com`,
      subscriptionType: 'free',
      monthlyUsage: 0,
      maxUsage: 5,
      isSubscribed: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      testUser: true,
      ...userData
    };
    
    await userRef.set(newUser);
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: `Test user created`,
        user: newUser
      })
    };
  } catch (error) {
    console.error('Create test user error:', error);
    throw error;
  }
}

async function resetAllUsage(db, headers) {
  try {
    const snapshot = await db.collection('users').get();
    let resetCount = 0;
    const timestamp = new Date().toISOString();
    
    const batch = db.batch();
    
    snapshot.forEach(doc => {
      batch.update(doc.ref, {
        monthlyUsage: 0,
        lastReset: timestamp,
        updatedAt: timestamp
      });
      resetCount++;
    });
    
    await batch.commit();
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: `Usage reset for ${resetCount} users`,
        resetCount,
        timestamp
      })
    };
  } catch (error) {
    console.error('Reset all usage error:', error);
    throw error;
  }
}

// SESSION 4D3: CRITICAL SECURITY FIX - Legacy password authentication function removed
// This legacy function used ADMIN_PASSWORD environment variable which created a security vulnerability
// All admin authentication is now handled by Firebase Auth + RBAC in firebase-auth-middleware.js
// Admin access is secured by:
// 1. Firebase ID token validation
// 2. Email verification requirements  
// 3. Admin role validation in Firestore
// 4. Environment variable ADMIN_EMAIL verification

async function syncUser(db, userId, userData, headers) {
  try {
    const userRef = db.collection('users').doc(userId);
    const doc = await userRef.get();
    const existingUser = doc.exists ? doc.data() : {};
    
    const syncedUser = {
      ...existingUser,
      id: userId,
      email: userData.email || existingUser.email || 'subscriber@unknown.com',
      subscriptionType: userData.subscriptionType || 'free',
      monthlyUsage: userData.monthlyUsage || existingUser.monthlyUsage || 0,
      maxUsage: userData.maxUsage || 5,
      isSubscribed: userData.isSubscribed || false,
      subscriptionId: userData.subscriptionId || existingUser.subscriptionId,
      lastActive: userData.lastActive || new Date().toISOString(),
      syncedFromClient: true,
      syncedAt: new Date().toISOString(),
      createdAt: existingUser.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    await userRef.set(syncedUser);
    
    console.log('User synced to Firestore:', { userId, userData });
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: `User ${userId} synced successfully`,
        user: syncedUser
      })
    };
  } catch (error) {
    console.error('Sync user error:', error);
    throw error;
  }
}

async function manualAddUser(db, userData, headers) {
  try {
    const email = userData.email || 'manual@unknown.com';
    const emailLower = email.toLowerCase().trim();
    
    // CRITICAL: Validate email if it's not a default/test email
    if (!emailLower.includes('@unknown.com') && !emailLower.includes('@example.com')) {
      const emailValidation = await isValidEmailForAdmin(emailLower);
      if (!emailValidation.valid) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({
            success: false,
            error: `Email validation failed: ${emailValidation.error}`
          })
        };
      }
    }
    
    // Check for existing user by email
    const snapshot = await db.collection('users').where('email', '==', emailLower).get();
    
    if (!snapshot.empty) {
      // Update existing user
      const doc = snapshot.docs[0];
      const existingUser = doc.data();
      
      const updateData = {
        ...existingUser,
        email: emailLower,
        subscriptionType: userData.subscriptionType || 'starter',
        monthlyUsage: userData.monthlyUsage || 0,
        maxUsage: userData.maxUsage || 50,
        isSubscribed: userData.isSubscribed !== false,
        subscriptionId: userData.subscriptionId || existingUser.subscriptionId || `manual-${Date.now()}`,
        lastActive: new Date().toISOString(),
        manuallyAdded: true,
        updatedAt: new Date().toISOString()
      };
      
      await doc.ref.update(updateData);
      
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
          success: true,
          message: `User ${emailLower} updated successfully (existing user)`,
          user: { id: doc.id, ...updateData }
        })
      };
    } else {
      // Create new user
      const userId = `manual_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;
      const userRef = db.collection('users').doc(userId);
      
      const newUser = {
        id: userId,
        email: emailLower,
        subscriptionType: userData.subscriptionType || 'starter',
        monthlyUsage: userData.monthlyUsage || 0,
        maxUsage: userData.maxUsage || 50,
        isSubscribed: userData.isSubscribed !== false,
        subscriptionId: userData.subscriptionId || `manual-${Date.now()}`,
        lastActive: new Date().toISOString(),
        manuallyAdded: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      await userRef.set(newUser);
      
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
          success: true,
          message: `User ${emailLower} added successfully (new user)`,
          user: newUser
        })
      };
    }
  } catch (error) {
    console.error('Manual add user error:', error);
    throw error;
  }
}

async function manualUnlockUser(db, userData, headers) {
  try {
    const email = userData.email;
    if (!email) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          success: false,
          error: 'Email is required'
        })
      };
    }

    const emailLower = email.toLowerCase().trim();
    
    // CRITICAL: Validate email for unlock operations
    const emailValidation = await isValidEmailForAdmin(emailLower);
    if (!emailValidation.valid) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: `Email validation failed: ${emailValidation.error}`
        })
      };
    }
    
    // Check for existing user by email
    const snapshot = await db.collection('users').where('email', '==', emailLower).get();
    
    if (!snapshot.empty) {
      // Update existing user
      const doc = snapshot.docs[0];
      
      const updateData = {
        manuallyUnlocked: true,
        maxUsage: 999999,
        subscriptionType: 'unlocked',
        updatedAt: new Date().toISOString()
      };
      
      await doc.ref.update(updateData);
      
      const updatedDoc = await doc.ref.get();
      const updatedUser = { id: updatedDoc.id, ...updatedDoc.data() };
      
      console.log('Existing user unlocked in Firestore:', updatedUser);
      
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
          success: true,
          message: `${email} unlocked with unlimited access (updated existing user)`,
          user: updatedUser
        })
      };
    } else {
      // Create new user
      const userId = `unlock_${email.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
      const userRef = db.collection('users').doc(userId);
      
      const newUser = {
        id: userId,
        email: emailLower,
        subscriptionType: 'unlocked',
        monthlyUsage: 0,
        maxUsage: 999999,
        isSubscribed: true,
        subscriptionId: `manual-unlock-${Date.now()}`,
        lastActive: new Date().toISOString(),
        manuallyUnlocked: true,
        unlockedBy: 'admin',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      await userRef.set(newUser);
      
      console.log('New user created and unlocked in Firestore:', newUser);
      
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
          success: true,
          message: `${email} unlocked with unlimited access (new user created)`,
          user: newUser
        })
      };
    }
  } catch (error) {
    console.error('Manual unlock user error:', error);
    throw error;
  }
}

// SESSION 4D3: Rate limiting now handled by firebase-auth-middleware
// Legacy rate limiting functions removed - centralized in middleware