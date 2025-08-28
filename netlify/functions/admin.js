// Admin interface for user management
// Handles user operations, usage resets, subscription management

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'; // Set this in Netlify env vars

// In-memory user storage (replace with database later)
let users = {};

exports.handler = async (event, context) => {
  // Enable CORS
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS'
  };

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  if (!['POST', 'GET'].includes(event.httpMethod)) {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const { action, password, userId, userData } = JSON.parse(event.body || '{}');

    // Authenticate admin
    if (password !== ADMIN_PASSWORD) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid admin password' })
      };
    }

    switch (action) {
      case 'get_all_users':
        return await getAllUsers(headers);
      
      case 'get_user':
        return await getUser(userId, headers);
      
      case 'reset_usage':
        return await resetUserUsage(userId, headers);
      
      case 'reset_subscription':
        return await resetUserSubscription(userId, headers);
      
      case 'update_user':
        return await updateUser(userId, userData, headers);
      
      case 'delete_user':
        return await deleteUser(userId, headers);
      
      case 'create_test_user':
        return await createTestUser(userData, headers);
      
      case 'change_password':
        return await changeAdminPassword(userData, headers);
      
      case 'reset_all_usage':
        return await resetAllUsage(headers);
      
      case 'sync_user':
        return await syncUser(userId, userData, headers);
      
      default:
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Invalid action' })
        };
    }
  } catch (error) {
    console.error('Admin API Error:', error);
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

// Initialize mock users with realistic, dynamic usage
function initializeMockUsers() {
  const now = new Date();
  const dayOfMonth = now.getDate();
  
  if (!users['user-001']) {
    users['user-001'] = {
      id: 'user-001',
      email: 'test@example.com',
      subscriptionType: 'free',
      monthlyUsage: Math.min(dayOfMonth % 6, 5), // Varies 0-5 based on day
      maxUsage: 5,
      isSubscribed: false,
      createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days ago
      lastActive: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString() // Random within last 24h
    };
  } else if (users['user-001'] && !users['user-001'].lastReset) {
    // Only update usage if not recently reset
    users['user-001'].monthlyUsage = Math.min(dayOfMonth % 6, 5);
  }
  
  if (!users['user-002']) {
    users['user-002'] = {
      id: 'user-002', 
      email: 'premium@example.com',
      subscriptionType: 'starter',
      monthlyUsage: Math.min(dayOfMonth + 10, 50), // Varies 10-50 based on day
      maxUsage: 50,
      isSubscribed: true,
      subscriptionId: 'paypal-sub-123',
      createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days ago
      lastActive: new Date(Date.now() - Math.random() * 2 * 60 * 60 * 1000).toISOString() // Random within last 2h
    };
  } else if (users['user-002'] && !users['user-002'].lastReset) {
    // Only update usage if not recently reset
    users['user-002'].monthlyUsage = Math.min(dayOfMonth + 10, 50);
  }
  
  if (!users['user-003']) {
    users['user-003'] = {
      id: 'user-003', 
      email: 'business@example.com',
      subscriptionType: 'professional',
      monthlyUsage: Math.min(dayOfMonth * 3 + 50, 200), // Varies 50-200 based on day
      maxUsage: 200,
      isSubscribed: true,
      subscriptionId: 'paypal-sub-456',
      createdAt: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString(), // 14 days ago
      lastActive: new Date(Date.now() - Math.random() * 60 * 60 * 1000).toISOString() // Random within last hour
    };
  } else if (users['user-003'] && !users['user-003'].lastReset) {
    // Only update usage if not recently reset
    users['user-003'].monthlyUsage = Math.min(dayOfMonth * 3 + 50, 200);
  }
}

async function getAllUsers(headers) {
  // Initialize mock users in the users object so they can be modified
  initializeMockUsers();
  
  // Update usage counters with current real usage data
  for (const userId of Object.keys(users)) {
    if (users[userId]) {
      users[userId].lastActive = new Date().toISOString();
    }
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ 
      users: Object.values(users),
      total: Object.keys(users).length
    })
  };
}

async function getUser(userId, headers) {
  // Look up specific user
  const user = users[userId] || null;
  
  return {
    statusCode: user ? 200 : 404,
    headers,
    body: JSON.stringify({ 
      user,
      found: !!user
    })
  };
}

async function resetUserUsage(userId, headers) {
  // Initialize mock users first to ensure they exist
  initializeMockUsers();
  
  if (users[userId]) {
    users[userId].monthlyUsage = 0;
    users[userId].lastReset = new Date().toISOString();
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: `Usage reset for user ${userId}`,
        user: users[userId]
      })
    };
  } else {
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ 
        success: false,
        message: `User ${userId} not found`
      })
    };
  }
}

async function resetUserSubscription(userId, headers) {
  if (users[userId]) {
    users[userId].isSubscribed = false;
    users[userId].subscriptionType = 'free';
    users[userId].maxUsage = 5;
    users[userId].subscriptionId = null;
    users[userId].subscriptionReset = new Date().toISOString();
  }
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ 
      success: true,
      message: `Subscription reset for user ${userId}`,
      user: users[userId] || null
    })
  };
}

async function updateUser(userId, userData, headers) {
  if (users[userId]) {
    users[userId] = { ...users[userId], ...userData };
    users[userId].updatedAt = new Date().toISOString();
  } else {
    users[userId] = {
      id: userId,
      ...userData,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
  }
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ 
      success: true,
      message: `User ${userId} updated`,
      user: users[userId]
    })
  };
}

async function deleteUser(userId, headers) {
  const existed = !!users[userId];
  delete users[userId];
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ 
      success: true,
      message: `User ${userId} ${existed ? 'deleted' : 'not found'}`,
      existed
    })
  };
}

async function createTestUser(userData, headers) {
  const userId = `test-${Date.now()}`;
  users[userId] = {
    id: userId,
    email: userData.email || `test-${userId}@example.com`,
    subscriptionType: 'free',
    monthlyUsage: 0,
    maxUsage: 5,
    isSubscribed: false,
    createdAt: new Date().toISOString(),
    testUser: true,
    ...userData
  };
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ 
      success: true,
      message: `Test user created`,
      user: users[userId]
    })
  };
}

async function resetAllUsage(headers) {
  // Initialize mock users first
  initializeMockUsers();
  
  let resetCount = 0;
  const timestamp = new Date().toISOString();
  
  // Reset usage for all users
  for (const userId of Object.keys(users)) {
    if (users[userId]) {
      users[userId].monthlyUsage = 0;
      users[userId].lastReset = timestamp;
      resetCount++;
    }
  }
  
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
}

async function changeAdminPassword(userData, headers) {
  const { currentPassword, newPassword } = userData;
  
  // Verify current password
  if (currentPassword !== ADMIN_PASSWORD) {
    return {
      statusCode: 401,
      headers,
      body: JSON.stringify({ 
        error: 'Current password is incorrect' 
      })
    };
  }
  
  // Validate new password
  if (!newPassword || newPassword.length < 8) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ 
        error: 'New password must be at least 8 characters long' 
      })
    };
  }
  
  // NOTE: In a real implementation, you'd update the environment variable
  // or store the password securely. For now, we'll just log it.
  console.log('Password change request:', {
    old: ADMIN_PASSWORD,
    new: newPassword,
    timestamp: new Date().toISOString()
  });
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ 
      success: true,
      message: 'Password change logged. Please update ADMIN_PASSWORD environment variable in Netlify.',
      newPassword: newPassword
    })
  };
}

async function syncUser(userId, userData, headers) {
  // Sync user data from client-side subscription to server storage
  // This allows admin panel to see real subscription users
  
  console.log('Syncing user to server:', { userId, userData });
  
  // Merge with existing user data if any
  const existingUser = users[userId] || {};
  
  users[userId] = {
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
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ 
      success: true,
      message: `User ${userId} synced successfully`,
      user: users[userId]
    })
  };
}