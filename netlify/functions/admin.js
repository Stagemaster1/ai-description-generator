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

async function getAllUsers(headers) {
  // In a real app, this would query your database
  // For now, return mock data + any stored users
  const mockUsers = [
    {
      id: 'user-001',
      email: 'test@example.com',
      subscriptionType: 'free',
      monthlyUsage: 3,
      maxUsage: 5,
      isSubscribed: false,
      createdAt: new Date().toISOString(),
      lastActive: new Date().toISOString()
    },
    {
      id: 'user-002', 
      email: 'premium@example.com',
      subscriptionType: 'starter',
      monthlyUsage: 25,
      maxUsage: 50,
      isSubscribed: true,
      subscriptionId: 'paypal-sub-123',
      createdAt: new Date().toISOString(),
      lastActive: new Date().toISOString()
    }
  ];

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ 
      users: [...mockUsers, ...Object.values(users)],
      total: mockUsers.length + Object.keys(users).length
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
  if (users[userId]) {
    users[userId].monthlyUsage = 0;
    users[userId].lastReset = new Date().toISOString();
  }
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ 
      success: true,
      message: `Usage reset for user ${userId}`,
      user: users[userId] || null
    })
  };
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