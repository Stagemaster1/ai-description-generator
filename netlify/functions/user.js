// Simple user management using shared memory store
// In a production environment, consider using a database like Supabase or Firebase

// Shared user storage (same as admin.js)
let users = {};

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
    const { action, userId, email } = JSON.parse(event.body || '{}');

    switch (action) {
      case 'get_usage':
        return await getUserUsage(userId, headers);
      
      case 'increment_usage':
        return await incrementUsage(userId, headers);
      
      case 'reset_usage':
        return await resetUsage(userId, headers);
      
      case 'create_user':
        return await createUser(email, headers);
      
      default:
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Invalid action' })
        };
    }
  } catch (error) {
    console.error('User API Error:', error);
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

// Simple localStorage-based user management for demo
// In production, replace with proper database operations

async function getUserUsage(userId, headers) {
  // Initialize user if they don't exist
  if (!users[userId]) {
    users[userId] = {
      id: userId,
      monthlyUsage: 0,
      maxUsage: 5,
      subscriptionType: 'free',
      isSubscribed: false,
      createdAt: new Date().toISOString(),
      lastActive: new Date().toISOString()
    };
  }
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      user: users[userId]
    })
  };
}

async function incrementUsage(userId, headers) {
  // Initialize user if they don't exist
  if (!users[userId]) {
    users[userId] = {
      id: userId,
      monthlyUsage: 0,
      maxUsage: 5,
      subscriptionType: 'free',
      isSubscribed: false,
      createdAt: new Date().toISOString(),
      lastActive: new Date().toISOString()
    };
  }
  
  // Increment usage
  users[userId].monthlyUsage = (users[userId].monthlyUsage || 0) + 1;
  users[userId].lastActive = new Date().toISOString();
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      user: users[userId],
      message: 'Usage incremented successfully'
    })
  };
}

async function resetUsage(userId, headers) {
  // In production, this would reset usage count in database for new billing period
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      message: 'Usage reset successfully'
    })
  };
}

async function createUser(email, headers) {
  // In production, this would create a user record in your database
  
  const userId = generateUserId();
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      userId,
      email,
      subscriptionStatus: 'free',
      maxUsage: 5,
      monthlyUsage: 0,
      createdAt: new Date().toISOString()
    })
  };
}

function generateUserId() {
  return 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// Helper function to get current billing period
function getCurrentBillingPeriod() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

// Helper function to check if usage should be reset (new billing period)
function shouldResetUsage(lastResetPeriod) {
  return getCurrentBillingPeriod() !== lastResetPeriod;
}