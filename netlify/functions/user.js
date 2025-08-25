// Simple user management using Netlify Identity
// In a production environment, consider using a database like Supabase or Firebase

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
  // For demo purposes, we'll use a simple key-value approach
  // In production, this would query a database
  
  // Since we can't access localStorage from serverless function,
  // we'll return a default response and let the frontend handle usage tracking
  // In a real implementation, this would query your database
  
  const currentDate = new Date();
  const currentMonth = `${currentDate.getFullYear()}-${currentDate.getMonth()}`;
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      userId,
      monthlyUsage: 0, // Would come from database
      maxUsage: 5, // Would come from subscription status
      currentPeriod: currentMonth,
      subscriptionStatus: 'free'
    })
  };
}

async function incrementUsage(userId, headers) {
  // In production, this would update the database
  // For now, return success and let frontend handle the increment
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
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