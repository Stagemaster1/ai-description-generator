// PayPal subscription webhook + Notion notification
// Handles new subscriptions: auto-create user + notify via Notion

const fetch = require('node-fetch');

exports.handler = async (event, context) => {
  // Enable CORS
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
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
    // For testing - accept manual calls
    if (event.httpMethod === 'POST' && event.body) {
      const data = JSON.parse(event.body);
      
      // Manual test call
      if (data.action === 'test_subscription') {
        return await handleNewSubscription(
          data.email, 
          data.planName, 
          data.subscriptionId || 'test-sub-' + Date.now(),
          headers
        );
      }
      
      // TODO: Real PayPal webhook data parsing will go here
      // For now, just log webhook data
      console.log('PayPal webhook received:', data);
    }
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ message: 'Webhook received' })
    };
    
  } catch (error) {
    console.error('Subscription webhook error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Webhook processing failed' })
    };
  }
};

async function handleNewSubscription(email, planName, subscriptionId, headers) {
  try {
    // Step 1: Auto-create user in admin system
    const userResult = await createUserInAdminSystem(email, planName, subscriptionId);
    
    // Step 2: Send notification to Notion (if configured)
    console.log('Attempting to send Notion notification...');
    const notionResult = await sendNotionNotification(email, planName, subscriptionId);
    console.log('Notion result:', notionResult);
    
    console.log('Subscription processed:', {
      email,
      planName,
      subscriptionId,
      userCreated: userResult.success,
      notionSent: notionResult.success
    });
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'Subscription processed successfully',
        userCreated: userResult.success,
        notionNotified: notionResult.success
      })
    };
    
  } catch (error) {
    console.error('Failed to handle subscription:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: error.message })
    };
  }
}

async function createUserInAdminSystem(email, planName, subscriptionId) {
  // Call the admin API to create user automatically
  const adminData = {
    action: 'manual_add_user',
    password: process.env.ADMIN_PASSWORD || 'set_in_netlify_env',
    userData: {
      email: email.toLowerCase().trim(),
      subscriptionType: planName,
      subscriptionId: subscriptionId,
      isSubscribed: true,
      maxUsage: getPlanUsageLimit(planName),
      monthlyUsage: 0,
      autoCreated: true,
      createdViaWebhook: true
    }
  };
  
  try {
    // Call our own admin endpoint to create the user
    const response = await fetch(`${process.env.URL}/.netlify/functions/admin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(adminData)
    });
    
    const result = await response.json();
    return { success: response.ok, data: result };
    
  } catch (error) {
    console.error('Failed to create user in admin system:', error);
    return { success: false, error: error.message };
  }
}

async function sendNotionNotification(email, planName, subscriptionId) {
  const notionToken = process.env.NOTION_TOKEN;
  
  console.log('Notion token exists:', !!notionToken);
  
  if (!notionToken) {
    console.log('No Notion token configured - skipping Notion notification');
    return { success: false, error: 'No Notion token' };
  }
  
  try {
    // Get or create the subscribers database
    const databaseId = await getOrCreateSubscribersDatabase();
    
    // Add new subscriber to database
    const pageData = {
      parent: { database_id: databaseId },
      properties: {
        'Email': {
          title: [{ text: { content: email } }]
        },
        'Plan': {
          select: { name: planName }
        },
        'Amount': {
          rich_text: [{ text: { content: getPlanAmount(planName) } }]
        },
        'Subscription ID': {
          rich_text: [{ text: { content: subscriptionId } }]
        },
        'Date': {
          date: { start: new Date().toISOString().split('T')[0] }
        },
        'Status': {
          select: { name: 'Active' }
        },
        'Source': {
          rich_text: [{ text: { content: 'PayPal Webhook' } }]
        }
      }
    };
    
    const response = await fetch('https://api.notion.com/v1/pages', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${notionToken}`,
        'Content-Type': 'application/json',
        'Notion-Version': '2022-06-28'
      },
      body: JSON.stringify(pageData)
    });
    
    const result = await response.json();
    
    if (response.ok) {
      console.log('Subscriber added to Notion:', { email, planName });
      return { success: true, data: result };
    } else {
      console.error('Notion API error:', result);
      return { success: false, error: result.message };
    }
    
  } catch (error) {
    console.error('Notion notification failed:', error);
    return { success: false, error: error.message };
  }
}

async function getOrCreateSubscribersDatabase() {
  // Use the manually created database ID
  return '25d0eb38e797809e90d2cdd8c9e10bec';
}

function getPlanUsageLimit(planName) {
  const limits = {
    'starter': 50,
    'professional': 200,
    'enterprise': 999999
  };
  return limits[planName] || 50;
}

function getPlanAmount(planName) {
  const amounts = {
    'starter': '$19.99',
    'professional': '$49.99',
    'enterprise': '$99.99'
  };
  return amounts[planName] || 'unknown';
}