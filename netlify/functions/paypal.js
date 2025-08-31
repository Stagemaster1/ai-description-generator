// PayPal payment processing
// PayPal REST API integration for subscriptions

const fetch = require('node-fetch');

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_BASE_URL = process.env.PAYPAL_MODE === process.env.PAYPAL_LIVE_VALUE 
  ? 'https://api.paypal.com' 
  : 'https://api.test.paypal.com';

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

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const { action, planName, email, orderID } = JSON.parse(event.body);

    switch (action) {
      case 'create_subscription':
        return await createSubscription(planName, email, headers);
      
      case 'capture_order':
        return await captureOrder(orderID, headers);
      
      case 'get_subscription_status':
        return await getSubscriptionStatus(email, headers);
      
      case 'get_plan_ids':
        return await getPlanIds(headers);
      
      default:
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Invalid action' })
        };
    }
  } catch (error) {
    console.error('PayPal API Error:', error);
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

async function getPayPalAccessToken() {
  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');
  
  const response = await fetch(`${PAYPAL_BASE_URL}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials'
  });

  const data = await response.json();
  return data.access_token;
}

async function createSubscription(planName, email, headers) {
  console.log('Creating subscription for plan:', planName, 'email:', email);
  
  const plans = {
    starter: {
      plan_id: process.env.PAYPAL_STARTER_PLAN_ID,
      amount: '19.99'
    },
    professional: {
      plan_id: process.env.PAYPAL_PROFESSIONAL_PLAN_ID,
      amount: '49.99'
    },
    enterprise: {
      plan_id: process.env.PAYPAL_ENTERPRISE_PLAN_ID,
      amount: '99.99'
    }
  };

  const plan = plans[planName];
  if (!plan) {
    console.error('Invalid plan name:', planName);
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid plan name' })
    };
  }

  console.log('Using plan ID:', plan.plan_id);

  const accessToken = await getPayPalAccessToken();

  const subscriptionData = {
    plan_id: plan.plan_id,
    subscriber: {
      email_address: email || 'test@example.com',
    },
    application_context: {
      brand_name: 'SolTecSol AI Description Generator',
      locale: 'en-US',
      shipping_preference: 'NO_SHIPPING',
      user_action: 'SUBSCRIBE_NOW',
      return_url: `${process.env.SITE_URL}/success`,
      cancel_url: `${process.env.SITE_URL}/cancel`
    }
  };

  const response = await fetch(`${PAYPAL_BASE_URL}/v1/billing/subscriptions`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Prefer': 'return=representation'
    },
    body: JSON.stringify(subscriptionData)
  });

  const subscription = await response.json();
  console.log('PayPal API Response:', {
    status: response.status,
    statusText: response.statusText,
    data: subscription
  });

  if (response.ok) {
    // Find the approval URL
    const approvalUrl = subscription.links.find(link => link.rel === 'approve')?.href;
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        subscription_id: subscription.id,
        approval_url: approvalUrl,
        status: subscription.status
      })
    };
  } else {
    console.error('PayPal subscription creation failed:', subscription);
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: subscription.message || 'Failed to create subscription' })
    };
  }
}

async function captureOrder(orderID, headers) {
  const accessToken = await getPayPalAccessToken();

  const response = await fetch(`${PAYPAL_BASE_URL}/v2/checkout/orders/${orderID}/capture`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    }
  });

  const captureData = await response.json();

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify(captureData)
  };
}

async function getSubscriptionStatus(email, headers) {
  // In a real implementation, you would query your database for the user's subscription
  // For now, return a basic response
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      status: 'active',
      plan: 'free',
      usage_limit: 5
    })
  };
}

async function getPlanIds(headers) {
  console.log('Plan IDs request - Environment variables:', {
    starter: process.env.PAYPAL_STARTER_PLAN_ID,
    professional: process.env.PAYPAL_PROFESSIONAL_PLAN_ID,
    enterprise: process.env.PAYPAL_ENTERPRISE_PLAN_ID
  });
  
  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      starter: process.env.PAYPAL_STARTER_PLAN_ID,
      professional: process.env.PAYPAL_PROFESSIONAL_PLAN_ID,
      enterprise: process.env.PAYPAL_ENTERPRISE_PLAN_ID
    })
  };
}
