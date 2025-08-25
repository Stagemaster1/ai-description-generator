// PayPal payment processing - Stripe kept for future use but disabled
// const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

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
    const { action, planName, email, customerId } = JSON.parse(event.body);

    switch (action) {
      case 'create_paypal_order':
        return await createPayPalOrder(planName, email, headers);
      
      case 'capture_paypal_order':
        return await capturePayPalOrder(event.body, headers);
      
      case 'get_subscription_status':
        return await getSubscriptionStatus(customerId, headers);
      
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

async function createCheckoutSession(planName, email, headers) {
  const plans = {
    starter: {
      price: process.env.STRIPE_STARTER_PRICE_ID,
      trial_days: 30
    },
    professional: {
      price: process.env.STRIPE_PROFESSIONAL_PRICE_ID,
      trial_days: 0
    },
    enterprise: {
      price: process.env.STRIPE_ENTERPRISE_PRICE_ID,
      trial_days: 0
    }
  };

  const plan = plans[planName];
  if (!plan) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid plan name' })
    };
  }

  const sessionConfig = {
    payment_method_types: ['card'],
    line_items: [{
      price: plan.price,
      quantity: 1,
    }],
    mode: 'subscription',
    success_url: `${process.env.SITE_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.SITE_URL}/`,
    customer_email: email,
    metadata: {
      plan_name: planName
    }
  };

  // Add trial period for starter plan
  if (plan.trial_days > 0) {
    sessionConfig.subscription_data = {
      trial_period_days: plan.trial_days
    };
  }

  const session = await stripe.checkout.sessions.create(sessionConfig);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ 
      checkout_url: session.url,
      session_id: session.id
    })
  };
}

async function createPortalSession(customerId, headers) {
  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: process.env.SITE_URL,
  });

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ portal_url: session.url })
  };
}

async function getSubscriptionStatus(customerId, headers) {
  const customer = await stripe.customers.retrieve(customerId, {
    expand: ['subscriptions']
  });

  const subscription = customer.subscriptions.data[0];
  
  if (!subscription) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        status: 'none',
        plan: 'free',
        usage_limit: 5
      })
    };
  }

  // Map Stripe subscription to our plan structure
  const planMapping = {
    [process.env.STRIPE_STARTER_PRICE_ID]: { name: 'starter', limit: 50 },
    [process.env.STRIPE_PROFESSIONAL_PRICE_ID]: { name: 'professional', limit: 200 },
    [process.env.STRIPE_ENTERPRISE_PRICE_ID]: { name: 'enterprise', limit: 999999 }
  };

  const priceId = subscription.items.data[0].price.id;
  const plan = planMapping[priceId] || { name: 'free', limit: 5 };

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      status: subscription.status,
      plan: plan.name,
      usage_limit: plan.limit,
      current_period_end: subscription.current_period_end,
      cancel_at_period_end: subscription.cancel_at_period_end
    })
  };
}