const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

exports.handler = async (event, context) => {
  // Verify webhook signature
  const sig = event.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  let stripeEvent;

  try {
    stripeEvent = stripe.webhooks.constructEvent(event.body, sig, endpointSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Webhook signature verification failed' })
    };
  }

  // Handle the event
  try {
    switch (stripeEvent.type) {
      case 'checkout.session.completed':
        await handleCheckoutCompleted(stripeEvent.data.object);
        break;
        
      case 'customer.subscription.created':
        await handleSubscriptionCreated(stripeEvent.data.object);
        break;
        
      case 'customer.subscription.updated':
        await handleSubscriptionUpdated(stripeEvent.data.object);
        break;
        
      case 'customer.subscription.deleted':
        await handleSubscriptionDeleted(stripeEvent.data.object);
        break;
        
      case 'invoice.payment_succeeded':
        await handlePaymentSucceeded(stripeEvent.data.object);
        break;
        
      case 'invoice.payment_failed':
        await handlePaymentFailed(stripeEvent.data.object);
        break;
        
      default:
        console.log(`Unhandled event type: ${stripeEvent.type}`);
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ received: true })
    };
    
  } catch (error) {
    console.error('Webhook handler error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Webhook handler failed' })
    };
  }
};

async function handleCheckoutCompleted(session) {
  console.log('Checkout completed:', session.id);
  
  // In a production app, you would:
  // 1. Save the customer data to your database
  // 2. Create or update user subscription status
  // 3. Send welcome email
  // 4. Set up any additional services
  
  // For this demo, we'll just log the event
  const customer = await stripe.customers.retrieve(session.customer);
  console.log('New customer:', customer.email);
}

async function handleSubscriptionCreated(subscription) {
  console.log('Subscription created:', subscription.id);
  
  // Get the price ID to determine the plan
  const priceId = subscription.items.data[0].price.id;
  const planMapping = {
    [process.env.STRIPE_STARTER_PRICE_ID]: { name: 'starter', limit: 50 },
    [process.env.STRIPE_PROFESSIONAL_PRICE_ID]: { name: 'professional', limit: 200 },
    [process.env.STRIPE_ENTERPRISE_PRICE_ID]: { name: 'enterprise', limit: 999999 }
  };
  
  const plan = planMapping[priceId];
  if (plan) {
    console.log(`User subscribed to ${plan.name} plan with ${plan.limit} descriptions/month`);
    // Update user's plan in your database
  }
}

async function handleSubscriptionUpdated(subscription) {
  console.log('Subscription updated:', subscription.id);
  
  // Handle plan upgrades/downgrades
  const priceId = subscription.items.data[0].price.id;
  const planMapping = {
    [process.env.STRIPE_STARTER_PRICE_ID]: { name: 'starter', limit: 50 },
    [process.env.STRIPE_PROFESSIONAL_PRICE_ID]: { name: 'professional', limit: 200 },
    [process.env.STRIPE_ENTERPRISE_PRICE_ID]: { name: 'enterprise', limit: 999999 }
  };
  
  const plan = planMapping[priceId];
  if (plan) {
    console.log(`User plan updated to ${plan.name}`);
    // Update user's plan in your database
  }
}

async function handleSubscriptionDeleted(subscription) {
  console.log('Subscription cancelled:', subscription.id);
  
  // Revert user to free plan
  console.log('User reverted to free plan');
  // Update user's plan in your database to 'free' with 5 descriptions/month
}

async function handlePaymentSucceeded(invoice) {
  console.log('Payment succeeded:', invoice.id);
  
  // Reset usage count for the new billing period
  console.log('Usage count reset for new billing period');
  // Reset user's monthly usage count in your database
}

async function handlePaymentFailed(invoice) {
  console.log('Payment failed:', invoice.id);
  
  // Handle failed payment
  // You might want to:
  // 1. Send email notification to customer
  // 2. Temporarily suspend service
  // 3. Retry payment after a few days
  
  const customer = await stripe.customers.retrieve(invoice.customer);
  console.log('Payment failed for customer:', customer.email);
}