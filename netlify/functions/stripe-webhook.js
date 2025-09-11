// Stripe Webhook Handler with Firebase Auth Middleware and Security
// SESSION 4D2 Implementation - Revenue Protection

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { getFirestore } = require('../../firebase-config');
const firebaseAuthMiddleware = require('./firebase-auth-middleware');
const securityLogger = require('./security-logger');

// Webhook validation and rate limiting
const webhookRequestMap = new Map();
const WEBHOOK_RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const MAX_WEBHOOK_REQUESTS = 100; // 100 webhooks per minute

exports.handler = async (event, context) => {
  const startTime = Date.now();
  const sourceIP = event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown';
  
  try {
    // SECURITY: Webhook rate limiting
    if (!checkWebhookRateLimit(sourceIP)) {
      securityLogger.logSuspiciousActivity({
        activityType: 'webhook_rate_limit_exceeded',
        description: 'Stripe webhook rate limit exceeded',
        clientIP: sourceIP,
        endpoint: 'stripe-webhook'
      });
      
      return {
        statusCode: 429,
        headers: firebaseAuthMiddleware.createSecureHeaders('', { webhook: true, contentType: 'application/json' }),
        body: JSON.stringify({ error: 'Webhook rate limit exceeded' })
      };
    }

    // SECURITY: Validate request method
    if (event.httpMethod !== 'POST') {
      securityLogger.logWebhookFailure({
        webhookType: 'stripe',
        reason: 'invalid_method',
        error: `Method ${event.httpMethod} not allowed`,
        sourceIP: sourceIP
      });
      
      return {
        statusCode: 405,
        headers: firebaseAuthMiddleware.createSecureHeaders('', { webhook: true, contentType: 'application/json' }),
        body: JSON.stringify({ error: 'Method not allowed' })
      };
    }

    // SECURITY: Validate required headers
    const sig = event.headers['stripe-signature'];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
    
    if (!sig) {
      securityLogger.logWebhookFailure({
        webhookType: 'stripe',
        reason: 'missing_signature',
        error: 'Stripe signature header missing',
        sourceIP: sourceIP
      });
      
      return {
        statusCode: 400,
        headers: firebaseAuthMiddleware.createSecureHeaders('', { webhook: true, contentType: 'application/json' }),
        body: JSON.stringify({ error: 'Webhook signature missing' })
      };
    }

    if (!endpointSecret) {
      securityLogger.logConfigIssue({
        component: 'stripe-webhook',
        issue: 'Missing STRIPE_WEBHOOK_SECRET environment variable',
        severity: 'CRITICAL',
        recommendation: 'Configure STRIPE_WEBHOOK_SECRET in environment variables'
      });
      
      return {
        statusCode: 500,
        headers: firebaseAuthMiddleware.createSecureHeaders('', { webhook: true, contentType: 'application/json' }),
        body: JSON.stringify({ error: 'Webhook configuration error' })
      };
    }

    // SECURITY: Verify webhook signature to prevent forged payments
    let stripeEvent;
    try {
      stripeEvent = stripe.webhooks.constructEvent(event.body, sig, endpointSecret);
      
      // Log successful webhook verification
      securityLogger.logWebhookSuccess({
        webhookType: 'stripe',
        eventId: stripeEvent.id,
        eventType: stripeEvent.type,
        sourceIP: sourceIP
      });
      
    } catch (err) {
      securityLogger.logWebhookFailure({
        webhookType: 'stripe',
        reason: 'signature_verification_failed',
        error: err.message,
        sourceIP: sourceIP,
        headers: {
          'stripe-signature': sig ? 'present' : 'missing',
          'content-type': event.headers['content-type']
        }
      });
      
      console.error('Webhook signature verification failed:', err.message);
      return {
        statusCode: 400,
        headers: firebaseAuthMiddleware.createSecureHeaders('', { webhook: true, contentType: 'application/json' }),
        body: JSON.stringify({ error: 'Webhook signature verification failed' })
      };
    }

    // SECURITY: Additional event validation
    if (!stripeEvent.id || !stripeEvent.type || !stripeEvent.data) {
      securityLogger.logWebhookFailure({
        webhookType: 'stripe',
        reason: 'invalid_event_structure',
        error: 'Event missing required fields',
        sourceIP: sourceIP
      });
      
      return {
        statusCode: 400,
        headers: firebaseAuthMiddleware.createSecureHeaders('', { webhook: true, contentType: 'application/json' }),
        body: JSON.stringify({ error: 'Invalid event structure' })
      };
    }

    // Handle the event with comprehensive error handling
    try {
      let handlerResult;
      
      switch (stripeEvent.type) {
        case 'checkout.session.completed':
          handlerResult = await handleCheckoutCompleted(stripeEvent.data.object, stripeEvent.id);
          break;
          
        case 'customer.subscription.created':
          handlerResult = await handleSubscriptionCreated(stripeEvent.data.object, stripeEvent.id);
          break;
          
        case 'customer.subscription.updated':
          handlerResult = await handleSubscriptionUpdated(stripeEvent.data.object, stripeEvent.id);
          break;
          
        case 'customer.subscription.deleted':
          handlerResult = await handleSubscriptionDeleted(stripeEvent.data.object, stripeEvent.id);
          break;
          
        case 'invoice.payment_succeeded':
          handlerResult = await handlePaymentSucceeded(stripeEvent.data.object, stripeEvent.id);
          break;
          
        case 'invoice.payment_failed':
          handlerResult = await handlePaymentFailed(stripeEvent.data.object, stripeEvent.id);
          break;
          
        default:
          console.log(`Unhandled event type: ${stripeEvent.type}`);
          handlerResult = { success: true, message: 'Event type not handled' };
      }

      // Log successful webhook processing
      securityLogger.logOperationSuccess({
        operation: 'stripe_webhook_processing',
        endpoint: 'stripe-webhook',
        duration: Date.now() - startTime,
        resourcesAccessed: [`stripe_event_${stripeEvent.type}`]
      });

      return {
        statusCode: 200,
        headers: firebaseAuthMiddleware.createSecureHeaders('', { webhook: true, contentType: 'application/json' }),
        body: JSON.stringify({ 
          received: true,
          eventId: stripeEvent.id,
          eventType: stripeEvent.type,
          processed: handlerResult?.success || true
        })
      };
      
    } catch (error) {
      // Log webhook processing failure
      securityLogger.logOperationFailure({
        operation: 'stripe_webhook_processing',
        endpoint: 'stripe-webhook',
        error: error.message,
        duration: Date.now() - startTime,
        stackTrace: error.stack
      });
      
      console.error('Webhook handler error:', error);
      return {
        statusCode: 500,
        headers: firebaseAuthMiddleware.createSecureHeaders('', { webhook: true, contentType: 'application/json' }),
        body: JSON.stringify({ 
          error: 'Webhook handler failed',
          eventId: stripeEvent.id,
          eventType: stripeEvent.type
        })
      };
    }
    
  } catch (outerError) {
    // Log outer error (validation/security issues)
    securityLogger.logOperationFailure({
      operation: 'stripe_webhook_validation',
      endpoint: 'stripe-webhook',
      error: outerError.message,
      duration: Date.now() - startTime,
      stackTrace: outerError.stack
    });
    
    console.error('Webhook validation error:', outerError);
    return {
      statusCode: 500,
      headers: firebaseAuthMiddleware.createSecureHeaders('', { webhook: true, contentType: 'application/json' }),
      body: JSON.stringify({ error: 'Webhook processing failed' })
    };
  }
};

/**
 * Check webhook rate limiting
 * @param {string} sourceIP - Source IP address
 * @returns {boolean} True if within rate limit
 */
function checkWebhookRateLimit(sourceIP) {
  try {
    const now = Date.now();
    const requests = webhookRequestMap.get(sourceIP) || [];
    
    // Remove old requests
    const validRequests = requests.filter(timestamp => now - timestamp < WEBHOOK_RATE_LIMIT_WINDOW);
    
    // Check rate limit
    if (validRequests.length >= MAX_WEBHOOK_REQUESTS) {
      return false;
    }
    
    // Add current request
    validRequests.push(now);
    webhookRequestMap.set(sourceIP, validRequests);
    
    return true;
  } catch (error) {
    console.error('Webhook rate limit check failed:', error);
    return true; // Fail open to avoid blocking legitimate webhooks
  }
}

async function handleCheckoutCompleted(session, eventId) {
  try {
    console.log('Checkout completed:', session.id);
    
    // SECURITY: Validate session object
    if (!session.id || !session.customer) {
      throw new Error('Invalid checkout session data');
    }
    
    // Get customer information with error handling
    const customer = await stripe.customers.retrieve(session.customer);
    if (!customer || !customer.email) {
      throw new Error('Invalid customer data from Stripe');
    }
    
    console.log('New customer:', customer.email);
    
    // SECURITY: Store checkout completion securely in Firestore
    const db = getFirestore();
    const checkoutData = {
      sessionId: session.id,
      customerId: session.customer,
      customerEmail: customer.email,
      amountTotal: session.amount_total,
      currency: session.currency,
      paymentStatus: session.payment_status,
      eventId: eventId,
      processedAt: new Date().toISOString(),
      subscriptionId: session.subscription || null
    };
    
    // Store in secure collection with validation
    await db.collection('stripe_checkouts')
      .doc(session.id)
      .set(checkoutData);
    
    // Log successful checkout processing
    securityLogger.logOperationSuccess({
      operation: 'stripe_checkout_completed',
      userId: customer.email,
      endpoint: 'stripe-webhook',
      resourcesAccessed: ['stripe_checkouts', 'stripe_customers']
    });
    
    return { success: true, customerId: customer.id, email: customer.email };
    
  } catch (error) {
    securityLogger.logOperationFailure({
      operation: 'stripe_checkout_completed',
      endpoint: 'stripe-webhook',
      error: error.message,
      stackTrace: error.stack
    });
    
    console.error('Checkout completion handler error:', error);
    throw error;
  }
}

async function handleSubscriptionCreated(subscription, eventId) {
  try {
    console.log('Subscription created:', subscription.id);
    
    // SECURITY: Validate subscription object
    if (!subscription.id || !subscription.customer || !subscription.items?.data?.length) {
      throw new Error('Invalid subscription data');
    }
    
    // Get the price ID to determine the plan with validation
    const priceId = subscription.items.data[0]?.price?.id;
    if (!priceId) {
      throw new Error('Missing price ID in subscription');
    }
    
    const planMapping = {
      [process.env.STRIPE_STARTER_PRICE_ID]: { name: 'starter', limit: 50 },
      [process.env.STRIPE_PROFESSIONAL_PRICE_ID]: { name: 'professional', limit: 200 },
      [process.env.STRIPE_ENTERPRISE_PRICE_ID]: { name: 'enterprise', limit: 999999 }
    };
    
    const plan = planMapping[priceId];
    if (!plan) {
      console.warn(`Unknown price ID: ${priceId}`);
      return { success: true, message: 'Unknown plan, skipped processing' };
    }
    
    console.log(`User subscribed to ${plan.name} plan with ${plan.limit} descriptions/month`);
    
    // SECURITY: Store subscription securely in Firestore
    const db = getFirestore();
    const subscriptionData = {
      subscriptionId: subscription.id,
      customerId: subscription.customer,
      priceId: priceId,
      planName: plan.name,
      usageLimit: plan.limit,
      status: subscription.status,
      currentPeriodStart: new Date(subscription.current_period_start * 1000).toISOString(),
      currentPeriodEnd: new Date(subscription.current_period_end * 1000).toISOString(),
      eventId: eventId,
      createdAt: new Date().toISOString()
    };
    
    // Store subscription data
    await db.collection('stripe_subscriptions')
      .doc(subscription.id)
      .set(subscriptionData);
    
    // Update user's plan in users collection if customer has email
    try {
      const customer = await stripe.customers.retrieve(subscription.customer);
      if (customer?.email) {
        // Find user by email and update subscription
        const userQuery = await db.collection('users')
          .where('email', '==', customer.email)
          .limit(1)
          .get();
        
        if (!userQuery.empty) {
          const userDoc = userQuery.docs[0];
          await userDoc.ref.update({
            subscriptionType: plan.name,
            maxUsage: plan.limit,
            isSubscribed: true,
            subscriptionStatus: subscription.status,
            stripeCustomerId: subscription.customer,
            stripeSubscriptionId: subscription.id,
            lastUpdated: new Date().toISOString()
          });
        }
      }
    } catch (userUpdateError) {
      console.warn('Could not update user subscription data:', userUpdateError.message);
    }
    
    // Log successful subscription creation
    securityLogger.logOperationSuccess({
      operation: 'stripe_subscription_created',
      endpoint: 'stripe-webhook',
      resourcesAccessed: ['stripe_subscriptions', 'users']
    });
    
    return { success: true, plan: plan.name, limit: plan.limit };
    
  } catch (error) {
    securityLogger.logOperationFailure({
      operation: 'stripe_subscription_created',
      endpoint: 'stripe-webhook',
      error: error.message,
      stackTrace: error.stack
    });
    
    console.error('Subscription creation handler error:', error);
    throw error;
  }
}

async function handleSubscriptionUpdated(subscription, eventId) {
  try {
    console.log('Subscription updated:', subscription.id);
    
    // SECURITY: Validate subscription object
    if (!subscription.id || !subscription.customer || !subscription.items?.data?.length) {
      throw new Error('Invalid subscription data');
    }
    
    // Handle plan upgrades/downgrades with validation
    const priceId = subscription.items.data[0]?.price?.id;
    if (!priceId) {
      throw new Error('Missing price ID in updated subscription');
    }
    
    const planMapping = {
      [process.env.STRIPE_STARTER_PRICE_ID]: { name: 'starter', limit: 50 },
      [process.env.STRIPE_PROFESSIONAL_PRICE_ID]: { name: 'professional', limit: 200 },
      [process.env.STRIPE_ENTERPRISE_PRICE_ID]: { name: 'enterprise', limit: 999999 }
    };
    
    const plan = planMapping[priceId];
    if (!plan) {
      console.warn(`Unknown price ID in update: ${priceId}`);
      return { success: true, message: 'Unknown plan, skipped update' };
    }
    
    console.log(`User plan updated to ${plan.name}`);
    
    // SECURITY: Update subscription data in Firestore
    const db = getFirestore();
    const updateData = {
      priceId: priceId,
      planName: plan.name,
      usageLimit: plan.limit,
      status: subscription.status,
      currentPeriodStart: new Date(subscription.current_period_start * 1000).toISOString(),
      currentPeriodEnd: new Date(subscription.current_period_end * 1000).toISOString(),
      eventId: eventId,
      updatedAt: new Date().toISOString()
    };
    
    // Update subscription record
    await db.collection('stripe_subscriptions')
      .doc(subscription.id)
      .update(updateData);
    
    // Update user's plan in users collection
    try {
      const customer = await stripe.customers.retrieve(subscription.customer);
      if (customer?.email) {
        const userQuery = await db.collection('users')
          .where('email', '==', customer.email)
          .limit(1)
          .get();
        
        if (!userQuery.empty) {
          const userDoc = userQuery.docs[0];
          await userDoc.ref.update({
            subscriptionType: plan.name,
            maxUsage: plan.limit,
            subscriptionStatus: subscription.status,
            lastUpdated: new Date().toISOString(),
            // Reset monthly usage on plan change if it's a new billing period
            ...(subscription.status === 'active' && { isSubscribed: true })
          });
        }
      }
    } catch (userUpdateError) {
      console.warn('Could not update user subscription data:', userUpdateError.message);
    }
    
    // Log successful subscription update
    securityLogger.logOperationSuccess({
      operation: 'stripe_subscription_updated',
      endpoint: 'stripe-webhook',
      resourcesAccessed: ['stripe_subscriptions', 'users']
    });
    
    return { success: true, plan: plan.name, status: subscription.status };
    
  } catch (error) {
    securityLogger.logOperationFailure({
      operation: 'stripe_subscription_updated',
      endpoint: 'stripe-webhook',
      error: error.message,
      stackTrace: error.stack
    });
    
    console.error('Subscription update handler error:', error);
    throw error;
  }
}

async function handleSubscriptionDeleted(subscription, eventId) {
  try {
    console.log('Subscription cancelled:', subscription.id);
    
    // SECURITY: Validate subscription object
    if (!subscription.id || !subscription.customer) {
      throw new Error('Invalid subscription cancellation data');
    }
    
    console.log('User reverted to free plan');
    
    // SECURITY: Update subscription status in Firestore
    const db = getFirestore();
    const cancellationData = {
      status: 'cancelled',
      cancelledAt: new Date().toISOString(),
      eventId: eventId
    };
    
    // Update subscription record
    await db.collection('stripe_subscriptions')
      .doc(subscription.id)
      .update(cancellationData);
    
    // Revert user to free plan with validation
    try {
      const customer = await stripe.customers.retrieve(subscription.customer);
      if (customer?.email) {
        const userQuery = await db.collection('users')
          .where('email', '==', customer.email)
          .limit(1)
          .get();
        
        if (!userQuery.empty) {
          const userDoc = userQuery.docs[0];
          await userDoc.ref.update({
            subscriptionType: 'free',
            maxUsage: 5,
            isSubscribed: false,
            subscriptionStatus: 'cancelled',
            cancelledAt: new Date().toISOString(),
            lastUpdated: new Date().toISOString()
          });
        }
      }
    } catch (userUpdateError) {
      console.warn('Could not update user to free plan:', userUpdateError.message);
    }
    
    // Log successful subscription cancellation
    securityLogger.logOperationSuccess({
      operation: 'stripe_subscription_cancelled',
      endpoint: 'stripe-webhook',
      resourcesAccessed: ['stripe_subscriptions', 'users']
    });
    
    return { success: true, status: 'cancelled', revertedToFree: true };
    
  } catch (error) {
    securityLogger.logOperationFailure({
      operation: 'stripe_subscription_cancelled',
      endpoint: 'stripe-webhook',
      error: error.message,
      stackTrace: error.stack
    });
    
    console.error('Subscription cancellation handler error:', error);
    throw error;
  }
}

async function handlePaymentSucceeded(invoice, eventId) {
  try {
    console.log('Payment succeeded:', invoice.id);
    
    // SECURITY: Validate invoice object
    if (!invoice.id || !invoice.customer) {
      throw new Error('Invalid payment success data');
    }
    
    console.log('Usage count reset for new billing period');
    
    // SECURITY: Store payment success in Firestore
    const db = getFirestore();
    const paymentData = {
      invoiceId: invoice.id,
      customerId: invoice.customer,
      subscriptionId: invoice.subscription,
      amountPaid: invoice.amount_paid,
      currency: invoice.currency,
      status: invoice.status,
      periodStart: new Date(invoice.period_start * 1000).toISOString(),
      periodEnd: new Date(invoice.period_end * 1000).toISOString(),
      eventId: eventId,
      processedAt: new Date().toISOString()
    };
    
    // Store payment record
    await db.collection('stripe_payments')
      .doc(invoice.id)
      .set(paymentData);
    
    // Reset user's monthly usage count for new billing period
    try {
      const customer = await stripe.customers.retrieve(invoice.customer);
      if (customer?.email) {
        const userQuery = await db.collection('users')
          .where('email', '==', customer.email)
          .limit(1)
          .get();
        
        if (!userQuery.empty) {
          const userDoc = userQuery.docs[0];
          const currentMonth = getCurrentBillingPeriod();
          
          await userDoc.ref.update({
            monthlyUsage: 0, // Reset usage for new billing period
            lastResetPeriod: currentMonth,
            lastPayment: new Date().toISOString(),
            paymentStatus: 'succeeded',
            lastUpdated: new Date().toISOString()
          });
        }
      }
    } catch (userUpdateError) {
      console.warn('Could not reset user usage count:', userUpdateError.message);
    }
    
    // Log successful payment processing
    securityLogger.logOperationSuccess({
      operation: 'stripe_payment_succeeded',
      endpoint: 'stripe-webhook',
      resourcesAccessed: ['stripe_payments', 'users']
    });
    
    return { success: true, invoiceId: invoice.id, usageReset: true };
    
  } catch (error) {
    securityLogger.logOperationFailure({
      operation: 'stripe_payment_succeeded',
      endpoint: 'stripe-webhook',
      error: error.message,
      stackTrace: error.stack
    });
    
    console.error('Payment success handler error:', error);
    throw error;
  }
}

async function handlePaymentFailed(invoice, eventId) {
  try {
    console.log('Payment failed:', invoice.id);
    
    // SECURITY: Validate invoice object
    if (!invoice.id || !invoice.customer) {
      throw new Error('Invalid payment failure data');
    }
    
    const customer = await stripe.customers.retrieve(invoice.customer);
    console.log('Payment failed for customer:', customer.email);
    
    // SECURITY: Store payment failure in Firestore
    const db = getFirestore();
    const failureData = {
      invoiceId: invoice.id,
      customerId: invoice.customer,
      customerEmail: customer?.email || 'unknown',
      subscriptionId: invoice.subscription,
      amountDue: invoice.amount_due,
      currency: invoice.currency,
      status: invoice.status,
      attemptCount: invoice.attempt_count,
      nextPaymentAttempt: invoice.next_payment_attempt ? new Date(invoice.next_payment_attempt * 1000).toISOString() : null,
      eventId: eventId,
      failedAt: new Date().toISOString()
    };
    
    // Store payment failure record
    await db.collection('stripe_payment_failures')
      .doc(invoice.id)
      .set(failureData);
    
    // Update user's payment status
    if (customer?.email) {
      try {
        const userQuery = await db.collection('users')
          .where('email', '==', customer.email)
          .limit(1)
          .get();
        
        if (!userQuery.empty) {
          const userDoc = userQuery.docs[0];
          await userDoc.ref.update({
            paymentStatus: 'failed',
            lastPaymentFailure: new Date().toISOString(),
            paymentAttemptCount: invoice.attempt_count,
            lastUpdated: new Date().toISOString()
          });
        }
      } catch (userUpdateError) {
        console.warn('Could not update user payment status:', userUpdateError.message);
      }
    }
    
    // Log payment failure for monitoring
    securityLogger.logOperationFailure({
      operation: 'stripe_payment_failed',
      userId: customer?.email || 'unknown',
      endpoint: 'stripe-webhook',
      error: `Payment failed for invoice ${invoice.id}`,
      stackTrace: null
    });
    
    return { success: true, invoiceId: invoice.id, customerEmail: customer?.email };
    
  } catch (error) {
    securityLogger.logOperationFailure({
      operation: 'stripe_payment_failed_handler',
      endpoint: 'stripe-webhook',
      error: error.message,
      stackTrace: error.stack
    });
    
    console.error('Payment failure handler error:', error);
    throw error;
  }
}

/**
 * Get current billing period for subscription management
 * @returns {string} Current billing period (YYYY-MM format)
 */
function getCurrentBillingPeriod() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

// Clean up old webhook request records periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, requests] of webhookRequestMap.entries()) {
    const validRequests = requests.filter(timestamp => now - timestamp < WEBHOOK_RATE_LIMIT_WINDOW);
    if (validRequests.length === 0) {
      webhookRequestMap.delete(ip);
    } else {
      webhookRequestMap.set(ip, validRequests);
    }
  }
}, 5 * 60 * 1000); // Clean every 5 minutes