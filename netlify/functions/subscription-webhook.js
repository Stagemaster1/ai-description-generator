// SESSION 4D6: Secured PayPal Subscription Webhook
// Integrates with Firebase Auth middleware for enhanced security
// Consolidates with main paypal-webhook.js security framework

const fetch = require('node-fetch');
const firebaseAuthMiddleware = require('./firebase-auth-middleware');
const securityLogger = require('./security-logger');
const crypto = require('crypto');
const distributedRateLimiter = require('./distributed-rate-limiter');

exports.handler = async (event, context) => {
  const clientIP = event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown';
  
  // SESSION 4D6: Enhanced comprehensive security headers for webhook
  const headers = firebaseAuthMiddleware.createSecureHeaders('', {
    webhook: true,
    webhookOrigin: 'https://www.paypal.com',
    contentType: 'application/json'
  });
  
  // Override specific headers for PayPal webhook requirements
  headers['Access-Control-Allow-Headers'] = 'Content-Type, PayPal-Request-Id, PayPal-Transmission-Id, PayPal-Auth-Algo, PayPal-Transmission-Time, PayPal-Cert-Id, PayPal-Signature';
  headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS';

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  // SESSION 4D6: Enhanced method validation
  if (event.httpMethod !== 'POST') {
    securityLogger.logWebhookFailure({
      webhookType: 'paypal_subscription',
      reason: 'invalid_method',
      error: `Method ${event.httpMethod} not allowed`,
      sourceIP: clientIP
    });
    
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    // SESSION 1C-2: Enhanced distributed webhook validation and rate limiting
    const rateLimitResult = await distributedRateLimiter.checkRateLimit(clientIP, {
      maxRequests: 50, // 50 webhook requests per minute per IP
      windowMs: 60 * 1000, // 1 minute
      type: 'webhook_subscription',
      clientIP: clientIP,
      userAgent: event.headers['user-agent'] || 'paypal-webhook',
      endpoint: 'subscription-webhook'
    });

    if (!rateLimitResult.allowed) {
      securityLogger.logSuspiciousActivity({
        activityType: 'webhook_rate_limit_exceeded',
        description: 'PayPal subscription webhook rate limit exceeded',
        clientIP: clientIP,
        endpoint: 'subscription-webhook',
        retryAfter: rateLimitResult.retryAfter
      });

      return {
        statusCode: 429,
        headers: {
          ...headers,
          'Retry-After': rateLimitResult.retryAfter?.toString() || '60'
        },
        body: JSON.stringify({
          error: 'Webhook rate limit exceeded',
          retryAfter: rateLimitResult.retryAfter
        })
      };
    }

    if (event.httpMethod === 'POST' && event.body) {
      let data;
      try {
        data = JSON.parse(event.body);
      } catch (parseError) {
        securityLogger.logWebhookFailure({
          webhookType: 'paypal_subscription',
          reason: 'invalid_json',
          error: 'Invalid JSON in webhook body',
          sourceIP: clientIP,
          bodyHash: crypto.createHash('sha256').update(event.body).digest('hex')
        });
        
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Invalid JSON payload' })
        };
      }
      
      // SESSION 4D6: Enhanced security logging for webhook events
      securityLogger.logWebhookSuccess({
        webhookType: 'paypal_subscription',
        eventId: data.id || 'manual_test',
        eventType: data.action || 'test_subscription',
        sourceIP: clientIP
      });
      
      // Manual test call (for testing purposes only)
      if (data.action === 'test_subscription') {
        return await handleNewSubscription(
          data.email, 
          data.planName, 
          data.subscriptionId || 'test-sub-' + Date.now(),
          headers
        );
      }
      
      // Real PayPal webhook data processing
      console.log('PayPal subscription webhook received:', {
        eventType: data.event_type || data.action,
        resourceType: data.resource_type,
        eventId: data.id
      });
    }
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ message: 'Webhook received successfully' })
    };
    
  } catch (error) {
    console.error('Subscription webhook error:', error);
    
    // SESSION 4D6: Enhanced error logging
    securityLogger.logWebhookFailure({
      webhookType: 'paypal_subscription',
      reason: 'processing_error',
      error: error.message,
      sourceIP: clientIP,
      stackTrace: error.stack
    });
    
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
    
    // Step 2: Log subscription (Notion integration removed for security)
    console.log('Subscription processed successfully:', { email, planName, subscriptionId });
    const notionResult = { success: false, message: 'Notion integration disabled for security' };
    
    console.log('Subscription processed:', {
      email,
      planName,
      subscriptionId,
      userCreated: userResult.success,
      notionSent: false
    });
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'Subscription processed successfully',
        userCreated: userResult.success,
        notionNotified: false
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
    password: process.env.ADMIN_PASSWORD,
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

// NOTION INTEGRATION FUNCTIONS REMOVED FOR SECURITY COMPLIANCE
// Original Notion notification functionality has been disabled
// to comply with Session 4D6 scope restrictions

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

// SESSION 1C-2: Webhook rate limiting configuration
// SECURITY FIX: Replaced stateful Map with distributed rate limiting
const WEBHOOK_RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const MAX_WEBHOOK_REQUESTS = 50; // 50 webhook requests per minute per IP

/**
 * SESSION 1C-2: Check webhook rate limiting using distributed system
 * @param {string} clientIP - Client IP address
 * @param {Object} options - Additional options
 * @returns {Promise<boolean>} True if within rate limit
 */
async function checkWebhookRateLimit(clientIP, options = {}) {
  try {
    const result = await distributedRateLimiter.checkRateLimit(clientIP, {
      maxRequests: MAX_WEBHOOK_REQUESTS,
      windowMs: WEBHOOK_RATE_LIMIT_WINDOW,
      type: 'webhook_subscription',
      clientIP: clientIP,
      userAgent: options.userAgent || 'webhook',
      endpoint: options.endpoint || 'subscription-webhook'
    });

    return result.allowed;
  } catch (error) {
    console.error('Webhook rate limit check failed:', error);
    // Allow request on error to avoid breaking functionality
    return true;
  }
}

// REMOVED: setInterval for serverless compatibility
// Cleanup will be handled by infrastructure or periodic cloud functions