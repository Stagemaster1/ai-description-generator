// Netlify serverless function to upgrade user from trial to subscription
// Called by PayPal webhook after successful payment
// Moves user from Users collection to users collection

const admin = require('firebase-admin');

// Initialize Firebase Admin (singleton pattern)
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_ADMIN_PROJECT_ID,
        clientEmail: process.env.FIREBASE_ADMIN_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_ADMIN_PRIVATE_KEY.replace(/\\n/g, '\n')
      })
    });
    console.log('Firebase Admin initialized successfully');
  } catch (error) {
    console.error('Firebase Admin initialization error:', error);
  }
}

// Plan configurations
const PLAN_CONFIG = {
  starter: {
    descriptionsAllowed: 50,
    planType: 'starter'
  },
  professional: {
    descriptionsAllowed: 250,
    planType: 'professional'
  },
  enterprise: {
    descriptionsAllowed: 1000,
    planType: 'enterprise'
  }
};

exports.handler = async (event, context) => {
  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Handle preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // Only allow POST
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    // Parse request body (from PayPal webhook)
    const body = JSON.parse(event.body || '{}');

    // Extract required fields
    const {
      userId,
      email,
      subscriptionId,
      planType, // 'starter', 'professional', or 'enterprise'
      billingCycle, // 'monthly' or 'annual'
      billingAmount,
      nextBillingDate
    } = body;

    // Validate required fields
    if (!userId || !email || !subscriptionId || !planType) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Missing required fields' })
      };
    }

    // Validate plan type
    if (!PLAN_CONFIG[planType]) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid plan type' })
      };
    }

    const planConfig = PLAN_CONFIG[planType];

    // Check if user exists in Users (trial) collection
    const trialUserDoc = await admin.firestore().collection('Users').doc(userId).get();
    let previousData = {};

    if (trialUserDoc.exists) {
      previousData = trialUserDoc.data();
      console.log(`Upgrading trial user ${userId} to ${planType}`);
    } else {
      console.log(`Creating new subscribed user ${userId} (${planType})`);
    }

    // Create subscribed user document in users collection (lowercase u)
    const subscribedUserDoc = {
      // Identity
      email: email,
      userId: userId,

      // Status & Plan
      status: planType,
      planType: planType,
      previousStatus: previousData.status || null,

      // Subscription Details
      subscriptionId: subscriptionId,
      subscriptionProvider: 'paypal',
      subscriptionStatus: 'active',

      // Usage Tracking
      descriptionsRemaining: planConfig.descriptionsAllowed,
      descriptionsUsed: 0,
      totalDescriptionsAllowed: planConfig.descriptionsAllowed,

      // Billing
      billingCycle: billingCycle || 'monthly',
      billingAmount: billingAmount,
      currency: 'USD',
      nextBillingDate: nextBillingDate ? admin.firestore.Timestamp.fromDate(new Date(nextBillingDate)) : null,

      // Timestamps
      createdAt: previousData.createdAt || admin.firestore.FieldValue.serverTimestamp(),
      subscribedAt: admin.firestore.FieldValue.serverTimestamp(),
      lastActiveAt: admin.firestore.FieldValue.serverTimestamp(),
      lastDescriptionGeneratedAt: previousData.lastDescriptionGeneratedAt || null,
      trialStartedAt: previousData.createdAt || null,
      trialEndedAt: trialUserDoc.exists ? admin.firestore.FieldValue.serverTimestamp() : null,

      // Security & Anti-Abuse
      ipAddress: previousData.ipAddress || 'unknown',
      signupIpAddress: previousData.signupIpAddress || 'unknown',

      // Flags
      emailVerified: true,
      accountActive: true,

      // Metadata
      source: previousData.source || 'organic',
      referralCode: previousData.referralCode || null,

      // Optional: User Preferences (preserve from trial if exists)
      preferences: {
        language: previousData.preferences?.language || 'en',
        defaultTone: previousData.preferences?.defaultTone || 'professional',
        defaultLength: previousData.preferences?.defaultLength || 'medium'
      }
    };

    // Write to users collection
    await admin.firestore().collection('users').doc(userId).set(subscribedUserDoc);

    // Delete from Users collection if exists (move from trial to subscribed)
    if (trialUserDoc.exists) {
      await admin.firestore().collection('Users').doc(userId).delete();
      console.log(`Deleted trial user document for ${userId}`);
    }

    console.log(`Successfully upgraded user ${userId} to ${planType} subscription`);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        userId: userId,
        status: planType,
        message: 'User upgraded to subscription successfully'
      })
    };

  } catch (error) {
    console.error('Error upgrading user to subscription:', error);

    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: 'Failed to upgrade user',
        message: error.message
      })
    };
  }
};
