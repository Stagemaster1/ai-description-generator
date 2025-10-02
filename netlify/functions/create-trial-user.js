// Netlify serverless function to create trial user in Firestore
// Called after email verification when user chooses "Start Free Trial"

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

exports.handler = async (event, context) => {
  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': 'https://signup.soltecsol.com',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Credentials': 'true',
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
    // Verify Firebase ID token
    const authHeader = event.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Unauthorized - No token provided' })
      };
    }

    const idToken = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userId = decodedToken.uid;
    const userEmail = decodedToken.email;

    // Verify email is verified
    if (!decodedToken.email_verified) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ error: 'Email not verified' })
      };
    }

    // Parse request body
    const body = JSON.parse(event.body || '{}');
    const ipAddress = body.ipAddress || event.headers['x-forwarded-for']?.split(',')[0].trim() || 'unknown';

    // Calculate expiration date (6 months from now)
    const now = new Date();
    const expiresAt = new Date();
    expiresAt.setMonth(expiresAt.getMonth() + 6);

    // Parse source from request (optional)
    const source = body.source || 'organic';
    const referralCode = body.referralCode || null;

    // Create comprehensive trial user document in Users collection (capital U)
    const userDoc = {
      // Identity
      email: userEmail,
      userId: userId,

      // Status & Plan
      status: 'trial',
      planType: 'trial',

      // Usage Tracking
      descriptionsRemaining: 3,
      descriptionsUsed: 0,
      totalDescriptionsAllowed: 3,

      // Timestamps
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      lastActiveAt: admin.firestore.FieldValue.serverTimestamp(),
      lastDescriptionGeneratedAt: null,
      expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),

      // Security & Anti-Abuse
      ipAddress: ipAddress,
      signupIpAddress: ipAddress,

      // Flags
      emailVerified: true,
      accountActive: true,
      trialExpired: false,

      // Metadata
      source: source,
      referralCode: referralCode
    };

    // Write to Firestore
    await admin.firestore().collection('Users').doc(userId).set(userDoc);

    console.log(`Trial user created: ${userId} (${userEmail})`);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        userId: userId,
        status: 'trial',
        descriptionsRemaining: 3,
        expiresAt: expiresAt.toISOString()
      })
    };

  } catch (error) {
    console.error('Error creating trial user:', error);

    // Handle specific Firebase errors
    if (error.code === 'auth/id-token-expired') {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Token expired' })
      };
    }

    if (error.code === 'auth/argument-error') {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid token' })
      };
    }

    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: 'Failed to create trial user',
        message: error.message
      })
    };
  }
};
