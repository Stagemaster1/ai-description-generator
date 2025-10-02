// Netlify serverless function to check if user exists in Firestore
// Checks both Users (trial) and users (subscribed) collections

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
    'Access-Control-Allow-Origin': 'https://signup.soltecsol.com, https://login.soltecsol.com, https://app.soltecsol.com',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Credentials': 'true',
    'Content-Type': 'application/json'
  };

  // Handle preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // Only allow GET
  if (event.httpMethod !== 'GET') {
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
    const requestingUserId = decodedToken.uid;

    // Get userId from query parameter
    const userId = event.queryStringParameters?.userId;

    if (!userId) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'userId parameter required' })
      };
    }

    // Security: Only allow users to check their own status
    if (userId !== requestingUserId) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ error: 'Forbidden - Can only check own status' })
      };
    }

    // Check Users collection (trial users)
    const trialUserDoc = await admin.firestore().collection('Users').doc(userId).get();

    if (trialUserDoc.exists) {
      const userData = trialUserDoc.data();
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          exists: true,
          collection: 'Users',
          status: userData.status || 'trial',
          descriptionsRemaining: userData.descriptionsRemaining || 0
        })
      };
    }

    // Check users collection (subscribed users)
    const subscribedUserDoc = await admin.firestore().collection('users').doc(userId).get();

    if (subscribedUserDoc.exists) {
      const userData = subscribedUserDoc.data();
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          exists: true,
          collection: 'users',
          status: userData.status || 'unknown',
          descriptionsRemaining: userData.descriptionsRemaining || 0
        })
      };
    }

    // User not found in either collection
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({
        exists: false,
        message: 'User not found in Firestore'
      })
    };

  } catch (error) {
    console.error('Error checking user status:', error);

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
        error: 'Failed to check user status',
        message: error.message
      })
    };
  }
};
