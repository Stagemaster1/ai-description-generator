// SESSION 4D3: Firebase Configuration - Admin-only access to Firebase client config
// Secured with firebase-auth-middleware and admin role validation

const firebaseAuthMiddleware = require('./firebase-auth-middleware');

// Import Firebase Admin SDK functions
const { getAuth, getFirestore, initializeFirebaseAdmin } = require('./firebase-admin-config');

exports.handler = async (event, context) => {
    // SESSION 4D3: Use firebase-auth-middleware for secure admin authentication
    const authResult = await firebaseAuthMiddleware.authenticateRequest(event, {
        requireAuth: true,
        requireSubscription: false, // Admin endpoints don't need subscription validation
        requireAdmin: true, // CRITICAL: Require admin role for Firebase config access
        allowedMethods: ['GET'],
        rateLimit: true
    });

    // Handle authentication failures
    if (!authResult.success) {
        return authResult.response;
    }

    const { headers, user } = authResult;

    // Return the Firebase configuration as JSON
    // Only public configuration values - no sensitive credentials exposed
    const firebaseConfig = {
        apiKey: process.env.FIREBASE_API_KEY,
        authDomain: process.env.FIREBASE_AUTH_DOMAIN,
        projectId: process.env.FIREBASE_PROJECT_ID,
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
        messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
        appId: process.env.FIREBASE_APP_ID
    };

    // Validate that all required environment variables are present
    const missingVars = Object.entries(firebaseConfig)
        .filter(([key, value]) => !value)
        .map(([key]) => key);

    if (missingVars.length > 0) {
        console.error('Missing Firebase environment variables:', missingVars);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Firebase configuration incomplete',
                missing: missingVars
            })
        };
    }

    // SESSION 4D3: Log admin access to Firebase config
    console.log('[ADMIN ACCESS] Firebase config accessed by:', {
        adminId: user.uid,
        adminEmail: user.email,
        timestamp: new Date().toISOString()
    });

    return {
        statusCode: 200,
        headers: {
            ...headers,
            'Cache-Control': 'private, no-cache' // Admin-only data should not be cached
        },
        body: JSON.stringify(firebaseConfig)
    };
};

// Export Firebase Admin SDK functions for other modules
module.exports.getAuth = getAuth;
module.exports.getFirestore = getFirestore;
module.exports.initializeFirebaseAdmin = initializeFirebaseAdmin;