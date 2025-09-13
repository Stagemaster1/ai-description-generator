// Firebase Configuration - Public endpoint for client-side Firebase initialization
// This endpoint provides only public configuration values needed for Firebase client setup

exports.handler = async (event, context) => {
    // CORS headers for cross-origin requests
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Content-Type': 'application/json'
    };

    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers
        };
    }

    // Only allow GET requests
    if (event.httpMethod !== 'GET') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

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

    // Log public access to Firebase config (no sensitive data)
    console.log('[PUBLIC ACCESS] Firebase config requested:', {
        timestamp: new Date().toISOString(),
        origin: event.headers.origin
    });

    return {
        statusCode: 200,
        headers: {
            ...headers,
            'Cache-Control': 'public, max-age=300' // Public data can be cached for 5 minutes
        },
        body: JSON.stringify(firebaseConfig)
    };
};