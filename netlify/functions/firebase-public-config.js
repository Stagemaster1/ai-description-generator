console.log("ENV:", process.env);

// SESSION 4C: Public Firebase Configuration Endpoint
// Provides Firebase client configuration for public access (non-admin)
// This is safe as it only exposes public configuration values

exports.handler = async (event, context) => {
    // Handle CORS for all origins since this is public configuration
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=300' // Cache for 5 minutes
    };

    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers,
            body: ''
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

    try {
        // Return only public Firebase configuration values
        // These are safe to expose as they're needed for client-side Firebase initialization
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
                statusCode: 503,
                headers,
                body: JSON.stringify({
                    error: 'Service configuration incomplete',
                    message: 'Firebase configuration is not properly set up'
                })
            };
        }

        // Log successful config access (without sensitive details)
        console.log('[PUBLIC CONFIG] Firebase config accessed from:', {
            origin: event.headers.origin || 'unknown',
            userAgent: event.headers['user-agent'] || 'unknown',
            timestamp: new Date().toISOString()
        });

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(firebaseConfig)
        };

    } catch (error) {
        console.error('Firebase public config error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({
                error: 'Configuration service temporarily unavailable',
                message: 'Please try again later'
            })
        };
    }
};