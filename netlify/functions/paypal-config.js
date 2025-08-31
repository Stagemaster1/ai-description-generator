// PayPal Configuration - Returns only public Client ID for frontend use
// This function provides secure access to PayPal Client ID without exposing secrets

exports.handler = async (event, context) => {
    // Enable CORS for frontend access
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, OPTIONS'
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

    // Return the PayPal Client ID as JSON
    return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ clientId: process.env.PAYPAL_CLIENT_ID })
    };
};