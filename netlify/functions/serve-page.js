const fs = require('fs');
const path = require('path');

exports.handler = async (event, context) => {
    try {
        // Read the index.html file from the site root
        const htmlPath = path.resolve(__dirname, '../../index.html');
        let html = fs.readFileSync(htmlPath, 'utf8');
        
        // Get PayPal Client ID from environment variables
        const paypalClientId = process.env.PAYPAL_CLIENT_ID;
        
        if (!paypalClientId) {
            console.error('PAYPAL_CLIENT_ID environment variable not set');
            return {
                statusCode: 500,
                headers: {
                    'Content-Type': 'text/html'
                },
                body: '<h1>Server Configuration Error</h1><p>PayPal configuration missing. Please contact support.</p>'
            };
        }
        
        // Replace placeholder with actual Client ID
        html = html.replace('PAYPAL_CLIENT_ID_PLACEHOLDER', paypalClientId);
        
        return {
            statusCode: 200,
            headers: {
                'Content-Type': 'text/html',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            },
            body: html
        };
        
    } catch (error) {
        console.error('Error serving page:', error);
        return {
            statusCode: 500,
            headers: {
                'Content-Type': 'text/html'
            },
            body: '<h1>Server Error</h1><p>Unable to load the page. Please try again later.</p>'
        };
    }
};