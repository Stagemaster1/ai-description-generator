// Netlify serverless function to retrieve client IP address
// This prevents CORS issues and provides reliable IP detection

exports.handler = async (event, context) => {
  try {
    // Get client IP from various possible headers
    const clientIP =
      event.headers['x-forwarded-for']?.split(',')[0].trim() ||
      event.headers['x-real-ip'] ||
      event.headers['client-ip'] ||
      context.clientContext?.custom?.netlify?.ip ||
      'unknown';

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': 'https://signup.soltecsol.com',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      },
      body: JSON.stringify({
        ip: clientIP,
        timestamp: new Date().toISOString()
      })
    };
  } catch (error) {
    console.error('Error retrieving client IP:', error);

    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        error: 'Failed to retrieve client IP',
        message: error.message
      })
    };
  }
};