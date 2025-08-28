// Simple Notion token test
exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  try {
    const notionToken = process.env.NOTION_TOKEN;
    
    if (!notionToken) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          error: 'NOTION_TOKEN not found in environment variables',
          debug: 'Environment variables are not properly set'
        })
      };
    }
    
    // Test basic Notion API call
    const response = await fetch('https://api.notion.com/v1/users/me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${notionToken}`,
        'Notion-Version': '2022-06-28'
      }
    });
    
    const result = await response.json();
    
    if (response.ok) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          message: 'Notion token works!',
          user: result.name || result.id || 'Unknown user'
        })
      };
    } else {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          error: 'Notion API rejected token',
          details: result.message || 'Unknown API error',
          code: result.code
        })
      };
    }
    
  } catch (error) {
    console.error('Notion test error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: 'Server error during token test',
        message: error.message
      })
    };
  }
};