// Direct Notion API test - minimal version
const fetch = require('node-fetch');

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
    
    console.log('=== DIRECT NOTION TEST ===');
    console.log('Token exists:', !!notionToken);
    console.log('Token starts with secret_:', notionToken?.startsWith('secret_'));
    
    if (!notionToken) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'No NOTION_TOKEN found' })
      };
    }

    // Try to add a simple entry to the database
    const databaseId = '25d0eb38e797809e90d2cdd8c9e10bec';
    
    const pageData = {
      parent: { database_id: databaseId },
      properties: {
        'Email': {
          title: [{ text: { content: 'direct-test@example.com' } }]
        },
        'Plan': {
          select: { name: 'starter' }
        },
        'Amount': {
          rich_text: [{ text: { content: '$19.99' } }]
        }
      }
    };
    
    console.log('Attempting to create page with data:', JSON.stringify(pageData, null, 2));
    
    const response = await fetch('https://api.notion.com/v1/pages', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${notionToken}`,
        'Content-Type': 'application/json',
        'Notion-Version': '2022-06-28'
      },
      body: JSON.stringify(pageData)
    });
    
    const result = await response.json();
    
    console.log('Response status:', response.status);
    console.log('Response data:', JSON.stringify(result, null, 2));
    
    if (response.ok) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          message: 'Direct Notion test SUCCESS!',
          pageId: result.id
        })
      };
    } else {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          error: 'Notion API error',
          status: response.status,
          details: result
        })
      };
    }

  } catch (error) {
    console.error('Direct test error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: 'Server error',
        message: error.message
      })
    };
  }
};