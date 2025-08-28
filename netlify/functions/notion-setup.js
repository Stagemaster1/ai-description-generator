// One-time Notion database setup
// This will create the subscriber database for you automatically

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
    
    console.log('Notion setup starting...');
    console.log('Token exists:', !!notionToken);
    
    if (!notionToken) {
      console.log('No Notion token found');
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          error: 'Please add NOTION_TOKEN to your Netlify environment variables first',
          instructions: 'Go to notion.so/my-integrations, create integration, copy token'
        })
      };
    }

    // Create the subscribers database
    console.log('Creating database...');
    const database = await createSubscribersDatabase(notionToken);
    console.log('Database created:', database.id);
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'Subscribers database created successfully!',
        databaseId: database.id,
        instructions: 'Add this database ID to NOTION_DATABASE_ID in Netlify environment variables'
      })
    };

  } catch (error) {
    console.error('Notion setup error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: error.message })
    };
  }
};

async function createSubscribersDatabase(notionToken) {
  const databaseData = {
    parent: {
      type: 'page_id',
      page_id: '25c0eb38e797800a9755d1ff4909f097'
    },
    title: [
      {
        type: 'text',
        text: {
          content: 'SolTecSol Subscribers'
        }
      }
    ],
    properties: {
      'Email': {
        type: 'email',
        email: {}
      },
      'Plan': {
        type: 'select',
        select: {
          options: [
            { name: 'starter', color: 'green' },
            { name: 'professional', color: 'blue' },
            { name: 'enterprise', color: 'purple' }
          ]
        }
      },
      'Amount': {
        type: 'rich_text',
        rich_text: {}
      },
      'Subscription ID': {
        type: 'rich_text',
        rich_text: {}
      },
      'Date': {
        type: 'date',
        date: {}
      },
      'Status': {
        type: 'select',
        select: {
          options: [
            { name: 'Active', color: 'green' },
            { name: 'Cancelled', color: 'red' },
            { name: 'Pending', color: 'yellow' }
          ]
        }
      },
      'Source': {
        type: 'rich_text',
        rich_text: {}
      }
    }
  };

  const response = await fetch('https://api.notion.com/v1/databases', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${notionToken}`,
      'Content-Type': 'application/json',
      'Notion-Version': '2022-06-28'
    },
    body: JSON.stringify(databaseData)
  });

  const result = await response.json();

  if (!response.ok) {
    throw new Error(`Failed to create database: ${result.message || 'Unknown error'}`);
  }

  return result;
}