// Anonymous User Tracking API
// Tracks usage for anonymous users by browser fingerprint to prevent refresh abuse

const { getFirestore } = require('../../firebase-config');

exports.handler = async (event, context) => {
  // Enable CORS
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const { action, fingerprint, usage } = JSON.parse(event.body || '{}');

    if (!action || !fingerprint) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          success: false,
          message: 'Missing required fields' 
        })
      };
    }

    // Initialize Firebase
    const db = getFirestore();

    switch (action) {
      case 'get_usage':
        return await getAnonymousUsage(db, fingerprint, headers);
      
      case 'update_usage':
        return await updateAnonymousUsage(db, fingerprint, usage, headers);
      
      default:
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ 
            success: false,
            message: 'Invalid action' 
          })
        };
    }
  } catch (error) {
    console.error('Anonymous tracking API error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        success: false,
        message: 'Internal server error' 
      })
    };
  }
};

// Get anonymous usage for a fingerprint
async function getAnonymousUsage(db, fingerprint, headers) {
  try {
    // Look up usage by fingerprint
    const usageDoc = await db.collection('anonymous_usage').doc(fingerprint).get();
    
    if (!usageDoc.exists) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
          success: true,
          usage: 0
        })
      };
    }

    const data = usageDoc.data();
    const usage = data.usage || 0;
    
    // Check if usage should reset (monthly reset)
    const lastUpdate = new Date(data.lastUpdated);
    const now = new Date();
    const shouldReset = now.getMonth() !== lastUpdate.getMonth() || now.getFullYear() !== lastUpdate.getFullYear();
    
    if (shouldReset) {
      // Reset usage for new month
      await usageDoc.ref.update({
        usage: 0,
        lastUpdated: now.toISOString(),
        resetAt: now.toISOString()
      });
      
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
          success: true,
          usage: 0
        })
      };
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        usage: usage
      })
    };

  } catch (error) {
    console.error('Get anonymous usage error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        success: false,
        message: 'Failed to get usage' 
      })
    };
  }
}

// Update anonymous usage for a fingerprint
async function updateAnonymousUsage(db, fingerprint, usage, headers) {
  try {
    const now = new Date();
    const usageDoc = db.collection('anonymous_usage').doc(fingerprint);
    
    // Get current data
    const currentDoc = await usageDoc.get();
    
    if (currentDoc.exists) {
      const currentData = currentDoc.data();
      const lastUpdate = new Date(currentData.lastUpdated);
      
      // Check if usage should reset (monthly reset)
      const shouldReset = now.getMonth() !== lastUpdate.getMonth() || now.getFullYear() !== lastUpdate.getFullYear();
      
      if (shouldReset) {
        // Reset for new month, but still apply the new usage
        await usageDoc.update({
          usage: Math.min(usage, 1), // Start fresh but don't go backwards
          lastUpdated: now.toISOString(),
          resetAt: now.toISOString(),
          fingerprint: fingerprint
        });
      } else {
        // Update with highest usage (prevents going backwards)
        const newUsage = Math.max(currentData.usage || 0, usage);
        await usageDoc.update({
          usage: newUsage,
          lastUpdated: now.toISOString(),
          fingerprint: fingerprint
        });
      }
    } else {
      // Create new record
      await usageDoc.set({
        usage: usage,
        fingerprint: fingerprint,
        createdAt: now.toISOString(),
        lastUpdated: now.toISOString(),
        userAgent: '', // Could add from headers if needed
        ipHash: '' // Could add hashed IP if needed
      });
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: 'Usage updated successfully'
      })
    };

  } catch (error) {
    console.error('Update anonymous usage error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        success: false,
        message: 'Failed to update usage' 
      })
    };
  }
}