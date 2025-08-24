// Barcode/UPC lookup functionality
// Integrates with multiple barcode databases to identify products

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
    const { barcode } = JSON.parse(event.body);

    if (!barcode) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Barcode is required' })
      };
    }

    // Validate barcode format
    if (!isValidBarcode(barcode)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid barcode format' })
      };
    }

    // Try multiple barcode lookup services
    let productInfo = null;
    
    // Try UPCDatabase.org first (free tier available)
    try {
      productInfo = await lookupUPCDatabase(barcode);
    } catch (error) {
      console.warn('UPCDatabase lookup failed:', error.message);
    }

    // Try OpenFoodFacts as fallback (free, good for food products)
    if (!productInfo) {
      try {
        productInfo = await lookupOpenFoodFacts(barcode);
      } catch (error) {
        console.warn('OpenFoodFacts lookup failed:', error.message);
      }
    }

    // Try Barcode Lookup API as another fallback
    if (!productInfo && process.env.BARCODE_LOOKUP_API_KEY) {
      try {
        productInfo = await lookupBarcodeLookupAPI(barcode);
      } catch (error) {
        console.warn('Barcode Lookup API failed:', error.message);
      }
    }

    if (productInfo) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          product: productInfo
        })
      };
    } else {
      return {
        statusCode: 404,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Product not found in barcode databases'
        })
      };
    }

  } catch (error) {
    console.error('Barcode lookup error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Internal server error',
        message: error.message 
      })
    };
  }
};

function isValidBarcode(barcode) {
  // Remove any spaces or dashes
  const cleanBarcode = barcode.replace(/[\s-]/g, '');
  
  // Check if it's a valid UPC/EAN format
  const upcPattern = /^\d{12}$/; // UPC-A (12 digits)
  const eanPattern = /^\d{13}$/; // EAN-13 (13 digits)
  const upcEPattern = /^\d{8}$/;  // UPC-E (8 digits)
  
  return upcPattern.test(cleanBarcode) || 
         eanPattern.test(cleanBarcode) || 
         upcEPattern.test(cleanBarcode);
}

async function lookupUPCDatabase(barcode) {
  // UPCDatabase.org - free tier available
  const response = await fetch(`https://api.upcdatabase.org/product/${barcode}`, {
    headers: {
      'User-Agent': 'SolTecSol-AI-Description-Generator/1.0'
    }
  });

  if (!response.ok) {
    throw new Error(`UPCDatabase API error: ${response.status}`);
  }

  const data = await response.json();
  
  if (data.success) {
    return {
      name: data.title,
      brand: data.brand,
      category: data.category,
      description: data.description,
      imageUrl: data.image,
      source: 'UPCDatabase',
      barcode: barcode,
      additionalInfo: {
        size: data.size,
        model: data.model
      }
    };
  }
  
  return null;
}

async function lookupOpenFoodFacts(barcode) {
  // OpenFoodFacts - free, good for food products
  const response = await fetch(`https://world.openfoodfacts.org/api/v0/product/${barcode}.json`);
  
  if (!response.ok) {
    throw new Error(`OpenFoodFacts API error: ${response.status}`);
  }

  const data = await response.json();
  
  if (data.status === 1 && data.product) {
    const product = data.product;
    return {
      name: product.product_name || product.product_name_en,
      brand: product.brands,
      category: product.categories,
      description: product.generic_name || product.product_name,
      imageUrl: product.image_url,
      source: 'OpenFoodFacts',
      barcode: barcode,
      additionalInfo: {
        ingredients: product.ingredients_text,
        nutrition: product.nutriments,
        quantity: product.quantity
      }
    };
  }
  
  return null;
}

async function lookupBarcodeLookupAPI(barcode) {
  // Barcode Lookup API - requires API key
  if (!process.env.BARCODE_LOOKUP_API_KEY) {
    throw new Error('Barcode Lookup API key not configured');
  }

  const response = await fetch(`https://api.barcodelookup.com/v3/products?barcode=${barcode}&formatted=y&key=${process.env.BARCODE_LOOKUP_API_KEY}`);
  
  if (!response.ok) {
    throw new Error(`Barcode Lookup API error: ${response.status}`);
  }

  const data = await response.json();
  
  if (data.products && data.products.length > 0) {
    const product = data.products[0];
    return {
      name: product.title,
      brand: product.brand,
      category: product.category,
      description: product.description,
      imageUrl: product.images?.[0],
      source: 'BarcodeLookupAPI',
      barcode: barcode,
      additionalInfo: {
        manufacturer: product.manufacturer,
        model: product.model,
        size: product.size,
        weight: product.weight
      }
    };
  }
  
  return null;
}

// Helper function to generate product info when barcode lookup fails
function generateFallbackProductInfo(barcode) {
  return {
    name: `Product ${barcode}`,
    brand: 'Unknown Brand',
    category: 'General Product',
    description: `Product identified by barcode ${barcode}`,
    imageUrl: null,
    source: 'Fallback',
    barcode: barcode,
    additionalInfo: {
      note: 'Product information not found in databases. Description will be generated based on user input.'
    }
  };
}
