const { OpenAI } = require('openai');
const { getAuth, getFirestore } = require('./firebase-config');
const firebaseAuthMiddleware = require('./firebase-auth-middleware');
const securityLogger = require('./security-logger');

// Note: Rate limiting is now handled by firebase-auth-middleware.js

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Brand tone configurations
const brandTones = {
  luxury: "Write in a sophisticated, premium tone that emphasizes quality, exclusivity, and elegance. Use refined language that appeals to discerning customers who value luxury.",
  casual: "Write in a friendly, conversational tone that feels approachable and relatable. Use everyday language that connects with customers on a personal level.",
  professional: "Write in an authoritative, professional tone that builds trust and credibility. Use clear, confident language that demonstrates expertise.",
  fun: "Write in a playful, energetic tone that's engaging and memorable. Use creative language that brings personality and excitement to the product.",
  minimalist: "Write in a clean, concise tone that focuses on essential information. Use simple, direct language that communicates clearly without unnecessary flourishes."
};

exports.handler = async (event, context) => {
  // SECURITY: Use Firebase authentication middleware for comprehensive validation
  const authResult = await firebaseAuthMiddleware.authenticateRequest(event, {
    requireAuth: true,
    requireSubscription: true,
    allowedMethods: ['POST', 'OPTIONS'],
    rateLimit: true
  });

  if (!authResult.success) {
    return authResult.response;
  }

  const { headers, user, subscription, clientIP } = authResult;

  try {
    // User is already authenticated and subscription validated by the middleware
    const authenticatedUser = user;
    
    console.log('Firebase authenticated user:', authenticatedUser.uid);
    console.log('Subscription status:', {
      type: subscription.subscriptionType,
      usage: `${subscription.currentUsage}/${subscription.maxUsage}`
    });

    // Log successful operation start
    const operationStart = Date.now();

    const { productUrl, productInfo, brandTone, descriptionLength, language, targetAudience, keyFeatures, userId, inputMode } = JSON.parse(event.body);
    
    // SECURITY FIX: Verify userId matches authenticated user
    if (userId !== authenticatedUser.uid) {
      // Log suspicious activity
      securityLogger.logSuspiciousActivity({
        activityType: 'user_id_mismatch',
        description: 'Request userId does not match authenticated user',
        clientIP: clientIP,
        userId: authenticatedUser.uid,
        endpoint: '/generate',
        additionalData: { requestedUserId: userId }
      });

      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ error: 'Access denied: User ID mismatch' })
      };
    }
    
    console.log('Generation request for authenticated user:', {
      userId: authenticatedUser.uid,
      brandTone,
      descriptionLength,
      inputMode,
      hasProductInfo: !!productInfo,
      hasProductUrl: !!productUrl
    });

    // Validate required fields
    if (!brandTone) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Brand tone is required' })
      };
    }

    // Validate that we have either URL or product info
    if (!productUrl && !productInfo) {
      console.log('Validation failed: Missing product data', { inputMode, hasUrl: !!productUrl, hasInfo: !!productInfo });
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Product URL or product information is required' })
      };
    }

    // Validate brand tone
    if (!brandTones[brandTone]) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid brand tone' })
      };
    }

    // Extract or use provided product information
    let finalProductInfo;
    if (inputMode === 'barcode' && productInfo) {
      // Use barcode-provided product info
      finalProductInfo = {
        productType: determineProductType(productInfo.name, productInfo.category),
        platform: productInfo.source || 'Barcode Database',
        url: null,
        barcode: productInfo.barcode,
        name: productInfo.name,
        brand: productInfo.brand,
        category: productInfo.category,
        description: productInfo.description,
        additionalInfo: productInfo.additionalInfo
      };
    } else {
      // Extract product information from URL
      finalProductInfo = extractProductInfo(productUrl);
    }

    // Generate the description using OpenAI
    const description = await generateDescription({
      productUrl,
      productInfo: finalProductInfo,
      brandTone,
      descriptionLength,
      targetAudience,
      keyFeatures,
      inputMode
    });

    // Log successful operation
    const operationEnd = Date.now();
    securityLogger.logOperationSuccess({
      operation: 'generate_description',
      userId: authenticatedUser.uid,
      endpoint: '/generate',
      duration: operationEnd - operationStart,
      resourcesAccessed: ['openai_api', 'firebase_firestore']
    });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        description,
        success: true,
        usage: {
          currentUsage: subscription.currentUsage,
          maxUsage: subscription.maxUsage,
          subscriptionType: subscription.subscriptionType
        }
      })
    };

  } catch (error) {
    console.error('OpenAI API Error:', error);
    
    // Log operation failure
    const operationEnd = Date.now();
    securityLogger.logOperationFailure({
      operation: 'generate_description',
      userId: user?.uid,
      endpoint: '/generate',
      error: error.message,
      duration: operationEnd - operationStart,
      stackTrace: error.stack
    });
    
    // Handle specific OpenAI errors
    if (error.status === 429) {
      return {
        statusCode: 429,
        headers,
        body: JSON.stringify({ 
          error: 'Rate limit exceeded. Please try again in a moment.',
          retry_after: 60
        })
      };
    }

    if (error.status === 401) {
      // Log configuration issue
      securityLogger.logConfigIssue({
        component: 'openai_api',
        issue: 'Invalid API key or authentication failed',
        severity: 'HIGH',
        recommendation: 'Check OPENAI_API_KEY environment variable'
      });

      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ 
          error: 'API configuration error. Please contact support.'
        })
      };
    }

    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Failed to generate description. Please try again.',
        message: error.message 
      })
    };
  }
};

// Note: Subscription validation is now handled by firebase-auth-middleware.js

function extractProductInfo(productUrl) {
  const urlLower = productUrl.toLowerCase();
  let productType = 'product';
  let platform = 'unknown';
  
  // Detect platform
  if (urlLower.includes('aliexpress')) platform = 'AliExpress';
  else if (urlLower.includes('amazon')) platform = 'Amazon';
  else if (urlLower.includes('ebay')) platform = 'eBay';
  else if (urlLower.includes('shopify')) platform = 'Shopify';
  
  // Extract product type from URL
  if (urlLower.includes('watch') || urlLower.includes('clock')) productType = 'timepiece';
  else if (urlLower.includes('phone') || urlLower.includes('mobile')) productType = 'smartphone';
  else if (urlLower.includes('headphone') || urlLower.includes('earphone') || urlLower.includes('audio')) productType = 'audio device';
  else if (urlLower.includes('shirt') || urlLower.includes('dress') || urlLower.includes('clothing') || urlLower.includes('fashion')) productType = 'fashion item';
  else if (urlLower.includes('laptop') || urlLower.includes('computer')) productType = 'computer';
  else if (urlLower.includes('kitchen') || urlLower.includes('cook')) productType = 'kitchen appliance';
  else if (urlLower.includes('book')) productType = 'book';
  else if (urlLower.includes('toy') || urlLower.includes('game')) productType = 'toy/game';
  else if (urlLower.includes('beauty') || urlLower.includes('cosmetic')) productType = 'beauty product';
  else if (urlLower.includes('home') || urlLower.includes('decor')) productType = 'home decor item';
  
  return {
    productType,
    platform,
    url: productUrl
  };
}

function determineProductType(productName, category) {
  if (!productName && !category) return 'product';
  
  const text = `${productName || ''} ${category || ''}`.toLowerCase();
  
  if (text.includes('watch') || text.includes('clock') || text.includes('timepiece')) return 'timepiece';
  if (text.includes('phone') || text.includes('mobile') || text.includes('smartphone')) return 'smartphone';
  if (text.includes('headphone') || text.includes('earphone') || text.includes('audio') || text.includes('speaker')) return 'audio device';
  if (text.includes('shirt') || text.includes('dress') || text.includes('clothing') || text.includes('apparel') || text.includes('fashion')) return 'fashion item';
  if (text.includes('laptop') || text.includes('computer') || text.includes('pc')) return 'computer';
  if (text.includes('kitchen') || text.includes('cook') || text.includes('appliance')) return 'kitchen appliance';
  if (text.includes('book') || text.includes('novel') || text.includes('magazine')) return 'book';
  if (text.includes('toy') || text.includes('game') || text.includes('play')) return 'toy/game';
  if (text.includes('beauty') || text.includes('cosmetic') || text.includes('makeup')) return 'beauty product';
  if (text.includes('home') || text.includes('decor') || text.includes('furniture')) return 'home decor item';
  if (text.includes('food') || text.includes('snack') || text.includes('drink') || text.includes('beverage')) return 'food/beverage';
  if (text.includes('health') || text.includes('supplement') || text.includes('vitamin')) return 'health product';
  if (text.includes('tool') || text.includes('hardware') || text.includes('equipment')) return 'tool/equipment';
  
  return 'product';
}

async function generateDescription({ productUrl, productInfo, brandTone, descriptionLength = 'medium', language = 'english', targetAudience, keyFeatures, inputMode }) {
  const toneInstruction = brandTones[brandTone];
  
  // Length specifications
  const lengthSpecs = {
    short: {
      words: '50-100 words',
      style: 'concise and impactful',
      structure: 'Focus on the most compelling benefits and key features only'
    },
    medium: {
      words: '150-250 words', 
      style: 'balanced and comprehensive',
      structure: 'Include headline, key benefits, and important features with good flow'
    },
    extensive: {
      words: '300-500 words',
      style: 'detailed and thorough',
      structure: 'Complete product story with headline, detailed benefits, features, and strong call-to-action'
    }
  };
  
  const lengthSpec = lengthSpecs[descriptionLength || 'medium'] || lengthSpecs.medium;
  
  // Build the prompt
  let prompt = `Generate a compelling, SEO-optimized product description for an e-commerce listing.

PRODUCT DETAILS:`;

  if (inputMode === 'barcode' && productInfo.barcode) {
    prompt += `
- Product Name: ${productInfo.name || 'Unknown Product'}
- Brand: ${productInfo.brand || 'Unknown Brand'}
- Category: ${productInfo.category || 'General Product'}
- Product Type: ${productInfo.productType}
- Barcode/UPC: ${productInfo.barcode}
- Source: ${productInfo.platform}`;
    
    if (productInfo.description) {
      prompt += `\n- Existing Description: ${productInfo.description}`;
    }
  } else if (inputMode === 'barcode' && productInfo.platform === 'Manual Entry') {
    // Manual entry - don't mention source or barcode stuff
    prompt += `
- Product Name: ${productInfo.name}
- Product Type: ${productInfo.productType}

IMPORTANT: Write about the PRODUCT (${productInfo.name}), not about the target audience. The target audience is WHO you're selling to, the product name is WHAT you're selling.`;
    
  } else {
    prompt += `
- Product URL: ${productUrl}
- Product Type: ${productInfo.productType}
- Platform: ${productInfo.platform}`;
  }

  prompt += `\n\nBRAND TONE: ${toneInstruction}`;

  if (targetAudience) {
    prompt += `\nTARGET AUDIENCE: ${targetAudience}`;
  }

  if (keyFeatures) {
    prompt += `\nKEY FEATURES TO HIGHLIGHT: ${keyFeatures}`;
  }

  prompt += `

LANGUAGE: Write the description in ${language === 'english' ? 'English' : 
  language === 'german' ? 'German (Deutsch)' :
  language === 'french' ? 'French (Français)' :
  language === 'spanish' ? 'Spanish (Español)' :
  language === 'portuguese' ? 'Portuguese (Português)' :
  language === 'italian' ? 'Italian (Italiano)' :
  language === 'dutch' ? 'Dutch (Nederlands)' :
  language === 'russian' ? 'Russian (Русский)' :
  language === 'japanese' ? 'Japanese (日本語)' :
  language === 'korean' ? 'Korean (한국어)' :
  language === 'chinese' ? 'Chinese (中文)' :
  language === 'arabic' ? 'Arabic (العربية)' :
  language === 'hindi' ? 'Hindi (हिन्दी)' : 'English'}. Use natural, fluent, native-level language that sounds authentic to native speakers.

LENGTH REQUIREMENT: ${lengthSpec.words} - ${lengthSpec.style}
STRUCTURE: ${lengthSpec.structure}

REQUIREMENTS:
1. Create a compelling headline that grabs attention
2. Write in the specified length (${lengthSpec.words}) while maintaining high quality
3. Include SEO-friendly keywords naturally in the target language
4. Focus on benefits, not just features
5. Create urgency or desire to purchase
6. Make it conversion-focused
7. Maintain the same professional quality regardless of length
8. Use culturally appropriate marketing language for the target market
9. ${descriptionLength === 'short' ? 'Be punchy and direct - every word counts' : 
     descriptionLength === 'extensive' ? 'Provide comprehensive details and compelling storytelling' :
     'Balance detail with readability for optimal conversion'}

Please generate a professional product description that matches the specified brand tone and appeals to the target audience in the specified language.`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4",
      messages: [
        {
          role: "system",
          content: "You are an expert e-commerce copywriter specializing in creating high-converting product descriptions that boost sales and improve SEO rankings."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      max_tokens: 500,
      temperature: 0.7,
    });

    return response.choices[0].message.content.trim();
  } catch (error) {
    console.error('OpenAI API call failed:', error);
    throw error;
  }
}

// Note: Rate limiting cleanup is now handled by firebase-auth-middleware.js
