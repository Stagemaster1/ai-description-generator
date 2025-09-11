// SESSION 4D6: Secured Barcode/UPC lookup functionality
// Integrates with multiple barcode databases to identify products
// Enhanced with Firebase Auth middleware, proper rate limiting, and security headers

const fetch = require('node-fetch');
const firebaseAuthMiddleware = require('./firebase-auth-middleware');
const securityLogger = require('./security-logger');

exports.handler = async (event, context) => {
    try {
        // SESSION 4D6: Apply comprehensive authentication and security using firebase-auth-middleware
        const authResult = await firebaseAuthMiddleware.authenticateRequest(event, {
            requireAuth: true,
            requireSubscription: true, // Barcode lookup requires valid subscription
            requireAdmin: false,
            allowedMethods: ['POST'],
            rateLimit: true
        });

        if (!authResult.success) {
            // Log barcode lookup access failure
            securityLogger.logAuthFailure({
                reason: 'barcode_lookup_access_denied',
                error: 'Authentication failed for barcode lookup',
                clientIP: event.headers['x-forwarded-for'] || 'unknown',
                endpoint: 'barcode-lookup',
                method: event.httpMethod
            });
            
            return authResult.response;
        }

        const { headers, user, subscription, clientIP } = authResult;

        // Parse and validate request body
        let requestBody;
        try {
            requestBody = JSON.parse(event.body || '{}');
        } catch (parseError) {
            securityLogger.logSecurityEvent({
                type: 'invalid_request_body',
                userId: user.uid,
                clientIP: clientIP,
                endpoint: 'barcode-lookup',
                error: 'Invalid JSON in request body'
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'Invalid request body - must be valid JSON' 
                })
            };
        }

        const { barcode } = requestBody;

        if (!barcode) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'Barcode parameter is required' 
                })
            };
        }

        // Validate barcode format for security
        if (!isValidBarcode(barcode)) {
            securityLogger.logSecurityEvent({
                type: 'invalid_barcode_format',
                userId: user.uid,
                clientIP: clientIP,
                endpoint: 'barcode-lookup',
                barcode: barcode
            });

            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'Invalid barcode format. Must be 8, 12, or 13 digit UPC/EAN code.' 
                })
            };
        }

        // Log successful barcode lookup attempt
        securityLogger.logSecurityEvent({
            type: 'barcode_lookup_attempt',
            userId: user.uid,
            email: user.email,
            clientIP: clientIP,
            barcode: barcode,
            subscriptionType: subscription.subscriptionType,
            usageAfter: subscription.currentUsage
        });

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
            // Log successful lookup
            securityLogger.logSecurityEvent({
                type: 'barcode_lookup_success',
                userId: user.uid,
                barcode: barcode,
                source: productInfo.source,
                productName: productInfo.name
            });

            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    success: true,
                    product: productInfo
                })
            };
        } else {
            // Log failed lookup
            securityLogger.logSecurityEvent({
                type: 'barcode_lookup_not_found',
                userId: user.uid,
                barcode: barcode
            });

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
        
        // Log server error
        securityLogger.logSecurityEvent({
            type: 'barcode_lookup_server_error',
            error: error.message,
            stack: error.stack,
            endpoint: 'barcode-lookup'
        });

        return {
            statusCode: 500,
            headers: firebaseAuthMiddleware.createSecureHeaders(),
            body: JSON.stringify({ 
                error: 'Internal server error',
                message: 'Barcode lookup service temporarily unavailable'
            })
        };
    }
};

/**
 * Validate barcode format for security
 * @param {string} barcode - Barcode to validate
 * @returns {boolean} True if valid format
 */
function isValidBarcode(barcode) {
    if (!barcode || typeof barcode !== 'string') {
        return false;
    }

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

/**
 * Lookup product info from UPCDatabase.org
 * @param {string} barcode - Product barcode
 * @returns {Object|null} Product information or null
 */
async function lookupUPCDatabase(barcode) {
    try {
        // UPCDatabase.org - free tier available
        const response = await fetch(`https://api.upcdatabase.org/product/${barcode}`, {
            headers: {
                'User-Agent': 'SolTecSol-AI-Description-Generator/1.0'
            },
            timeout: 10000
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
    } catch (error) {
        console.error('UPCDatabase lookup error:', error);
        throw new Error(`UPCDatabase lookup failed: ${error.message}`);
    }
}

/**
 * Lookup product info from OpenFoodFacts
 * @param {string} barcode - Product barcode
 * @returns {Object|null} Product information or null
 */
async function lookupOpenFoodFacts(barcode) {
    try {
        // OpenFoodFacts - free, good for food products
        const response = await fetch(`https://world.openfoodfacts.org/api/v0/product/${barcode}.json`, {
            timeout: 10000
        });
        
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
    } catch (error) {
        console.error('OpenFoodFacts lookup error:', error);
        throw new Error(`OpenFoodFacts lookup failed: ${error.message}`);
    }
}

/**
 * Lookup product info from Barcode Lookup API
 * @param {string} barcode - Product barcode
 * @returns {Object|null} Product information or null
 */
async function lookupBarcodeLookupAPI(barcode) {
    try {
        // Barcode Lookup API - requires API key
        if (!process.env.BARCODE_LOOKUP_API_KEY) {
            throw new Error('Barcode Lookup API key not configured');
        }

        const response = await fetch(`https://api.barcodelookup.com/v3/products?barcode=${barcode}&formatted=y&key=${process.env.BARCODE_LOOKUP_API_KEY}`, {
            timeout: 10000
        });
        
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
    } catch (error) {
        console.error('Barcode Lookup API error:', error);
        throw new Error(`Barcode Lookup API failed: ${error.message}`);
    }
}