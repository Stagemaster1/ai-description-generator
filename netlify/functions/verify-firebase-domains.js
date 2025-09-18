// SESSION 4A: Firebase Auth Domain Verification Endpoint
// Verifies Firebase Auth domain allowlist configuration for subdomain restructuring

const { getAuth, verifyAuthDomains, updateAuthorizedDomains } = require('./firebase-admin-config');
const firebaseAuthMiddleware = require('./firebase-auth-middleware');

exports.handler = async (event, context) => {
    // Require admin authentication for domain verification
    const authResult = await firebaseAuthMiddleware.authenticateRequest(event, {
        requireAuth: true,
        requireSubscription: false,
        requireAdmin: true,
        allowedMethods: ['GET', 'POST'],
        rateLimit: true
    });

    if (!authResult.success) {
        return authResult.response;
    }

    const { headers, user } = authResult;

    try {
        if (event.httpMethod === 'GET') {
            // Verify current domain configuration
            const domainStatus = await verifyAuthDomains();

            // Log admin verification access
            console.log('[ADMIN VERIFICATION] Firebase domains checked by:', {
                adminId: user.uid,
                adminEmail: user.email,
                timestamp: new Date().toISOString(),
                domainsComplete: domainStatus.isComplete
            });

            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    success: true,
                    verification: domainStatus,
                    timestamp: new Date().toISOString()
                })
            };

        } else if (event.httpMethod === 'POST') {
            // Update authorized domains
            const body = JSON.parse(event.body || '{}');
            const { domains, action } = body;

            if (action === 'add' && Array.isArray(domains)) {
                const updateResult = await updateAuthorizedDomains(domains);

                // Log admin domain update
                console.log('[ADMIN UPDATE] Firebase domains updated by:', {
                    adminId: user.uid,
                    adminEmail: user.email,
                    timestamp: new Date().toISOString(),
                    domainsAdded: updateResult.added || [],
                    success: updateResult.success
                });

                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({
                        success: updateResult.success,
                        result: updateResult,
                        timestamp: new Date().toISOString()
                    })
                };
            } else {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({
                        error: 'Invalid request body. Expected { action: "add", domains: [...] }'
                    })
                };
            }
        }

    } catch (error) {
        console.error('Firebase domain verification failed:', error);

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({
                error: 'Domain verification failed',
                message: error.message,
                timestamp: new Date().toISOString()
            })
        };
    }
};