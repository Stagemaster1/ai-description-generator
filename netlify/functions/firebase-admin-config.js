// Firebase Admin SDK Configuration - Core Infrastructure
// This file initializes Firebase Admin SDK and exports auth/firestore instances
// SESSION 4A: Firebase Auth domain allowlist support implementation

const admin = require('firebase-admin');

// Global Firebase Admin instance
let firebaseAdmin = null;
let authInstance = null;
let firestoreInstance = null;

/**
 * Initialize Firebase Admin SDK with environment variables
 * @returns {Object} Firebase admin instance
 */
function initializeFirebaseAdmin() {
    if (firebaseAdmin) {
        return firebaseAdmin;
    }

    try {
        // Validate required environment variables
        const requiredEnvVars = [
            'FIREBASE_PROJECT_ID',
            'FIREBASE_PRIVATE_KEY',
            'FIREBASE_CLIENT_EMAIL'
        ];

        const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
        if (missingVars.length > 0) {
            throw new Error(`Missing required Firebase environment variables: ${missingVars.join(', ')}`);
        }

        // Parse private key from environment (handle potential JSON encoding)
        let privateKey = process.env.FIREBASE_PRIVATE_KEY;
        if (privateKey.startsWith('"') && privateKey.endsWith('"')) {
            privateKey = JSON.parse(privateKey);
        }
        privateKey = privateKey.replace(/\\n/g, '\n');

        // Firebase Admin SDK configuration
        const serviceAccount = {
            type: "service_account",
            project_id: process.env.FIREBASE_PROJECT_ID,
            private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
            private_key: privateKey,
            client_email: process.env.FIREBASE_CLIENT_EMAIL,
            client_id: process.env.FIREBASE_CLIENT_ID,
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
            client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
        };

        // Initialize Firebase Admin
        firebaseAdmin = admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            projectId: process.env.FIREBASE_PROJECT_ID,
            // SESSION 4A: Configure authorized domains for auth operations
            authDomain: `${process.env.FIREBASE_PROJECT_ID}.firebaseapp.com`
        });

        console.log('Firebase Admin SDK initialized successfully');
        return firebaseAdmin;

    } catch (error) {
        console.error('Firebase Admin SDK initialization failed:', error);
        throw new Error(`Firebase initialization failed: ${error.message}`);
    }
}

/**
 * Get Firebase Auth instance
 * @returns {Object} Firebase Auth instance
 */
function getAuth() {
    if (!authInstance) {
        const app = initializeFirebaseAdmin();
        authInstance = admin.auth(app);
    }
    return authInstance;
}

/**
 * Get Firestore instance
 * @returns {Object} Firestore instance
 */
function getFirestore() {
    if (!firestoreInstance) {
        const app = initializeFirebaseAdmin();
        firestoreInstance = admin.firestore(app);

        // Configure Firestore settings
        firestoreInstance.settings({
            timestampsInSnapshots: true,
            ignoreUndefinedProperties: true
        });
    }
    return firestoreInstance;
}

/**
 * SESSION 4A: Verify Firebase Auth domain configuration
 * @returns {Object} Domain configuration status
 */
async function verifyAuthDomains() {
    try {
        const auth = getAuth();
        const config = await auth.getProjectConfig();

        // Expected authorized domains for SolTecSol subdomains
        const expectedDomains = [
            `${process.env.FIREBASE_PROJECT_ID}.firebaseapp.com`,
            'app.soltecsol.com',
            'www.soltecsol.com',
            'subscriptions.soltecsol.com',
            'signup.soltecsol.com',
            'soltecsol.com'
        ];

        const authorizedDomains = config.authorizedDomains || [];
        const missingDomains = expectedDomains.filter(domain =>
            !authorizedDomains.includes(domain)
        );

        return {
            configured: authorizedDomains,
            expected: expectedDomains,
            missing: missingDomains,
            isComplete: missingDomains.length === 0
        };

    } catch (error) {
        console.error('Firebase Auth domain verification failed:', error);
        return {
            error: error.message,
            isComplete: false
        };
    }
}

/**
 * SESSION 4A: Update Firebase Auth authorized domains
 * @param {Array} domains - List of domains to authorize
 * @returns {Object} Update result
 */
async function updateAuthorizedDomains(domains) {
    try {
        const auth = getAuth();

        // Get current configuration
        const currentConfig = await auth.getProjectConfig();

        // Merge existing domains with new ones (remove duplicates)
        const existingDomains = currentConfig.authorizedDomains || [];
        const allDomains = [...new Set([...existingDomains, ...domains])];

        // Update project configuration
        await auth.updateProjectConfig({
            authorizedDomains: allDomains
        });

        console.log('Firebase Auth authorized domains updated:', allDomains);

        return {
            success: true,
            authorizedDomains: allDomains,
            added: domains.filter(domain => !existingDomains.includes(domain))
        };

    } catch (error) {
        console.error('Firebase Auth domain update failed:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Export functions for use by other modules
module.exports = {
    initializeFirebaseAdmin,
    getAuth,
    getFirestore,
    verifyAuthDomains,
    updateAuthorizedDomains,
    admin // Export admin for direct access if needed
};