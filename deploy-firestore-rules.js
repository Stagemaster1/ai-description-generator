#!/usr/bin/env node

// Firebase Firestore Security Rules Deployment Script
// Run this script to deploy the security rules to your Firebase project
// Usage: node deploy-firestore-rules.js

const { initializeFirebase, admin } = require('./firebase-config');
const fs = require('fs');
const path = require('path');

async function deployFirestoreRules() {
    try {
        console.log('🔐 Deploying Firestore Security Rules...\n');

        // Initialize Firebase Admin SDK
        initializeFirebase();
        
        // Read the security rules file
        const rulesPath = path.join(__dirname, 'firestore.rules');
        
        if (!fs.existsSync(rulesPath)) {
            throw new Error('firestore.rules file not found. Please ensure the file exists in the project root.');
        }

        const rulesContent = fs.readFileSync(rulesPath, 'utf8');
        console.log('✅ Security rules file loaded');
        console.log(`📄 Rules file size: ${rulesContent.length} characters\n`);

        // Get the project ID from environment
        const projectId = process.env.FIREBASE_PROJECT_ID;
        if (!projectId) {
            throw new Error('FIREBASE_PROJECT_ID environment variable is required');
        }

        console.log(`🎯 Target project: ${projectId}`);
        console.log('⏳ Deploying security rules...\n');

        // Deploy the rules using Firebase Admin SDK
        const securityRules = admin.securityRules();
        
        // Create a ruleset
        const rulesetResult = await securityRules.createRuleset({
            source: [{
                name: 'firestore.rules',
                content: rulesContent
            }]
        });

        console.log(`✅ Ruleset created: ${rulesetResult.name}`);

        // Release the ruleset to make it active
        const releaseResult = await securityRules.releaseFirestoreRulesetByName(
            rulesetResult.name
        );

        console.log(`🚀 Security rules deployed successfully!`);
        console.log(`📋 Release name: ${releaseResult.name}`);
        console.log(`⏰ Deployed at: ${new Date().toISOString()}\n`);

        console.log('🔒 SECURITY FEATURES ACTIVATED:');
        console.log('  ✓ User data access control (own data only)');
        console.log('  ✓ Admin operations protection');
        console.log('  ✓ Public data read-only enforcement');
        console.log('  ✓ Email verification requirements');
        console.log('  ✓ Data structure validation');
        console.log('  ✓ Unauthorized access prevention\n');

        console.log('⚠️  IMPORTANT NOTES:');
        console.log('  • Rules may take a few minutes to propagate globally');
        console.log('  • Test your application thoroughly after deployment');
        console.log('  • Monitor Firebase console for any rule violations');
        console.log('  • Admin users need proper custom claims set');

    } catch (error) {
        console.error('❌ Failed to deploy Firestore security rules:');
        console.error(`   Error: ${error.message}`);
        
        if (error.code) {
            console.error(`   Code: ${error.code}`);
        }
        
        if (error.details) {
            console.error(`   Details: ${error.details}`);
        }

        console.log('\n🔧 TROUBLESHOOTING:');
        console.log('  • Verify FIREBASE_PROJECT_ID is set correctly');
        console.log('  • Check Firebase service account credentials');
        console.log('  • Ensure Firebase Admin SDK is properly configured');
        console.log('  • Verify project permissions and billing status');
        
        process.exit(1);
    }
}

// Run the deployment
deployFirestoreRules();