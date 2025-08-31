# Firebase Setup Guide - Step by Step

## Overview
Your app now uses Firebase for secure user database storage instead of in-memory storage. This guide will walk you through setting up Firebase from your existing account.

## Step 1: Access Your Firebase Console

1. Go to [Firebase Console](https://console.firebase.google.com)
2. Sign in with your Google account (the one with your old Firebase account)
3. You should see any existing projects, or you can create a new one

## Step 2: Create or Select Firebase Project

### If Creating New Project:
1. Click "Create a project" 
2. Project name: **"soltecsol-ai-generator"** (or your preferred name)
3. **Disable Google Analytics** (not needed for this app)
4. Click "Create project"

### If Using Existing Project:
1. Click on your existing project
2. We'll configure it for this app

## Step 3: Set Up Firestore Database

1. In your Firebase project, go to **"Firestore Database"** in left menu
2. Click **"Create database"**
3. **Select "Start in production mode"** (we'll set proper security rules)
4. Choose your preferred location (closest to your users)
5. Click **"Done"**

## Step 4: Create Service Account Credentials

1. Go to **Project Settings** (gear icon → Project settings)
2. Click the **"Service accounts"** tab
3. Click **"Generate new private key"**
4. **IMPORTANT**: Download and save the JSON file securely
5. **DO NOT** commit this file to your repository

## Step 5: Set Up Security Rules

In Firestore → Rules, replace the default rules with:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can only read/write their own data
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Admin logs - admin access only
    match /admin_logs/{document} {
      allow read, write: if false; // Only server-side access
    }
    
    // Payment logs - no client access
    match /payments/{document} {
      allow read, write: if false; // Only server-side access
    }
    
    // Deleted users archive - no client access
    match /deleted_users/{document} {
      allow read, write: if false; // Only server-side access
    }
  }
}
```

## Step 6: Configure Netlify Environment Variables

In your Netlify dashboard (Site settings → Environment variables), add these variables using the JSON file you downloaded:

### Required Firebase Variables:
```
FIREBASE_PROJECT_ID=your-project-id-from-json
FIREBASE_PRIVATE_KEY_ID=private_key_id-from-json
FIREBASE_PRIVATE_KEY=the-entire-private-key-from-json (keep the quotes and \\n)
FIREBASE_CLIENT_EMAIL=client_email-from-json
FIREBASE_CLIENT_ID=client_id-from-json
FIREBASE_CLIENT_CERT_URL=client_x509_cert_url-from-json
```

### Security Variables:
```
ADMIN_API_KEY=create-a-strong-random-key-here
PAYPAL_WEBHOOK_ID=get-from-paypal-developer-dashboard
```

## Step 7: Update PayPal Webhook URL

1. Go to [PayPal Developer Dashboard](https://developer.paypal.com)
2. Go to your app → Webhooks
3. **Add new webhook URL**: `https://your-domain.com/.netlify/functions/paypal-webhook`
4. **Select these events**:
   - BILLING.SUBSCRIPTION.CREATED
   - BILLING.SUBSCRIPTION.ACTIVATED
   - BILLING.SUBSCRIPTION.CANCELLED
   - BILLING.SUBSCRIPTION.SUSPENDED
   - PAYMENT.SALE.COMPLETED

## Step 8: Test the Integration

1. Deploy your updated code: `npm run deploy`
2. Test user creation by trying to use the app
3. Check Firestore console to see if user data appears
4. Test PayPal subscription to verify webhook integration

## Database Collections Created:

Your app will automatically create these Firestore collections:

- **`users`** - User accounts and subscription data
- **`admin_logs`** - Admin activity logging  
- **`payments`** - Payment records
- **`deleted_users`** - Archive of deleted user data

## Admin Panel Access

Once set up, you can access admin functions at:
`https://your-domain.com/.netlify/functions/firebase-admin`

**Authentication**: Use `Authorization: Bearer YOUR_ADMIN_API_KEY` header

## Security Features Implemented:

✅ **Server-side only Firebase access** (no client-side keys)  
✅ **Role-based admin authentication**  
✅ **All admin actions logged** with timestamps  
✅ **PayPal webhook signature verification**  
✅ **Proper Firestore security rules**  
✅ **Sensitive data protection**

## Troubleshooting:

- **"Firebase not initialized"**: Check environment variables in Netlify
- **"Permission denied"**: Verify Firestore security rules  
- **"Webhook not working"**: Check PayPal webhook URL and events
- **"Admin access denied"**: Verify ADMIN_API_KEY is set correctly

Your user database is now secure and properly integrated with PayPal subscriptions!