// Netlify scheduled function to cleanup expired trial users from Firestore
// Runs daily to delete trial users from Users collection after 6 months
// Scheduled via Netlify UI: Site Settings → Functions → Scheduled functions

const admin = require('firebase-admin');

// Initialize Firebase Admin (singleton pattern)
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_ADMIN_PROJECT_ID,
        clientEmail: process.env.FIREBASE_ADMIN_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_ADMIN_PRIVATE_KEY.replace(/\\n/g, '\n')
      })
    });
    console.log('Firebase Admin initialized successfully for cleanup');
  } catch (error) {
    console.error('Firebase Admin initialization error:', error);
  }
}

exports.handler = async (event, context) => {
  try {
    console.log('Starting cleanup of expired trial users...');

    const now = admin.firestore.Timestamp.now();
    const db = admin.firestore();

    // Query Users collection for expired trials
    const expiredUsersQuery = await db.collection('Users')
      .where('expiresAt', '<=', now)
      .get();

    if (expiredUsersQuery.empty) {
      console.log('No expired trial users found');
      return {
        statusCode: 200,
        body: JSON.stringify({
          success: true,
          message: 'No expired users to clean up',
          deletedCount: 0
        })
      };
    }

    console.log(`Found ${expiredUsersQuery.size} expired trial users to delete`);

    // Delete expired users in batch
    const batch = db.batch();
    const deletedUsers = [];

    expiredUsersQuery.forEach((doc) => {
      const userData = doc.data();
      deletedUsers.push({
        userId: doc.id,
        email: userData.email,
        createdAt: userData.createdAt,
        expiresAt: userData.expiresAt
      });
      batch.delete(doc.ref);
    });

    // Commit batch deletion
    await batch.commit();

    console.log(`Successfully deleted ${deletedUsers.length} expired trial users`);

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        message: `Cleaned up ${deletedUsers.length} expired trial users`,
        deletedCount: deletedUsers.length,
        deletedUsers: deletedUsers
      })
    };

  } catch (error) {
    console.error('Error during cleanup:', error);

    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Cleanup failed',
        message: error.message
      })
    };
  }
};
