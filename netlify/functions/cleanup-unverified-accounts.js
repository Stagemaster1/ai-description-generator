// Netlify Scheduled Function: Cleanup Unverified Accounts
// Runs daily at 3 AM UTC to delete Firebase Auth accounts that haven't verified their email within 48 hours
//
// Schedule configured in netlify.toml

const { getAuth } = require('./firebase-admin-config');

exports.handler = async (event, context) => {
    console.log('Starting unverified accounts cleanup job...');

    try {
        const auth = getAuth();
        const now = Date.now();
        const FORTY_EIGHT_HOURS = 48 * 60 * 60 * 1000; // 48 hours in milliseconds

        let deletedCount = 0;
        let errorCount = 0;
        let totalChecked = 0;

        // List all users (pagination handled automatically by Firebase Admin SDK)
        const listAllUsers = async (nextPageToken) => {
            const result = await auth.listUsers(1000, nextPageToken);

            for (const userRecord of result.users) {
                totalChecked++;

                // Check if email is not verified
                if (!userRecord.emailVerified) {
                    // Get account creation time
                    const createdAt = new Date(userRecord.metadata.creationTime).getTime();
                    const accountAge = now - createdAt;

                    // Delete if older than 48 hours
                    if (accountAge > FORTY_EIGHT_HOURS) {
                        try {
                            await auth.deleteUser(userRecord.uid);
                            deletedCount++;

                            console.log(`Deleted unverified account: ${userRecord.email} (UID: ${userRecord.uid}, Age: ${Math.round(accountAge / (60 * 60 * 1000))} hours)`);
                        } catch (deleteError) {
                            errorCount++;
                            console.error(`Failed to delete user ${userRecord.uid}:`, deleteError.message);
                        }
                    }
                }
            }

            // Continue pagination if there are more users
            if (result.pageToken) {
                await listAllUsers(result.pageToken);
            }
        };

        // Start listing users
        await listAllUsers();

        const summary = {
            success: true,
            totalChecked,
            deletedCount,
            errorCount,
            timestamp: new Date().toISOString(),
            message: `Cleanup completed: ${deletedCount} unverified accounts deleted, ${errorCount} errors`
        };

        console.log('Cleanup job completed:', summary);

        return {
            statusCode: 200,
            body: JSON.stringify(summary)
        };

    } catch (error) {
        console.error('Cleanup job failed:', error);

        return {
            statusCode: 500,
            body: JSON.stringify({
                success: false,
                error: error.message,
                timestamp: new Date().toISOString()
            })
        };
    }
};
