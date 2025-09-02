// User Authentication API
// Handles login, signup, and password verification

const { getFirestore } = require('../../firebase-config');
const crypto = require('crypto');

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
    const { action, email, password } = JSON.parse(event.body || '{}');

    if (!action || !email) {
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
      case 'login':
        return await handleLogin(db, email, password, headers);
      
      case 'signup':
        return await handleSignup(db, email, password, headers);
      
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
    console.error('User auth API error:', error);
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

// Handle user login
async function handleLogin(db, email, password, headers) {
  if (!password) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ 
        success: false,
        message: 'Password is required' 
      })
    };
  }

  try {
    // Find user by email
    const usersSnapshot = await db.collection('users').where('email', '==', email.toLowerCase()).get();
    
    if (usersSnapshot.empty) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          success: false,
          message: 'Invalid email or password' 
        })
      };
    }

    const userDoc = usersSnapshot.docs[0];
    const userData = userDoc.data();

    // Check if user has a password (existing subscribers might not have one)
    if (!userData.password) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          success: false,
          message: 'Please use Sign Up to set a password for your account' 
        })
      };
    }

    // Verify password
    const passwordHash = hashPassword(password);
    if (userData.password !== passwordHash) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          success: false,
          message: 'Invalid email or password' 
        })
      };
    }

    // Update last login
    await userDoc.ref.update({
      lastLogin: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });

    // Return user data (without password)
    const userResponse = {
      id: userDoc.id,
      email: userData.email,
      subscriptionType: userData.subscriptionType || 'free',
      maxUsage: userData.maxUsage || 5,
      monthlyUsage: userData.monthlyUsage || 0,
      isSubscribed: userData.isSubscribed || false,
      manuallyUnlocked: userData.manuallyUnlocked || false
    };

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: 'Login successful',
        user: userResponse 
      })
    };

  } catch (error) {
    console.error('Login error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        success: false,
        message: 'Login failed' 
      })
    };
  }
}

// Handle user signup
async function handleSignup(db, email, password, headers) {
  if (!password) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ 
        success: false,
        message: 'Password is required' 
      })
    };
  }

  if (password.length < 6) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ 
        success: false,
        message: 'Password must be at least 6 characters long' 
      })
    };
  }

  try {
    // Check if user already exists
    const existingUsersSnapshot = await db.collection('users').where('email', '==', email.toLowerCase()).get();
    
    if (!existingUsersSnapshot.empty) {
      const existingUserData = existingUsersSnapshot.docs[0].data();
      
      // If user exists but has no password (existing subscriber), allow them to set password
      if (!existingUserData.password) {
        const userDoc = existingUsersSnapshot.docs[0];
        const passwordHash = hashPassword(password);
        
        await userDoc.ref.update({
          password: passwordHash,
          lastLogin: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          passwordSetAt: new Date().toISOString()
        });

        // Return updated user data
        const updatedUserData = await userDoc.ref.get();
        const userData = updatedUserData.data();
        
        const userResponse = {
          id: userDoc.id,
          email: userData.email,
          subscriptionType: userData.subscriptionType || 'free',
          maxUsage: userData.maxUsage || 5,
          monthlyUsage: userData.monthlyUsage || 0,
          isSubscribed: userData.isSubscribed || false,
          manuallyUnlocked: userData.manuallyUnlocked || false
        };

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({ 
            success: true,
            message: 'Password set successfully for existing account',
            user: userResponse 
          })
        };
      } else {
        return {
          statusCode: 409,
          headers,
          body: JSON.stringify({ 
            success: false,
            message: 'Account already exists. Please login instead.' 
          })
        };
      }
    }

    // Create new user
    const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;
    const passwordHash = hashPassword(password);
    
    const newUser = {
      id: userId,
      email: email.toLowerCase(),
      password: passwordHash,
      subscriptionType: 'free',
      maxUsage: 5,
      monthlyUsage: 0,
      isSubscribed: false,
      manuallyUnlocked: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
      signupMethod: 'email_password'
    };

    await db.collection('users').doc(userId).set(newUser);

    // Return user data (without password)
    const userResponse = {
      id: userId,
      email: newUser.email,
      subscriptionType: newUser.subscriptionType,
      maxUsage: newUser.maxUsage,
      monthlyUsage: newUser.monthlyUsage,
      isSubscribed: newUser.isSubscribed,
      manuallyUnlocked: newUser.manuallyUnlocked
    };

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: 'Account created successfully',
        user: userResponse 
      })
    };

  } catch (error) {
    console.error('Signup error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        success: false,
        message: 'Account creation failed' 
      })
    };
  }
}

// Simple password hashing (for production, use bcrypt or similar)
function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'soltecsol_salt_2024').digest('hex');
}