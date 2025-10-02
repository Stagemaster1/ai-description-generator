// Shared Pricing Data for SolTecSol AI Description Generator
// Used by both subscriptions.html and pricing.html

window.pricingData = {
    starter: {
        name: 'Starter',
        monthlyPrice: 22.99,
        annualPrice: 249.99,
        features: [
            '50 descriptions/month',
            '5 brand tones',
            'SEO optimization',
            'First month free'
        ],
        badge: 'First Month Free',
        buttonColor: 'green', // #10b981
        paypalMonthlyPlanId: 'STARTER_MONTHLY_PLAN_ID', // Replace with actual PayPal plan ID
        paypalAnnualPlanId: 'STARTER_ANNUAL_PLAN_ID'   // Replace with actual PayPal plan ID
    },
    professional: {
        name: 'Professional',
        monthlyPrice: 79.99,
        annualPrice: 929.99,
        features: [
            '200 descriptions/month',
            'All brand tones',
            'Advanced SEO',
            'Priority support'
        ],
        badge: 'Most Popular',
        buttonColor: 'blue', // #3b82f6
        paypalMonthlyPlanId: 'PROFESSIONAL_MONTHLY_PLAN_ID', // Replace with actual PayPal plan ID
        paypalAnnualPlanId: 'PROFESSIONAL_ANNUAL_PLAN_ID'    // Replace with actual PayPal plan ID
    },
    enterprise: {
        name: 'Enterprise',
        monthlyPrice: 299.99,
        annualPrice: 3500.00,
        features: [
            'Unlimited descriptions',
            'All brand tones',
            'Advanced SEO',
            'Dedicated support'
        ],
        badge: 'Premium',
        buttonColor: 'gold', // #fbbf24
        paypalMonthlyPlanId: 'ENTERPRISE_MONTHLY_PLAN_ID', // Replace with actual PayPal plan ID
        paypalAnnualPlanId: 'ENTERPRISE_ANNUAL_PLAN_ID'    // Replace with actual PayPal plan ID
    }
};

// Color mappings for button glows
window.buttonColors = {
    green: {
        main: '#10b981',
        glow: 'rgba(16, 185, 129, 0.5)'
    },
    blue: {
        main: '#3b82f6',
        glow: 'rgba(59, 130, 246, 0.5)'
    },
    gold: {
        main: '#fbbf24',
        glow: 'rgba(251, 191, 36, 0.5)'
    }
};

// Data is now available globally via window.pricingData and window.buttonColors
