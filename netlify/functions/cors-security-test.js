#!/usr/bin/env node

/**
 * CORS Security Hardening Verification Test
 * SESSION 3B Implementation - Verifies that unknown origins are rejected
 */

const crossDomainValidator = require('./Github_Version/netlify/functions/cross-domain-validator');

async function testCORSSecurityHardening() {
    console.log('🛡️  CORS Security Hardening Verification Test');
    console.log('=' .repeat(50));

    const testCases = [
        {
            name: 'Valid Origin - www.soltecsol.com',
            origin: 'https://www.soltecsol.com',
            expected: 'valid',
        },
        {
            name: 'Valid Origin - ai-generator.soltecsol.com',
            origin: 'https://ai-generator.soltecsol.com',
            expected: 'valid',
        },
        {
            name: 'Invalid Origin - malicious.com',
            origin: 'https://malicious.com',
            expected: 'rejected',
        },
        {
            name: 'Invalid Origin - evil.soltecsol.com',
            origin: 'https://evil.soltecsol.com',
            expected: 'rejected',
        },
        {
            name: 'No Origin (server-to-server)',
            origin: '',
            expected: 'valid',
        }
    ];

    let passed = 0;
    let failed = 0;

    for (const testCase of testCases) {
        console.log(`\nTesting: ${testCase.name}`);
        console.log(`Origin: ${testCase.origin || '(empty)'}`);

        try {
            const result = crossDomainValidator.validateOrigin(testCase.origin);

            if (testCase.expected === 'valid') {
                if (result.valid && result.allowedOrigin) {
                    console.log(`✅ PASS: Origin correctly accepted`);
                    console.log(`   Allowed Origin: ${result.allowedOrigin}`);
                    passed++;
                } else {
                    console.log(`❌ FAIL: Valid origin was rejected`);
                    console.log(`   Result: ${JSON.stringify(result)}`);
                    failed++;
                }
            } else if (testCase.expected === 'rejected') {
                if (!result.valid || result.allowedOrigin === null) {
                    console.log(`✅ PASS: Origin correctly rejected`);
                    console.log(`   Result: ${JSON.stringify(result)}`);
                    passed++;
                } else {
                    console.log(`❌ FAIL: Invalid origin was accepted (security vulnerability!)`);
                    console.log(`   Result: ${JSON.stringify(result)}`);
                    failed++;
                }
            }
        } catch (error) {
            console.log(`❌ ERROR: ${error.message}`);
            failed++;
        }
    }

    console.log('\n' + '=' .repeat(50));
    console.log(`📊 Test Results: ${passed} passed, ${failed} failed`);

    if (failed === 0) {
        console.log('🎉 All CORS security tests passed! Unknown origins are properly rejected.');
        return true;
    } else {
        console.log('⚠️  Some CORS security tests failed. Review the implementation.');
        return false;
    }
}

// Run the test
if (require.main === module) {
    testCORSSecurityHardening()
        .then(success => {
            process.exit(success ? 0 : 1);
        })
        .catch(error => {
            console.error('Test execution failed:', error);
            process.exit(1);
        });
}

module.exports = { testCORSSecurityHardening };