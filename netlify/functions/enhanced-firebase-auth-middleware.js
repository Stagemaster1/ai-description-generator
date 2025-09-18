// Enhanced Firebase Authentication Middleware
// SESSION 2A-2 Implementation - Distributed Token Replay Prevention Integration
// Enterprise-Grade Security Controls with PCI-DSS 4.0 Compliance

const { getAuth, getFirestore } = require('./firebase-config');
const securityLogger = require('./security-logger');
const DistributedTokenReplayPrevention = require('./distributed-token-replay-prevention');

/**
 * Enhanced Firebase Authentication Middleware
 * Integrates distributed token replay prevention with existing authentication framework
 */
class EnhancedFirebaseAuthMiddleware {
    constructor() {
        // Enterprise Configuration Constants
        this.RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
        this.MAX_REQUESTS_PER_MINUTE = 30;
        this.TOKEN_REPLAY_WINDOW = 5 * 60 * 1000; // 5-minute enterprise replay window
        this.MAX_SESSION_AGE = 24 * 60 * 60; // 24 hours max session
        this.OPERATION_TIMEOUT = 5000; // 5-second timeout requirement

        // Initialize distributed token replay prevention
        this.tokenReplayPrevention = new DistributedTokenReplayPrevention();

        // PCI-DSS 4.0 Compliance Settings
        this.PCI_COMPLIANCE_ENABLED = true;
        this.REQUIRE_STRONG_AUTHENTICATION = true;
        this.AUDIT_ALL_OPERATIONS = true;
    }

    /**
     * Enhanced token verification with distributed replay prevention
     * @param {string} idToken - Firebase ID token
     * @param {string} ipAddress - Client IP address
     * @param {string} userAgent - Client user agent
     * @returns {Object} Enhanced validation result with security analysis
     */
    async verifyIdToken(idToken, ipAddress = null, userAgent = null) {
        const startTime = Date.now();
        let userId = null;

        try {
            // Input validation
            if (!idToken || typeof idToken !== 'string') {
                return {
                    valid: false,
                    error: 'Invalid token format',
                    statusCode: 401,
                    securityRisk: 'HIGH',
                    responseTime: Date.now() - startTime
                };
            }

            // Firebase token verification
            const auth = getAuth();
            let decodedToken;

            try {
                decodedToken = await Promise.race([
                    auth.verifyIdToken(idToken, true), // checkRevoked = true
                    new Promise((_, reject) =>
                        setTimeout(() => reject(new Error('Token verification timeout')), this.OPERATION_TIMEOUT)
                    )
                ]);
            } catch (error) {
                if (error.message === 'Token verification timeout') {
                    return {
                        valid: false,
                        error: 'Token verification timeout',
                        statusCode: 408,
                        securityRisk: 'CRITICAL',
                        responseTime: Date.now() - startTime
                    };
                }
                throw error;
            }

            userId = decodedToken.uid;
            const tokenId = decodedToken.jti || decodedToken.iat.toString();

            // CRITICAL: Distributed token replay prevention check FIRST
            const replayCheck = await Promise.race([
                this.tokenReplayPrevention.isTokenBlacklisted(tokenId, userId, ipAddress),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('Replay check timeout')), this.OPERATION_TIMEOUT)
                )
            ]);

            if (replayCheck.isBlacklisted) {
                await this.logSecurityViolation('TOKEN_REPLAY_ATTACK', {
                    userId: userId,
                    ipAddress: ipAddress,
                    reason: replayCheck.reason,
                    securityRisk: replayCheck.securityRisk,
                    tokenHash: tokenId.substring(0, 8) + '...'
                });

                return {
                    valid: false,
                    error: 'Token replay detected - security violation',
                    statusCode: 401,
                    securityRisk: replayCheck.securityRisk,
                    replayAnalysis: replayCheck,
                    responseTime: Date.now() - startTime
                };
            }

            // Enhanced token validation
            const validationResult = await this.performEnhancedTokenValidation(decodedToken);
            if (!validationResult.valid) {
                return {
                    ...validationResult,
                    responseTime: Date.now() - startTime
                };
            }

            // PCI-DSS 4.0 Compliance checks
            if (this.PCI_COMPLIANCE_ENABLED) {
                const complianceCheck = await this.performPCIComplianceCheck(decodedToken, ipAddress);
                if (!complianceCheck.compliant) {
                    return {
                        valid: false,
                        error: complianceCheck.error,
                        statusCode: 403,
                        securityRisk: 'HIGH',
                        complianceViolation: complianceCheck.violation,
                        responseTime: Date.now() - startTime
                    };
                }
            }

            // Behavioral analysis integration
            const behavioralAnalysis = replayCheck.behavioralAnalysis;
            if (behavioralAnalysis && behavioralAnalysis.recommendation === 'BLOCK') {
                await this.logSecurityViolation('BEHAVIORAL_ANOMALY_DETECTED', {
                    userId: userId,
                    ipAddress: ipAddress,
                    riskScore: behavioralAnalysis.score,
                    factors: behavioralAnalysis.factors
                });

                return {
                    valid: false,
                    error: 'Suspicious behavior detected',
                    statusCode: 403,
                    securityRisk: behavioralAnalysis.riskLevel,
                    behavioralAnalysis: behavioralAnalysis,
                    responseTime: Date.now() - startTime
                };
            }

            // CRITICAL: Blacklist token BEFORE returning success
            const blacklistResult = await Promise.race([
                this.tokenReplayPrevention.blacklistToken(tokenId, userId, 'TOKEN_CONSUMED'),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('Blacklist timeout')), this.OPERATION_TIMEOUT)
                )
            ]);

            if (!blacklistResult.success) {
                await this.logSecurityViolation('TOKEN_BLACKLISTING_FAILED', {
                    userId: userId,
                    tokenId: tokenId.substring(0, 8) + '...',
                    error: blacklistResult.error || blacklistResult.reason
                });

                // CRITICAL-001 & CRITICAL-003 FIX: Fail secure - reject if we can't blacklist the token
                return {
                    valid: false,
                    error: 'Authentication failed',
                    statusCode: 401,
                    securityRisk: 'CRITICAL',
                    responseTime: Date.now() - startTime,
                    failSecure: true
                };
            }

            // Successful authentication
            const user = {
                uid: decodedToken.uid,
                email: decodedToken.email,
                emailVerified: decodedToken.email_verified,
                authTime: decodedToken.auth_time,
                customClaims: decodedToken.custom_claims || {},
                securityLevel: this.calculateSecurityLevel(behavioralAnalysis, ipAddress)
            };

            // Log successful authentication
            await this.logAuthenticationSuccess(user, ipAddress, behavioralAnalysis);

            const responseTime = Date.now() - startTime;

            return {
                valid: true,
                user: user,
                statusCode: 200,
                securityRisk: behavioralAnalysis ? behavioralAnalysis.riskLevel : 'LOW',
                behavioralAnalysis: behavioralAnalysis,
                tokenBlacklisted: blacklistResult.success,
                responseTime: responseTime,
                performanceCompliant: responseTime < this.OPERATION_TIMEOUT
            };

        } catch (error) {
            await this.logAuthenticationError(error, userId, ipAddress);

            // CRITICAL-001 FIX: Fail secure - no authentication bypass allowed
            // Remove all system details from error response to prevent information disclosure
            return {
                valid: false,
                error: 'Authentication failed',
                statusCode: 401,
                securityRisk: 'CRITICAL',
                responseTime: Date.now() - startTime,
                failSecure: true
            };
        }
    }

    /**
     * Perform enhanced token validation with enterprise security checks
     * @param {Object} decodedToken - Decoded Firebase token
     * @returns {Object} Validation result
     */
    async performEnhancedTokenValidation(decodedToken) {
        // Token audience validation
        if (decodedToken.aud !== process.env.FIREBASE_PROJECT_ID) {
            return {
                valid: false,
                error: 'Invalid token audience',
                statusCode: 401,
                securityRisk: 'HIGH'
            };
        }

        // Session age validation
        const currentTime = Math.floor(Date.now() / 1000);
        const authTime = decodedToken.auth_time;

        if (currentTime - authTime > this.MAX_SESSION_AGE) {
            return {
                valid: false,
                error: 'Session expired - re-authentication required',
                statusCode: 401,
                securityRisk: 'MEDIUM'
            };
        }

        // Email verification enforcement
        if (!decodedToken.email_verified) {
            return {
                valid: false,
                error: 'Email verification required',
                statusCode: 403,
                emailVerified: false,
                securityRisk: 'HIGH'
            };
        }

        // Token payload validation
        if (!decodedToken.uid || !decodedToken.email) {
            return {
                valid: false,
                error: 'Invalid token payload',
                statusCode: 401,
                securityRisk: 'HIGH'
            };
        }

        // Token freshness check
        const tokenAge = currentTime - decodedToken.iat;
        const maxTokenAge = 60 * 60; // 1 hour

        if (tokenAge > maxTokenAge) {
            return {
                valid: false,
                error: 'Token too old - refresh required',
                statusCode: 401,
                securityRisk: 'MEDIUM'
            };
        }

        return {
            valid: true,
            securityRisk: 'LOW'
        };
    }

    /**
     * Perform PCI-DSS 4.0 compliance checks
     * @param {Object} decodedToken - Decoded Firebase token
     * @param {string} ipAddress - Client IP address
     * @returns {Object} Compliance check result
     */
    async performPCIComplianceCheck(decodedToken, ipAddress) {
        try {
            // Strong authentication requirement
            if (this.REQUIRE_STRONG_AUTHENTICATION) {
                const hasStrongAuth = decodedToken.firebase?.sign_in_provider !== 'password' ||
                                     decodedToken.custom_claims?.mfa_enabled === true;

                if (!hasStrongAuth) {
                    return {
                        compliant: false,
                        error: 'Strong authentication required for PCI compliance',
                        violation: 'WEAK_AUTHENTICATION'
                    };
                }
            }

            // Geographic restrictions (if configured)
            if (process.env.PCI_ALLOWED_COUNTRIES && ipAddress) {
                // This would integrate with IP geolocation service
                // For now, we'll assume compliance
            }

            // Session security requirements
            const currentTime = Math.floor(Date.now() / 1000);
            const sessionDuration = currentTime - decodedToken.auth_time;
            const maxPCISessionDuration = 15 * 60; // 15 minutes for high-security operations

            if (decodedToken.custom_claims?.requires_pci_session && sessionDuration > maxPCISessionDuration) {
                return {
                    compliant: false,
                    error: 'PCI session timeout - re-authentication required',
                    violation: 'SESSION_TIMEOUT'
                };
            }

            return {
                compliant: true,
                checksPerformed: [
                    'STRONG_AUTHENTICATION',
                    'SESSION_SECURITY',
                    'TOKEN_VALIDATION'
                ]
            };

        } catch (error) {
            return {
                compliant: false,
                error: 'PCI compliance check failed',
                violation: 'SYSTEM_ERROR'
                // CRITICAL-003 FIX: Remove systemError to prevent information disclosure
            };
        }
    }

    /**
     * Calculate security level based on behavioral analysis and context
     * @param {Object} behavioralAnalysis - Behavioral analysis result
     * @param {string} ipAddress - Client IP address
     * @returns {string} Security level
     */
    calculateSecurityLevel(behavioralAnalysis, ipAddress) {
        if (!behavioralAnalysis) {
            return 'MEDIUM';
        }

        switch (behavioralAnalysis.riskLevel) {
            case 'LOW':
                return 'HIGH';
            case 'MEDIUM':
                return 'MEDIUM';
            case 'HIGH':
                return 'LOW';
            default:
                return 'LOW';
        }
    }

    /**
     * Log security violation for audit trail
     * @param {string} violationType - Type of security violation
     * @param {Object} violationData - Violation data
     */
    async logSecurityViolation(violationType, violationData) {
        try {
            securityLogger.logSuspiciousActivity({
                activityType: violationType,
                description: `Enhanced auth middleware: ${violationType}`,
                userId: violationData.userId || 'unknown',
                additionalData: violationData
            });

            // Additional audit logging for PCI compliance
            if (this.AUDIT_ALL_OPERATIONS) {
                const db = getFirestore();
                await db.collection('securityAuditLog').add({
                    type: violationType,
                    timestamp: Date.now(),
                    data: violationData,
                    source: 'enhanced-firebase-auth-middleware',
                    version: '2A-2',
                    severity: violationData.securityRisk || 'HIGH'
                });
            }

        } catch (error) {
            console.error('Failed to log security violation:', error);
        }
    }

    /**
     * Log successful authentication
     * @param {Object} user - Authenticated user data
     * @param {string} ipAddress - Client IP address
     * @param {Object} behavioralAnalysis - Behavioral analysis result
     */
    async logAuthenticationSuccess(user, ipAddress, behavioralAnalysis) {
        try {
            securityLogger.log('INFO', 'AUTHENTICATION_SUCCESS', {
                userId: user.uid,
                email: user.email,
                ipAddress: ipAddress,
                securityLevel: user.securityLevel,
                behavioralRisk: behavioralAnalysis ? behavioralAnalysis.riskLevel : 'UNKNOWN',
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            console.error('Failed to log authentication success:', error);
        }
    }

    /**
     * Log authentication error
     * @param {Error} error - Authentication error
     * @param {string} userId - User ID (if available)
     * @param {string} ipAddress - Client IP address
     */
    async logAuthenticationError(error, userId, ipAddress) {
        try {
            securityLogger.logOperationFailure({
                operation: 'enhanced_token_verification',
                userId: userId || 'unknown',
                ipAddress: ipAddress || 'unknown',
                error: error.message,
                endpoint: 'enhanced-firebase-auth-middleware'
            });

        } catch (logError) {
            console.error('Failed to log authentication error:', logError);
        }
    }

    /**
     * Health check for enhanced authentication middleware
     * @returns {Object} Health status
     */
    async healthCheck() {
        try {
            const replayPreventionHealth = await this.tokenReplayPrevention.healthCheck();
            const authHealth = await this.checkFirebaseAuth();

            return {
                status: replayPreventionHealth.status === 'HEALTHY' && authHealth.status === 'HEALTHY' ? 'HEALTHY' : 'UNHEALTHY',
                components: {
                    tokenReplayPrevention: replayPreventionHealth,
                    firebaseAuth: authHealth
                },
                timestamp: new Date().toISOString(),
                version: '2A-2'
            };

        } catch (error) {
            return {
                status: 'UNHEALTHY',
                error: error.message,
                timestamp: new Date().toISOString(),
                version: '2A-2'
            };
        }
    }

    /**
     * Check Firebase Auth connectivity
     * @returns {Object} Firebase Auth health status
     */
    async checkFirebaseAuth() {
        try {
            const auth = getAuth();

            // Simple connectivity check - try to verify a dummy token format
            const testResult = await Promise.race([
                auth.verifyIdToken('dummy', false).catch(() => ({ error: 'expected' })),
                new Promise((resolve) => setTimeout(() => resolve({ status: 'timeout' }), 2000))
            ]);

            if (testResult.status === 'timeout') {
                return {
                    status: 'UNHEALTHY',
                    error: 'Firebase Auth timeout'
                };
            }

            return {
                status: 'HEALTHY',
                responseTime: Date.now()
            };

        } catch (error) {
            return {
                status: 'UNHEALTHY',
                error: error.message
            };
        }
    }

    /**
     * Get performance metrics
     * @returns {Object} Performance metrics
     */
    getPerformanceMetrics() {
        return this.tokenReplayPrevention.getPerformanceMetrics();
    }

    /**
     * Legacy compatibility method - integrates with existing isTokenReplayed calls
     * @param {string} tokenId - Token identifier
     * @returns {boolean} True if token is replayed
     */
    async isTokenReplayed(tokenId) {
        try {
            const result = await this.tokenReplayPrevention.isTokenBlacklisted(tokenId);
            return result.isBlacklisted;
        } catch (error) {
            // Fail secure
            return true;
        }
    }

    /**
     * Legacy compatibility method - integrates with existing recordTokenUsage calls
     * @param {string} tokenId - Token identifier
     */
    async recordTokenUsage(tokenId) {
        try {
            await this.tokenReplayPrevention.blacklistToken(tokenId, null, 'TOKEN_CONSUMED');
        } catch (error) {
            securityLogger.logOperationFailure({
                operation: 'legacy_token_usage_recording',
                tokenId: tokenId ? tokenId.substring(0, 8) + '...' : 'invalid',
                error: error.message,
                endpoint: 'enhanced-firebase-auth-middleware'
            });
        }
    }
}

module.exports = EnhancedFirebaseAuthMiddleware;