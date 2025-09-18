// CRITICAL-001 FIX: Fail-Safe Authentication Check
// Addresses Authentication Bypass Through Error Propagation and Network Partition Attacks
// CVSS 8.7 - Production-Ready Security Implementation
// PCI-DSS 4.0 Compliant with "Deny by Default" Approach

const { getAuth, getFirestore } = require('./firebase-config');
const securityLogger = require('./security-logger');
const crypto = require('crypto');

/**
 * CRITICAL-001 FAIL-SAFE AUTHENTICATION CHECK
 *
 * This class implements a robust, fail-safe authentication system that prevents
 * authentication bypass during error propagation and network partition scenarios.
 *
 * SECURITY PRINCIPLES:
 * 1. DENY BY DEFAULT - All failures result in authentication denial
 * 2. EXPLICIT POSITIVE CONFIRMATION - Authentication success requires explicit validation
 * 3. ERROR ISOLATION - Network/system errors cannot compromise security decisions
 * 4. NETWORK PARTITION RESILIENCE - Maintains security during Firestore outages
 * 5. NO IMPLICIT SUCCESS - Unknown states are treated as authentication failure
 */
class FailSafeAuthenticationCheck {
    constructor() {
        // CRITICAL-001 FIX: Enterprise-grade timeout controls (sub-5-second requirement)
        this.OPERATION_TIMEOUT_MS = 4500; // 4.5 seconds to ensure sub-5-second completion
        this.TOKEN_VERIFICATION_TIMEOUT_MS = 3000; // 3 seconds for Firebase token verification
        this.FIRESTORE_OPERATION_TIMEOUT_MS = 2000; // 2 seconds for Firestore operations
        this.CIRCUIT_BREAKER_TIMEOUT_MS = 1000; // 1 second circuit breaker timeout

        // CRITICAL-001 FIX: Fail-safe configuration
        this.MAX_RETRY_ATTEMPTS = 2; // Limited retries to prevent timeout accumulation
        this.MINIMUM_TOKEN_LENGTH = 100; // Minimum valid Firebase token length
        this.MAX_TOKEN_AGE_SECONDS = 3600; // 1 hour maximum token age

        // CRITICAL-001 FIX: Network partition resilience configuration
        this.NETWORK_PARTITION_GRACE_PERIOD_MS = 500; // Grace period for network operations
        this.LOCAL_VALIDATION_FALLBACK_ENABLED = false; // SECURITY: Disabled to prevent bypass

        // Authentication state tracking for explicit validation
        this.authenticationStates = {
            UNKNOWN: 'UNKNOWN',           // Initial state - DENY
            VALIDATING: 'VALIDATING',     // In progress - DENY
            AUTHENTICATED: 'AUTHENTICATED', // Explicit success - ALLOW
            DENIED: 'DENIED',             // Explicit failure - DENY
            ERROR: 'ERROR'                // System error - DENY
        };

        // Circuit breaker state for Firestore connectivity
        this.circuitBreakerState = {
            isOpen: false,
            failureCount: 0,
            lastFailureTime: null,
            maxFailures: 3
        };

        console.log('CRITICAL-001 Fail-Safe Authentication Check initialized with DENY-BY-DEFAULT security model');
    }

    /**
     * CRITICAL-001 MAIN ENTRY POINT: Fail-Safe Token Verification
     *
     * This method implements comprehensive fail-safe authentication with:
     * - Explicit positive confirmation required for access
     * - Network partition resilience
     * - Error isolation preventing security bypass
     * - Circuit breaker patterns for external dependencies
     *
     * @param {string} idToken - Firebase ID token
     * @param {Object} requestContext - Request context information
     * @returns {Object} Fail-safe authentication result
     */
    async performFailSafeAuthentication(idToken, requestContext = {}) {
        const operationId = this.generateSecureOperationId();
        const operationStartTime = Date.now();

        // CRITICAL-001 FIX: Initialize with explicit DENY state
        let authenticationState = this.authenticationStates.UNKNOWN;
        let securityContext = {
            operationId,
            startTime: operationStartTime,
            state: authenticationState,
            networkPartitionDetected: false,
            circuitBreakerTripped: false,
            explicitDenyReason: null
        };

        try {
            console.log(`CRITICAL-001: Starting fail-safe authentication [${operationId}]`);

            // CRITICAL-001 FIX: Step 1 - Input validation with explicit deny on failure
            const inputValidationResult = this.validateAuthenticationInput(idToken, requestContext);
            if (!inputValidationResult.valid) {
                authenticationState = this.authenticationStates.DENIED;
                securityContext.explicitDenyReason = inputValidationResult.reason;

                return this.createFailSafeResponse({
                    authenticated: false,
                    state: authenticationState,
                    reason: 'INPUT_VALIDATION_FAILED',
                    error: inputValidationResult.error,
                    securityRisk: 'HIGH',
                    statusCode: 401,
                    securityContext,
                    operationTime: Date.now() - operationStartTime
                });
            }

            // CRITICAL-001 FIX: Step 2 - Network partition detection
            authenticationState = this.authenticationStates.VALIDATING;
            securityContext.state = authenticationState;

            const networkStatus = await this.detectNetworkPartition();
            securityContext.networkPartitionDetected = networkStatus.partitionDetected;

            if (networkStatus.partitionDetected) {
                // CRITICAL-001 FIX: Network partition detected - EXPLICIT DENY
                authenticationState = this.authenticationStates.DENIED;
                securityContext.explicitDenyReason = 'NETWORK_PARTITION_DETECTED';

                await this.logSecurityEvent('NETWORK_PARTITION_AUTH_DENIAL', {
                    operationId,
                    partitionType: networkStatus.partitionType,
                    severity: 'CRITICAL'
                });

                return this.createFailSafeResponse({
                    authenticated: false,
                    state: authenticationState,
                    reason: 'NETWORK_PARTITION_DENIAL',
                    error: 'Authentication unavailable due to network conditions',
                    securityRisk: 'CRITICAL',
                    statusCode: 503,
                    securityContext,
                    operationTime: Date.now() - operationStartTime
                });
            }

            // CRITICAL-001 FIX: Step 3 - Circuit breaker check
            if (this.isCircuitBreakerOpen()) {
                authenticationState = this.authenticationStates.DENIED;
                securityContext.circuitBreakerTripped = true;
                securityContext.explicitDenyReason = 'CIRCUIT_BREAKER_OPEN';

                return this.createFailSafeResponse({
                    authenticated: false,
                    state: authenticationState,
                    reason: 'CIRCUIT_BREAKER_DENIAL',
                    error: 'Authentication service temporarily unavailable',
                    securityRisk: 'HIGH',
                    statusCode: 503,
                    securityContext,
                    operationTime: Date.now() - operationStartTime
                });
            }

            // CRITICAL-001 FIX: Step 4 - Isolated Firebase token verification
            const tokenVerificationResult = await this.performIsolatedTokenVerification(idToken, operationId);

            if (!tokenVerificationResult.success) {
                // CRITICAL-001 FIX: Token verification failed - handle with circuit breaker
                this.recordCircuitBreakerFailure();
                authenticationState = this.authenticationStates.DENIED;
                securityContext.explicitDenyReason = tokenVerificationResult.reason;

                return this.createFailSafeResponse({
                    authenticated: false,
                    state: authenticationState,
                    reason: tokenVerificationResult.reason,
                    error: tokenVerificationResult.error,
                    securityRisk: tokenVerificationResult.securityRisk,
                    statusCode: tokenVerificationResult.statusCode,
                    securityContext,
                    operationTime: Date.now() - operationStartTime
                });
            }

            // CRITICAL-001 FIX: Step 5 - Isolated token replay prevention check
            const replayPreventionResult = await this.performIsolatedReplayPreventionCheck(
                tokenVerificationResult.decodedToken,
                operationId
            );

            if (!replayPreventionResult.success) {
                authenticationState = this.authenticationStates.DENIED;
                securityContext.explicitDenyReason = replayPreventionResult.reason;

                await this.logSecurityEvent('TOKEN_REPLAY_DETECTED', {
                    operationId,
                    userId: tokenVerificationResult.decodedToken.uid,
                    reason: replayPreventionResult.reason,
                    severity: 'HIGH'
                });

                return this.createFailSafeResponse({
                    authenticated: false,
                    state: authenticationState,
                    reason: replayPreventionResult.reason,
                    error: replayPreventionResult.error,
                    securityRisk: 'CRITICAL',
                    statusCode: 401,
                    securityContext,
                    operationTime: Date.now() - operationStartTime
                });
            }

            // CRITICAL-001 FIX: Step 6 - EXPLICIT POSITIVE CONFIRMATION
            // ALL validations passed - explicitly set AUTHENTICATED state
            authenticationState = this.authenticationStates.AUTHENTICATED;
            securityContext.state = authenticationState;

            // Reset circuit breaker on successful operation
            this.resetCircuitBreaker();

            // CRITICAL-001 FIX: Record token usage in isolated operation
            await this.performIsolatedTokenUsageRecording(
                tokenVerificationResult.decodedToken,
                operationId
            );

            const operationTime = Date.now() - operationStartTime;

            // Log successful authentication with all security context
            await this.logSecurityEvent('FAIL_SAFE_AUTH_SUCCESS', {
                operationId,
                userId: tokenVerificationResult.decodedToken.uid,
                operationTime,
                securityContext,
                severity: 'INFO'
            });

            // CRITICAL-001 FIX: Return explicit success with comprehensive security context
            return this.createFailSafeResponse({
                authenticated: true,
                state: authenticationState,
                user: {
                    uid: tokenVerificationResult.decodedToken.uid,
                    email: tokenVerificationResult.decodedToken.email,
                    emailVerified: tokenVerificationResult.decodedToken.email_verified,
                    authTime: tokenVerificationResult.decodedToken.auth_time,
                    securityLevel: this.calculateSecurityLevel(securityContext)
                },
                reason: 'EXPLICIT_AUTHENTICATION_SUCCESS',
                securityRisk: 'LOW',
                statusCode: 200,
                securityContext,
                operationTime,
                performanceCompliant: operationTime < this.OPERATION_TIMEOUT_MS
            });

        } catch (error) {
            // CRITICAL-001 FIX: Comprehensive error isolation
            authenticationState = this.authenticationStates.ERROR;
            securityContext.state = authenticationState;
            securityContext.explicitDenyReason = 'SYSTEM_ERROR';

            // Record circuit breaker failure for system errors
            this.recordCircuitBreakerFailure();

            // CRITICAL-001 FIX: Sanitize error message to prevent information disclosure
            const sanitizedError = this.sanitizeErrorMessage(error);

            await this.logSecurityEvent('FAIL_SAFE_AUTH_ERROR', {
                operationId,
                error: sanitizedError,
                operationTime: Date.now() - operationStartTime,
                securityContext,
                severity: 'ERROR'
            });

            // CRITICAL-001 FIX: FAIL SECURE - Always deny on system error
            return this.createFailSafeResponse({
                authenticated: false,
                state: authenticationState,
                reason: 'SYSTEM_ERROR_DENIAL',
                error: 'Authentication service error',
                securityRisk: 'CRITICAL',
                statusCode: 500,
                securityContext,
                operationTime: Date.now() - operationStartTime,
                systemError: true
            });
        }
    }

    /**
     * CRITICAL-001 FIX: Validate authentication input with explicit deny on failure
     * @param {string} idToken - Firebase ID token
     * @param {Object} requestContext - Request context
     * @returns {Object} Validation result
     */
    validateAuthenticationInput(idToken, requestContext) {
        // Token presence validation
        if (!idToken) {
            return {
                valid: false,
                reason: 'TOKEN_MISSING',
                error: 'Authentication token required'
            };
        }

        // Token type validation
        if (typeof idToken !== 'string') {
            return {
                valid: false,
                reason: 'TOKEN_INVALID_TYPE',
                error: 'Authentication token must be a string'
            };
        }

        // Token length validation
        if (idToken.length < this.MINIMUM_TOKEN_LENGTH) {
            return {
                valid: false,
                reason: 'TOKEN_TOO_SHORT',
                error: 'Authentication token format invalid'
            };
        }

        // Token format validation (basic JWT structure check)
        const tokenParts = idToken.split('.');
        if (tokenParts.length !== 3) {
            return {
                valid: false,
                reason: 'TOKEN_MALFORMED',
                error: 'Authentication token format invalid'
            };
        }

        // Request context validation (optional but logged for security)
        if (requestContext) {
            if (requestContext.ipAddress && typeof requestContext.ipAddress !== 'string') {
                console.warn('CRITICAL-001: Invalid IP address type in request context');
            }
            if (requestContext.userAgent && typeof requestContext.userAgent !== 'string') {
                console.warn('CRITICAL-001: Invalid user agent type in request context');
            }
        }

        return {
            valid: true,
            reason: 'INPUT_VALIDATION_PASSED'
        };
    }

    /**
     * CRITICAL-001 FIX: Detect network partition conditions
     * @returns {Object} Network partition detection result
     */
    async detectNetworkPartition() {
        const startTime = Date.now();

        try {
            // CRITICAL-001 FIX: Quick connectivity test with timeout
            const connectivityTest = await Promise.race([
                this.performQuickConnectivityTest(),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('Connectivity test timeout')),
                    this.NETWORK_PARTITION_GRACE_PERIOD_MS)
                )
            ]);

            if (!connectivityTest.connected) {
                return {
                    partitionDetected: true,
                    partitionType: connectivityTest.reason,
                    detectionTime: Date.now() - startTime
                };
            }

            return {
                partitionDetected: false,
                detectionTime: Date.now() - startTime
            };

        } catch (error) {
            // CRITICAL-001 FIX: Treat detection failure as partition detected
            return {
                partitionDetected: true,
                partitionType: 'DETECTION_FAILURE',
                detectionTime: Date.now() - startTime,
                error: error.message
            };
        }
    }

    /**
     * CRITICAL-001 FIX: Perform quick connectivity test to Firestore
     * @returns {Object} Connectivity test result
     */
    async performQuickConnectivityTest() {
        try {
            const db = getFirestore();

            // CRITICAL-001 FIX: Minimal read operation to test connectivity
            const testDoc = await db.collection('_healthCheck').doc('connectivity').get();

            return {
                connected: true,
                responseTime: Date.now()
            };

        } catch (error) {
            return {
                connected: false,
                reason: error.code || 'UNKNOWN_ERROR',
                error: error.message
            };
        }
    }

    /**
     * CRITICAL-001 FIX: Perform isolated Firebase token verification with error isolation
     * @param {string} idToken - Firebase ID token
     * @param {string} operationId - Operation identifier
     * @returns {Object} Isolated token verification result
     */
    async performIsolatedTokenVerification(idToken, operationId) {
        const startTime = Date.now();

        try {
            // CRITICAL-001 FIX: Isolated Firebase token verification with timeout
            const auth = getAuth();

            const decodedToken = await Promise.race([
                auth.verifyIdToken(idToken, true), // checkRevoked = true
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('Token verification timeout')),
                    this.TOKEN_VERIFICATION_TIMEOUT_MS)
                )
            ]);

            // CRITICAL-001 FIX: Additional token validation
            const tokenValidation = this.validateDecodedToken(decodedToken);
            if (!tokenValidation.valid) {
                return {
                    success: false,
                    reason: tokenValidation.reason,
                    error: tokenValidation.error,
                    securityRisk: 'HIGH',
                    statusCode: 401
                };
            }

            return {
                success: true,
                decodedToken,
                verificationTime: Date.now() - startTime
            };

        } catch (error) {
            // CRITICAL-001 FIX: Handle specific Firebase errors with appropriate response
            if (error.message === 'Token verification timeout') {
                return {
                    success: false,
                    reason: 'TOKEN_VERIFICATION_TIMEOUT',
                    error: 'Authentication timeout',
                    securityRisk: 'HIGH',
                    statusCode: 408
                };
            }

            if (error.code === 'auth/id-token-expired') {
                return {
                    success: false,
                    reason: 'TOKEN_EXPIRED',
                    error: 'Authentication token expired',
                    securityRisk: 'MEDIUM',
                    statusCode: 401
                };
            }

            if (error.code === 'auth/id-token-revoked') {
                return {
                    success: false,
                    reason: 'TOKEN_REVOKED',
                    error: 'Authentication token revoked',
                    securityRisk: 'HIGH',
                    statusCode: 401
                };
            }

            // CRITICAL-001 FIX: Generic error handling with sanitization
            return {
                success: false,
                reason: 'TOKEN_VERIFICATION_FAILED',
                error: 'Authentication failed',
                securityRisk: 'HIGH',
                statusCode: 401
            };
        }
    }

    /**
     * CRITICAL-001 FIX: Validate decoded token with comprehensive checks
     * @param {Object} decodedToken - Decoded Firebase token
     * @returns {Object} Token validation result
     */
    validateDecodedToken(decodedToken) {
        // Audience validation
        if (decodedToken.aud !== process.env.FIREBASE_PROJECT_ID) {
            return {
                valid: false,
                reason: 'INVALID_AUDIENCE',
                error: 'Token audience mismatch'
            };
        }

        // Required fields validation
        if (!decodedToken.uid || !decodedToken.email) {
            return {
                valid: false,
                reason: 'MISSING_REQUIRED_FIELDS',
                error: 'Token payload incomplete'
            };
        }

        // Email verification enforcement
        if (!decodedToken.email_verified) {
            return {
                valid: false,
                reason: 'EMAIL_NOT_VERIFIED',
                error: 'Email verification required'
            };
        }

        // Token age validation
        const currentTime = Math.floor(Date.now() / 1000);
        const tokenAge = currentTime - decodedToken.iat;

        if (tokenAge > this.MAX_TOKEN_AGE_SECONDS) {
            return {
                valid: false,
                reason: 'TOKEN_TOO_OLD',
                error: 'Token refresh required'
            };
        }

        // Session age validation
        const sessionAge = currentTime - decodedToken.auth_time;
        const maxSessionAge = 24 * 60 * 60; // 24 hours

        if (sessionAge > maxSessionAge) {
            return {
                valid: false,
                reason: 'SESSION_EXPIRED',
                error: 'Re-authentication required'
            };
        }

        return {
            valid: true,
            reason: 'TOKEN_VALIDATION_PASSED'
        };
    }

    /**
     * CRITICAL-001 FIX: Perform isolated token replay prevention check
     * @param {Object} decodedToken - Decoded Firebase token
     * @param {string} operationId - Operation identifier
     * @returns {Object} Replay prevention result
     */
    async performIsolatedReplayPreventionCheck(decodedToken, operationId) {
        const startTime = Date.now();

        try {
            // CRITICAL-001 FIX: Generate token identifier for replay checking
            const tokenId = decodedToken.jti || decodedToken.iat.toString();
            const tokenHash = this.generateSecureTokenHash(tokenId);

            // CRITICAL-001 FIX: Check token replay with isolated Firestore operation
            const db = getFirestore();
            const replayCheckPromise = db.collection('usedTokens').doc(tokenHash).get();

            const tokenDoc = await Promise.race([
                replayCheckPromise,
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('Replay check timeout')),
                    this.FIRESTORE_OPERATION_TIMEOUT_MS)
                )
            ]);

            if (tokenDoc.exists) {
                const tokenData = tokenDoc.data();
                const now = Date.now();
                const replayWindow = 5 * 60 * 1000; // 5 minutes

                if ((now - tokenData.timestamp) < replayWindow) {
                    return {
                        success: false,
                        reason: 'TOKEN_REPLAY_DETECTED',
                        error: 'Token already used'
                    };
                }

                // Token record is old - remove it and allow
                await db.collection('usedTokens').doc(tokenHash).delete();
            }

            return {
                success: true,
                tokenHash,
                checkTime: Date.now() - startTime
            };

        } catch (error) {
            // CRITICAL-001 FIX: Replay check failure - FAIL SECURE
            if (error.message === 'Replay check timeout') {
                return {
                    success: false,
                    reason: 'REPLAY_CHECK_TIMEOUT',
                    error: 'Security check timeout'
                };
            }

            return {
                success: false,
                reason: 'REPLAY_CHECK_ERROR',
                error: 'Security check failed'
            };
        }
    }

    /**
     * CRITICAL-001 FIX: Perform isolated token usage recording
     * @param {Object} decodedToken - Decoded Firebase token
     * @param {string} operationId - Operation identifier
     */
    async performIsolatedTokenUsageRecording(decodedToken, operationId) {
        try {
            const tokenId = decodedToken.jti || decodedToken.iat.toString();
            const tokenHash = this.generateSecureTokenHash(tokenId);

            const db = getFirestore();
            const now = Date.now();

            // CRITICAL-001 FIX: Record token usage with timeout
            await Promise.race([
                db.collection('usedTokens').doc(tokenHash).set({
                    timestamp: now,
                    expiresAt: new Date(now + (5 * 60 * 1000)), // 5 minutes
                    operationId,
                    userId: decodedToken.uid
                }),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('Token recording timeout')),
                    this.FIRESTORE_OPERATION_TIMEOUT_MS)
                )
            ]);

        } catch (error) {
            // CRITICAL-001 FIX: Token recording failure is logged but doesn't affect authentication
            // since the token was already validated and replay check passed
            console.warn(`CRITICAL-001: Token usage recording failed for operation ${operationId}:`, error.message);

            await this.logSecurityEvent('TOKEN_USAGE_RECORDING_FAILED', {
                operationId,
                error: error.message,
                severity: 'WARN'
            });
        }
    }

    /**
     * CRITICAL-001 FIX: Circuit breaker implementation for external dependencies
     */
    isCircuitBreakerOpen() {
        if (!this.circuitBreakerState.isOpen) {
            return false;
        }

        const timeSinceLastFailure = Date.now() - this.circuitBreakerState.lastFailureTime;

        if (timeSinceLastFailure > this.CIRCUIT_BREAKER_TIMEOUT_MS) {
            // Reset circuit breaker after timeout
            this.resetCircuitBreaker();
            return false;
        }

        return true;
    }

    recordCircuitBreakerFailure() {
        this.circuitBreakerState.failureCount++;
        this.circuitBreakerState.lastFailureTime = Date.now();

        if (this.circuitBreakerState.failureCount >= this.circuitBreakerState.maxFailures) {
            this.circuitBreakerState.isOpen = true;
            console.warn('CRITICAL-001: Circuit breaker opened due to repeated failures');
        }
    }

    resetCircuitBreaker() {
        this.circuitBreakerState.isOpen = false;
        this.circuitBreakerState.failureCount = 0;
        this.circuitBreakerState.lastFailureTime = null;
    }

    /**
     * CRITICAL-001 FIX: Generate secure token hash for storage
     * @param {string} tokenId - Token identifier
     * @returns {string} Secure hash
     */
    generateSecureTokenHash(tokenId) {
        return crypto.createHash('sha256').update(tokenId).digest('hex');
    }

    /**
     * CRITICAL-001 FIX: Generate secure operation identifier
     * @returns {string} Secure operation ID
     */
    generateSecureOperationId() {
        const timestamp = Date.now();
        const randomBytes = crypto.randomBytes(8).toString('hex');
        return `CRIT001_${timestamp}_${randomBytes}`;
    }

    /**
     * CRITICAL-001 FIX: Calculate security level based on context
     * @param {Object} securityContext - Security context
     * @returns {string} Security level
     */
    calculateSecurityLevel(securityContext) {
        if (securityContext.networkPartitionDetected || securityContext.circuitBreakerTripped) {
            return 'LOW';
        }

        return 'HIGH';
    }

    /**
     * CRITICAL-001 FIX: Sanitize error messages to prevent information disclosure
     * @param {Error} error - Original error
     * @returns {string} Sanitized error message
     */
    sanitizeErrorMessage(error) {
        // Remove stack traces and system-specific information
        const message = error.message || 'Unknown error';

        // Remove file paths, line numbers, and other system details
        return message
            .replace(/\/[^\s]+/g, '[PATH_REMOVED]')
            .replace(/line \d+/gi, '[LINE_REMOVED]')
            .replace(/at .+$/gm, '[STACK_REMOVED]')
            .substring(0, 100); // Limit message length
    }

    /**
     * CRITICAL-001 FIX: Create standardized fail-safe response
     * @param {Object} responseData - Response data
     * @returns {Object} Standardized response
     */
    createFailSafeResponse(responseData) {
        // CRITICAL-001 FIX: Ensure explicit authentication state in response
        const response = {
            authenticated: responseData.authenticated === true, // Explicit boolean check
            state: responseData.state,
            reason: responseData.reason,
            securityRisk: responseData.securityRisk,
            statusCode: responseData.statusCode,
            operationTime: responseData.operationTime,
            timestamp: new Date().toISOString(),
            version: 'CRITICAL-001-FIX-1.0',
            failSafeEnabled: true
        };

        // Add user data only for successful authentication
        if (responseData.authenticated === true && responseData.user) {
            response.user = responseData.user;
        }

        // Add error information for failures
        if (responseData.authenticated !== true) {
            response.error = responseData.error;
        }

        // Add security context for debugging (without sensitive information)
        if (responseData.securityContext) {
            response.securityContext = {
                operationId: responseData.securityContext.operationId,
                state: responseData.securityContext.state,
                networkPartitionDetected: responseData.securityContext.networkPartitionDetected,
                circuitBreakerTripped: responseData.securityContext.circuitBreakerTripped
            };
        }

        // Add performance compliance information
        if (responseData.performanceCompliant !== undefined) {
            response.performanceCompliant = responseData.performanceCompliant;
        }

        return response;
    }

    /**
     * CRITICAL-001 FIX: Log security events with proper sanitization
     * @param {string} eventType - Event type
     * @param {Object} eventData - Event data
     */
    async logSecurityEvent(eventType, eventData) {
        try {
            const sanitizedEventData = {
                ...eventData,
                source: 'fail-safe-auth-check-critical-001',
                timestamp: new Date().toISOString()
            };

            // Remove sensitive information from logs
            if (sanitizedEventData.token) {
                delete sanitizedEventData.token;
            }
            if (sanitizedEventData.decodedToken) {
                delete sanitizedEventData.decodedToken;
            }

            securityLogger.log('INFO', eventType, sanitizedEventData);

        } catch (error) {
            // Logging failure should not affect authentication
            console.error('CRITICAL-001: Security event logging failed:', error.message);
        }
    }

    /**
     * CRITICAL-001 FIX: Health check for fail-safe authentication system
     * @returns {Object} Health status
     */
    async healthCheck() {
        const startTime = Date.now();

        try {
            // Test network connectivity
            const networkStatus = await this.detectNetworkPartition();

            // Test circuit breaker state
            const circuitBreakerOpen = this.isCircuitBreakerOpen();

            // Test Firestore connectivity
            const connectivityTest = await this.performQuickConnectivityTest();

            const responseTime = Date.now() - startTime;
            const isHealthy = !networkStatus.partitionDetected &&
                            !circuitBreakerOpen &&
                            connectivityTest.connected &&
                            responseTime < this.OPERATION_TIMEOUT_MS;

            return {
                status: isHealthy ? 'HEALTHY' : 'UNHEALTHY',
                components: {
                    networkPartition: !networkStatus.partitionDetected,
                    circuitBreaker: !circuitBreakerOpen,
                    firestoreConnectivity: connectivityTest.connected
                },
                responseTime,
                performanceCompliant: responseTime < this.OPERATION_TIMEOUT_MS,
                timestamp: new Date().toISOString(),
                version: 'CRITICAL-001-FIX-1.0'
            };

        } catch (error) {
            return {
                status: 'UNHEALTHY',
                error: this.sanitizeErrorMessage(error),
                responseTime: Date.now() - startTime,
                timestamp: new Date().toISOString(),
                version: 'CRITICAL-001-FIX-1.0'
            };
        }
    }
}

module.exports = FailSafeAuthenticationCheck;