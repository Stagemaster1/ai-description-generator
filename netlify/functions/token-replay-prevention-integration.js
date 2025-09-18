// Token Replay Prevention System Integration
// SESSION 2A-2 Implementation - Complete Integration Module
// Enterprise-Grade Security Controls Integration and Testing

const DistributedTokenReplayPrevention = require('./distributed-token-replay-prevention');
const EnhancedFirebaseAuthMiddleware = require('./enhanced-firebase-auth-middleware');
const EnterpriseErrorHandler = require('./enterprise-error-handler');
const PCIDSSComplianceValidator = require('./pci-dss-compliance-validator');
const securityLogger = require('./security-logger');

/**
 * Token Replay Prevention System Integration
 * Orchestrates all components of the distributed token replay prevention system
 * Provides unified interface for enterprise-grade security controls
 */
class TokenReplayPreventionIntegration {
    constructor() {
        // Initialize all components
        this.tokenReplayPrevention = new DistributedTokenReplayPrevention();
        this.enhancedAuthMiddleware = new EnhancedFirebaseAuthMiddleware();
        this.errorHandler = new EnterpriseErrorHandler();
        this.complianceValidator = new PCIDSSComplianceValidator();

        // System configuration
        this.SYSTEM_VERSION = '2A-2';
        this.ENTERPRISE_MODE = true;
        this.PCI_COMPLIANCE_REQUIRED = true;
        this.MAX_OPERATION_TIME = 5000; // 5-second requirement

        // Integration status
        this.systemStatus = {
            initialized: false,
            lastHealthCheck: null,
            lastComplianceValidation: null,
            operationalErrors: [],
            performanceMetrics: {}
        };
    }

    /**
     * Initialize the complete token replay prevention system
     * @returns {Object} Initialization result
     */
    async initializeSystem() {
        const initId = this.generateOperationId('INIT');
        const startTime = Date.now();

        try {
            console.log(`Initializing Token Replay Prevention System: ${initId}`);

            // Step 1: Component health checks
            const healthCheckResult = await this.performSystemHealthCheck();

            if (healthCheckResult.status !== 'HEALTHY') {
                throw new Error(`System health check failed: ${healthCheckResult.error}`);
            }

            // Step 2: PCI-DSS compliance validation
            const complianceResult = await this.performComplianceValidation();

            if (complianceResult.overallStatus === 'NON_COMPLIANT' && this.PCI_COMPLIANCE_REQUIRED) {
                throw new Error(`PCI-DSS compliance validation failed: ${complianceResult.criticalFindings.length} critical findings`);
            }

            // Step 3: Security controls validation
            const securityControlsResult = await this.validateSecurityControls();

            if (!securityControlsResult.allControlsOperational) {
                throw new Error(`Security controls validation failed: ${securityControlsResult.failedControls.length} controls failed`);
            }

            // Step 4: Performance benchmarking
            const performanceResult = await this.performPerformanceBenchmark();

            if (!performanceResult.meetsRequirements) {
                console.warn('Performance requirements not fully met, but system is operational');
            }

            // Update system status
            this.systemStatus = {
                initialized: true,
                initializationTime: Date.now() - startTime,
                lastHealthCheck: healthCheckResult,
                lastComplianceValidation: complianceResult,
                securityControls: securityControlsResult,
                performanceMetrics: performanceResult,
                operationalErrors: []
            };

            // Log successful initialization
            await this.logSystemEvent('SYSTEM_INITIALIZED', {
                initId: initId,
                initializationTime: this.systemStatus.initializationTime,
                complianceStatus: complianceResult.overallStatus,
                securityControlsStatus: securityControlsResult.allControlsOperational,
                performanceCompliant: performanceResult.meetsRequirements
            });

            return {
                success: true,
                initId: initId,
                status: this.systemStatus,
                message: 'Token Replay Prevention System successfully initialized',
                version: this.SYSTEM_VERSION
            };

        } catch (error) {
            const errorResult = await this.errorHandler.handleError(error, {
                operation: 'system_initialization',
                initId: initId,
                securityContext: true
            });

            this.systemStatus.operationalErrors.push(errorResult);

            return {
                success: false,
                initId: initId,
                error: error.message,
                errorDetails: errorResult,
                version: this.SYSTEM_VERSION
            };
        }
    }

    /**
     * Unified token verification with comprehensive security controls
     * @param {string} idToken - Firebase ID token
     * @param {Object} requestContext - Request context information
     * @returns {Object} Comprehensive verification result
     */
    async verifyTokenWithSecurityControls(idToken, requestContext = {}) {
        const verificationId = this.generateOperationId('VERIFY');
        const startTime = Date.now();

        try {
            // Validate system is initialized
            if (!this.systemStatus.initialized) {
                throw new Error('Token replay prevention system not initialized');
            }

            // Enhanced token verification with all security controls
            const verificationResult = await this.enhancedAuthMiddleware.verifyIdToken(
                idToken,
                requestContext.ipAddress,
                requestContext.userAgent
            );

            const operationTime = Date.now() - startTime;

            // Performance compliance check
            if (operationTime > this.MAX_OPERATION_TIME) {
                await this.logPerformanceWarning('token_verification', operationTime);
            }

            // Additional security context
            const securityContext = {
                verificationId: verificationId,
                operationTime: operationTime,
                performanceCompliant: operationTime < this.MAX_OPERATION_TIME,
                systemVersion: this.SYSTEM_VERSION,
                securityLevel: verificationResult.user ? verificationResult.user.securityLevel : 'UNKNOWN'
            };

            // Log verification attempt
            await this.logSystemEvent('TOKEN_VERIFICATION', {
                verificationId: verificationId,
                success: verificationResult.valid,
                userId: verificationResult.user ? verificationResult.user.uid : 'unknown',
                securityRisk: verificationResult.securityRisk,
                operationTime: operationTime,
                ipAddress: requestContext.ipAddress
            });

            return {
                ...verificationResult,
                securityContext: securityContext,
                systemStatus: 'OPERATIONAL',
                version: this.SYSTEM_VERSION
            };

        } catch (error) {
            const errorResult = await this.errorHandler.handleError(error, {
                operation: 'token_verification',
                verificationId: verificationId,
                securityContext: true,
                requestContext: requestContext
            });

            return {
                valid: false,
                error: 'Security system error during token verification',
                statusCode: 500,
                securityRisk: 'CRITICAL',
                errorDetails: errorResult,
                systemStatus: 'ERROR',
                version: this.SYSTEM_VERSION
            };
        }
    }

    /**
     * Perform comprehensive system health check
     * @returns {Object} System health status
     */
    async performSystemHealthCheck() {
        const healthCheckId = this.generateOperationId('HEALTH');

        try {
            const componentChecks = await Promise.all([
                this.tokenReplayPrevention.healthCheck(),
                this.enhancedAuthMiddleware.healthCheck(),
                this.checkFirestoreConnectivity(),
                this.checkSecurityLogging()
            ]);

            const [
                tokenReplayHealth,
                authMiddlewareHealth,
                firestoreHealth,
                loggingHealth
            ] = componentChecks;

            const allHealthy = componentChecks.every(check => check.status === 'HEALTHY');

            return {
                healthCheckId: healthCheckId,
                status: allHealthy ? 'HEALTHY' : 'UNHEALTHY',
                timestamp: Date.now(),
                components: {
                    tokenReplayPrevention: tokenReplayHealth,
                    authMiddleware: authMiddlewareHealth,
                    firestore: firestoreHealth,
                    logging: loggingHealth
                },
                overallHealth: allHealthy,
                version: this.SYSTEM_VERSION
            };

        } catch (error) {
            return {
                healthCheckId: healthCheckId,
                status: 'UNHEALTHY',
                error: error.message,
                timestamp: Date.now(),
                version: this.SYSTEM_VERSION
            };
        }
    }

    /**
     * Perform PCI-DSS compliance validation
     * @returns {Object} Compliance validation result
     */
    async performComplianceValidation() {
        try {
            const validationResult = await this.complianceValidator.performComplianceValidation();

            // Store validation results
            this.systemStatus.lastComplianceValidation = validationResult;

            return validationResult;

        } catch (error) {
            const errorResult = await this.errorHandler.handleError(error, {
                operation: 'compliance_validation',
                complianceViolation: true
            });

            return {
                validationId: 'FAILED_' + Date.now(),
                overallStatus: 'NON_COMPLIANT',
                error: error.message,
                errorDetails: errorResult,
                version: this.SYSTEM_VERSION
            };
        }
    }

    /**
     * Validate all security controls are operational
     * @returns {Object} Security controls validation result
     */
    async validateSecurityControls() {
        const validationId = this.generateOperationId('SEC_CTRL');

        try {
            const securityControls = [
                { name: 'Token Blacklisting', test: () => this.testTokenBlacklistingControl() },
                { name: 'Distributed Locking', test: () => this.testDistributedLockingControl() },
                { name: 'Behavioral Analysis', test: () => this.testBehavioralAnalysisControl() },
                { name: 'Error Handling', test: () => this.testErrorHandlingControl() },
                { name: 'Audit Logging', test: () => this.testAuditLoggingControl() }
            ];

            const controlResults = [];
            const failedControls = [];

            for (const control of securityControls) {
                try {
                    const result = await control.test();
                    controlResults.push({
                        name: control.name,
                        status: 'OPERATIONAL',
                        result: result
                    });
                } catch (controlError) {
                    controlResults.push({
                        name: control.name,
                        status: 'FAILED',
                        error: controlError.message
                    });
                    failedControls.push(control.name);
                }
            }

            return {
                validationId: validationId,
                allControlsOperational: failedControls.length === 0,
                controlResults: controlResults,
                failedControls: failedControls,
                timestamp: Date.now(),
                version: this.SYSTEM_VERSION
            };

        } catch (error) {
            return {
                validationId: validationId,
                allControlsOperational: false,
                error: error.message,
                failedControls: ['ALL'],
                timestamp: Date.now(),
                version: this.SYSTEM_VERSION
            };
        }
    }

    /**
     * Perform performance benchmark testing
     * @returns {Object} Performance benchmark result
     */
    async performPerformanceBenchmark() {
        const benchmarkId = this.generateOperationId('PERF');

        try {
            const testIterations = 10;
            const performanceTests = [];

            for (let i = 0; i < testIterations; i++) {
                const testStart = Date.now();

                // Test token replay prevention operation
                const testTokenId = 'perf_test_' + Date.now() + '_' + i;
                const blacklistResult = await this.tokenReplayPrevention.blacklistToken(testTokenId, 'perf_user', 'PERFORMANCE_TEST');
                const checkResult = await this.tokenReplayPrevention.isTokenBlacklisted(testTokenId);

                const testDuration = Date.now() - testStart;
                const testSuccess = blacklistResult.success && checkResult.isBlacklisted;

                performanceTests.push({
                    iteration: i,
                    duration: testDuration,
                    success: testSuccess,
                    compliant: testDuration < this.MAX_OPERATION_TIME
                });
            }

            const averageDuration = performanceTests.reduce((sum, test) => sum + test.duration, 0) / testIterations;
            const maxDuration = Math.max(...performanceTests.map(test => test.duration));
            const successRate = performanceTests.filter(test => test.success).length / testIterations;
            const complianceRate = performanceTests.filter(test => test.compliant).length / testIterations;

            const meetsRequirements = averageDuration < this.MAX_OPERATION_TIME &&
                                    maxDuration < this.MAX_OPERATION_TIME &&
                                    successRate >= 0.99 &&
                                    complianceRate >= 0.95;

            return {
                benchmarkId: benchmarkId,
                meetsRequirements: meetsRequirements,
                metrics: {
                    averageDuration: averageDuration,
                    maxDuration: maxDuration,
                    minDuration: Math.min(...performanceTests.map(test => test.duration)),
                    successRate: successRate,
                    complianceRate: complianceRate,
                    threshold: this.MAX_OPERATION_TIME
                },
                testResults: performanceTests,
                timestamp: Date.now(),
                version: this.SYSTEM_VERSION
            };

        } catch (error) {
            return {
                benchmarkId: benchmarkId,
                meetsRequirements: false,
                error: error.message,
                timestamp: Date.now(),
                version: this.SYSTEM_VERSION
            };
        }
    }

    /**
     * Get comprehensive system status
     * @returns {Object} Complete system status
     */
    getSystemStatus() {
        return {
            ...this.systemStatus,
            currentTime: Date.now(),
            version: this.SYSTEM_VERSION,
            enterpriseMode: this.ENTERPRISE_MODE,
            pciComplianceRequired: this.PCI_COMPLIANCE_REQUIRED
        };
    }

    /**
     * Get performance metrics from all components
     * @returns {Object} Consolidated performance metrics
     */
    getPerformanceMetrics() {
        try {
            const tokenReplayMetrics = this.tokenReplayPrevention.getPerformanceMetrics();
            const authMiddlewareMetrics = this.enhancedAuthMiddleware.getPerformanceMetrics();

            return {
                tokenReplayPrevention: tokenReplayMetrics,
                authMiddleware: authMiddlewareMetrics,
                systemMetrics: this.systemStatus.performanceMetrics,
                timestamp: Date.now(),
                version: this.SYSTEM_VERSION
            };

        } catch (error) {
            return {
                error: error.message,
                timestamp: Date.now(),
                version: this.SYSTEM_VERSION
            };
        }
    }

    // Test methods for security controls validation
    async testTokenBlacklistingControl() {
        const testToken = 'test_blacklist_' + Date.now();
        const blacklistResult = await this.tokenReplayPrevention.blacklistToken(testToken, 'test_user', 'CONTROL_TEST');
        const checkResult = await this.tokenReplayPrevention.isTokenBlacklisted(testToken);

        if (!blacklistResult.success || !checkResult.isBlacklisted) {
            throw new Error('Token blacklisting control test failed');
        }

        return { success: true, testToken: testToken.substring(0, 8) + '...' };
    }

    async testDistributedLockingControl() {
        const lockId = 'test_lock_' + Date.now();
        const lockResult = await this.tokenReplayPrevention.acquireDistributedLock(lockId);
        const releaseResult = await this.tokenReplayPrevention.releaseDistributedLock(lockId);

        if (!lockResult.success || !releaseResult) {
            throw new Error('Distributed locking control test failed');
        }

        return { success: true, lockId: lockId };
    }

    async testBehavioralAnalysisControl() {
        const analysisResult = await this.tokenReplayPrevention.performBehavioralAnalysis('test_user', '127.0.0.1', 'test_token');

        if (!analysisResult.riskLevel || !analysisResult.score !== undefined) {
            throw new Error('Behavioral analysis control test failed');
        }

        return { success: true, riskLevel: analysisResult.riskLevel };
    }

    async testErrorHandlingControl() {
        const testError = new Error('Test error for control validation');
        const errorResult = await this.errorHandler.handleError(testError, { operation: 'control_test' });

        if (!errorResult.handled || !errorResult.errorId) {
            throw new Error('Error handling control test failed');
        }

        return { success: true, errorId: errorResult.errorId };
    }

    async testAuditLoggingControl() {
        await this.logSystemEvent('CONTROL_TEST', { testTime: Date.now() });
        return { success: true, logged: true };
    }

    // Utility methods
    async checkFirestoreConnectivity() {
        try {
            const { getFirestore } = require('firebase-admin/firestore');
            const db = getFirestore();
            await db.collection('healthCheck').doc('connectivity').set({ timestamp: Date.now() });
            await db.collection('healthCheck').doc('connectivity').delete();

            return { status: 'HEALTHY', service: 'Firestore' };
        } catch (error) {
            return { status: 'UNHEALTHY', service: 'Firestore', error: error.message };
        }
    }

    async checkSecurityLogging() {
        try {
            securityLogger.log('INFO', 'HEALTH_CHECK', { timestamp: Date.now() });
            return { status: 'HEALTHY', service: 'Security Logging' };
        } catch (error) {
            return { status: 'UNHEALTHY', service: 'Security Logging', error: error.message };
        }
    }

    async logSystemEvent(eventType, eventData) {
        try {
            securityLogger.log('INFO', eventType, {
                ...eventData,
                source: 'token-replay-prevention-integration',
                version: this.SYSTEM_VERSION,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            console.error('Failed to log system event:', error);
        }
    }

    async logPerformanceWarning(operation, duration) {
        try {
            securityLogger.log('WARN', 'PERFORMANCE_WARNING', {
                operation: operation,
                duration: duration,
                threshold: this.MAX_OPERATION_TIME,
                source: 'token-replay-prevention-integration',
                version: this.SYSTEM_VERSION,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            console.error('Failed to log performance warning:', error);
        }
    }

    generateOperationId(prefix) {
        return `${prefix}_${Date.now()}_${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    }
}

module.exports = TokenReplayPreventionIntegration;