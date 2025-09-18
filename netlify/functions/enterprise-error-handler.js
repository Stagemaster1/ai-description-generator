// Enterprise Error Handler and Security Logger
// SESSION 2A-2 Implementation - Comprehensive Error Handling and Logging
// PCI-DSS 4.0 Compliant Security Event Management

const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const crypto = require('crypto');

/**
 * Enterprise Error Handler for Distributed Token Replay Prevention
 * Provides comprehensive error handling, logging, and security event management
 */
class EnterpriseErrorHandler {
    constructor() {
        // Error Classification
        this.ERROR_TYPES = {
            SECURITY: 'SECURITY',
            PERFORMANCE: 'PERFORMANCE',
            SYSTEM: 'SYSTEM',
            COMPLIANCE: 'COMPLIANCE',
            NETWORK: 'NETWORK'
        };

        // Security Event Severities
        this.SEVERITY_LEVELS = {
            CRITICAL: 'CRITICAL',
            HIGH: 'HIGH',
            MEDIUM: 'MEDIUM',
            LOW: 'LOW',
            INFO: 'INFO'
        };

        // PCI-DSS Event Categories
        this.PCI_EVENT_CATEGORIES = {
            AUTH_FAILURE: 'AUTH_FAILURE',
            DATA_ACCESS: 'DATA_ACCESS',
            SYSTEM_CHANGE: 'SYSTEM_CHANGE',
            SECURITY_VIOLATION: 'SECURITY_VIOLATION',
            COMPLIANCE_CHECK: 'COMPLIANCE_CHECK'
        };

        // Error Recovery Strategies
        this.RECOVERY_STRATEGIES = {
            RETRY: 'RETRY',
            FAILOVER: 'FAILOVER',
            CIRCUIT_BREAK: 'CIRCUIT_BREAK',
            FAIL_SECURE: 'FAIL_SECURE'
        };

        // Firestore Collections
        this.ERROR_LOG_COLLECTION = 'enterpriseErrorLog';
        this.SECURITY_EVENTS_COLLECTION = 'securityEvents';
        this.PERFORMANCE_METRICS_COLLECTION = 'performanceMetrics';
        this.COMPLIANCE_AUDIT_COLLECTION = 'complianceAudit';

        // Circuit Breaker State
        this.circuitBreakerState = new Map();
        this.CIRCUIT_BREAKER_THRESHOLD = 5;
        this.CIRCUIT_BREAKER_TIMEOUT = 30000; // 30 seconds
    }

    /**
     * Handle enterprise-grade errors with comprehensive logging and recovery
     * @param {Error} error - Error object
     * @param {Object} context - Error context information
     * @returns {Object} Error handling result with recovery strategy
     */
    async handleError(error, context = {}) {
        const errorId = this.generateErrorId();
        const timestamp = Date.now();

        try {
            // Classify error type and severity
            const classification = this.classifyError(error, context);

            // Create comprehensive error record
            const errorRecord = {
                errorId: errorId,
                timestamp: timestamp,
                // CRITICAL-003 FIX: Sanitize error details to prevent information disclosure
                error: {
                    name: this.sanitizeErrorName(error.name),
                    message: this.sanitizeErrorMessage(error.message),
                    // Remove stack trace from client responses - security risk
                    code: error.code
                },
                classification: classification,
                context: this.sanitizeContext(context),
                severity: classification.severity,
                category: classification.category,
                source: 'distributed-token-replay-prevention',
                version: '2A-2'
            };

            // Log error to Firestore
            await this.logErrorToFirestore(errorRecord);

            // Handle security-specific errors
            if (classification.type === this.ERROR_TYPES.SECURITY) {
                await this.handleSecurityError(error, context, errorRecord);
            }

            // Handle performance issues
            if (classification.type === this.ERROR_TYPES.PERFORMANCE) {
                await this.handlePerformanceError(error, context, errorRecord);
            }

            // Handle compliance violations
            if (classification.type === this.ERROR_TYPES.COMPLIANCE) {
                await this.handleComplianceError(error, context, errorRecord);
            }

            // Determine recovery strategy
            const recoveryStrategy = this.determineRecoveryStrategy(classification, context);

            // Execute recovery strategy
            const recoveryResult = await this.executeRecoveryStrategy(recoveryStrategy, context);

            // Log recovery attempt
            await this.logRecoveryAttempt(errorId, recoveryStrategy, recoveryResult);

            return {
                errorId: errorId,
                handled: true,
                classification: classification,
                recoveryStrategy: recoveryStrategy,
                recoveryResult: recoveryResult,
                severity: classification.severity,
                timestamp: timestamp
            };

        } catch (handlingError) {
            // Meta-error handling - error in error handler
            console.error('Critical: Error handler failed:', handlingError);

            // CRITICAL-003 FIX: Sanitize meta-error response to prevent information disclosure
            return {
                errorId: errorId,
                handled: false,
                error: 'Service temporarily unavailable',
                severity: this.SEVERITY_LEVELS.CRITICAL,
                timestamp: timestamp
            };
        }
    }

    /**
     * Classify error type and severity
     * @param {Error} error - Error object
     * @param {Object} context - Error context
     * @returns {Object} Error classification
     */
    classifyError(error, context) {
        let type = this.ERROR_TYPES.SYSTEM;
        let severity = this.SEVERITY_LEVELS.MEDIUM;
        let category = 'UNKNOWN';

        // Security error classification
        if (this.isSecurityError(error, context)) {
            type = this.ERROR_TYPES.SECURITY;
            severity = this.SEVERITY_LEVELS.HIGH;

            if (error.message.includes('replay') || error.message.includes('blacklist')) {
                category = this.PCI_EVENT_CATEGORIES.SECURITY_VIOLATION;
                severity = this.SEVERITY_LEVELS.CRITICAL;
            } else if (error.message.includes('auth') || error.message.includes('token')) {
                category = this.PCI_EVENT_CATEGORIES.AUTH_FAILURE;
                severity = this.SEVERITY_LEVELS.HIGH;
            }
        }

        // Performance error classification
        if (this.isPerformanceError(error, context)) {
            type = this.ERROR_TYPES.PERFORMANCE;
            severity = this.SEVERITY_LEVELS.MEDIUM;
            category = 'PERFORMANCE_DEGRADATION';

            if (context.responseTime && context.responseTime > 5000) {
                severity = this.SEVERITY_LEVELS.HIGH;
            }
        }

        // Compliance error classification
        if (this.isComplianceError(error, context)) {
            type = this.ERROR_TYPES.COMPLIANCE;
            severity = this.SEVERITY_LEVELS.HIGH;
            category = this.PCI_EVENT_CATEGORIES.COMPLIANCE_CHECK;
        }

        // Network error classification
        if (this.isNetworkError(error)) {
            type = this.ERROR_TYPES.NETWORK;
            severity = this.SEVERITY_LEVELS.MEDIUM;
            category = 'NETWORK_FAILURE';
        }

        return {
            type: type,
            severity: severity,
            category: category,
            riskLevel: this.calculateRiskLevel(type, severity, context),
            requiresImmedateAction: severity === this.SEVERITY_LEVELS.CRITICAL
        };
    }

    /**
     * Handle security-specific errors
     * @param {Error} error - Security error
     * @param {Object} context - Error context
     * @param {Object} errorRecord - Comprehensive error record
     */
    async handleSecurityError(error, context, errorRecord) {
        try {
            // Create security event
            const securityEvent = {
                eventId: this.generateEventId(),
                timestamp: Date.now(),
                type: 'SECURITY_ERROR',
                severity: errorRecord.severity,
                error: errorRecord.error,
                context: context,
                userAgent: context.userAgent,
                ipAddress: context.ipAddress,
                userId: context.userId,
                action: 'ERROR_DETECTED',
                source: 'enterprise-error-handler'
            };

            // Log to security events collection
            const db = getFirestore();
            await db.collection(this.SECURITY_EVENTS_COLLECTION).add(securityEvent);

            // Trigger security alerts for critical events
            if (errorRecord.severity === this.SEVERITY_LEVELS.CRITICAL) {
                await this.triggerSecurityAlert(securityEvent);
            }

            // Update security metrics
            await this.updateSecurityMetrics(errorRecord);

        } catch (securityHandlingError) {
            console.error('Failed to handle security error:', securityHandlingError);
        }
    }

    /**
     * Handle performance-specific errors
     * @param {Error} error - Performance error
     * @param {Object} context - Error context
     * @param {Object} errorRecord - Comprehensive error record
     */
    async handlePerformanceError(error, context, errorRecord) {
        try {
            const performanceData = {
                timestamp: Date.now(),
                operation: context.operation || 'unknown',
                responseTime: context.responseTime || 0,
                errorType: error.name,
                errorMessage: error.message,
                threshold: context.threshold || 5000,
                severity: errorRecord.severity
            };

            // Log performance metrics
            const db = getFirestore();
            await db.collection(this.PERFORMANCE_METRICS_COLLECTION).add(performanceData);

            // Check if circuit breaker should be activated
            if (this.shouldActivateCircuitBreaker(context.operation, error)) {
                await this.activateCircuitBreaker(context.operation);
            }

        } catch (performanceHandlingError) {
            console.error('Failed to handle performance error:', performanceHandlingError);
        }
    }

    /**
     * Handle compliance-specific errors
     * @param {Error} error - Compliance error
     * @param {Object} context - Error context
     * @param {Object} errorRecord - Comprehensive error record
     */
    async handleComplianceError(error, context, errorRecord) {
        try {
            const complianceViolation = {
                timestamp: Date.now(),
                violationType: context.violationType || 'UNKNOWN',
                requirement: context.requirement || 'PCI-DSS-4.0',
                description: error.message,
                severity: errorRecord.severity,
                userId: context.userId,
                ipAddress: context.ipAddress,
                action: context.action || 'UNKNOWN',
                remediationRequired: true
            };

            // Log compliance violation
            const db = getFirestore();
            await db.collection(this.COMPLIANCE_AUDIT_COLLECTION).add(complianceViolation);

            // Trigger compliance alerts
            await this.triggerComplianceAlert(complianceViolation);

        } catch (complianceHandlingError) {
            console.error('Failed to handle compliance error:', complianceHandlingError);
        }
    }

    /**
     * Determine appropriate recovery strategy
     * @param {Object} classification - Error classification
     * @param {Object} context - Error context
     * @returns {string} Recovery strategy
     */
    determineRecoveryStrategy(classification, context) {
        // Security errors - fail secure
        if (classification.type === this.ERROR_TYPES.SECURITY) {
            return this.RECOVERY_STRATEGIES.FAIL_SECURE;
        }

        // Performance errors - circuit breaker or retry
        if (classification.type === this.ERROR_TYPES.PERFORMANCE) {
            if (context.retryCount && context.retryCount >= 3) {
                return this.RECOVERY_STRATEGIES.CIRCUIT_BREAK;
            }
            return this.RECOVERY_STRATEGIES.RETRY;
        }

        // Network errors - retry with backoff
        if (classification.type === this.ERROR_TYPES.NETWORK) {
            return this.RECOVERY_STRATEGIES.RETRY;
        }

        // Compliance errors - fail secure
        if (classification.type === this.ERROR_TYPES.COMPLIANCE) {
            return this.RECOVERY_STRATEGIES.FAIL_SECURE;
        }

        // Default strategy
        return this.RECOVERY_STRATEGIES.FAIL_SECURE;
    }

    /**
     * Execute recovery strategy
     * @param {string} strategy - Recovery strategy
     * @param {Object} context - Error context
     * @returns {Object} Recovery result
     */
    async executeRecoveryStrategy(strategy, context) {
        switch (strategy) {
            case this.RECOVERY_STRATEGIES.RETRY:
                return await this.executeRetryStrategy(context);

            case this.RECOVERY_STRATEGIES.FAILOVER:
                return await this.executeFailoverStrategy(context);

            case this.RECOVERY_STRATEGIES.CIRCUIT_BREAK:
                return await this.executeCircuitBreakerStrategy(context);

            case this.RECOVERY_STRATEGIES.FAIL_SECURE:
                return this.executeFailSecureStrategy(context);

            default:
                return {
                    strategy: strategy,
                    executed: false,
                    reason: 'Unknown recovery strategy'
                };
        }
    }

    /**
     * Execute retry recovery strategy
     * @param {Object} context - Error context
     * @returns {Object} Retry result
     */
    async executeRetryStrategy(context) {
        try {
            const maxRetries = 3;
            const retryDelay = Math.min(1000 * Math.pow(2, context.retryCount || 0), 5000);

            if ((context.retryCount || 0) >= maxRetries) {
                return {
                    strategy: this.RECOVERY_STRATEGIES.RETRY,
                    executed: false,
                    reason: 'Maximum retries exceeded',
                    retryCount: context.retryCount
                };
            }

            // Wait before retry
            await new Promise(resolve => setTimeout(resolve, retryDelay));

            return {
                strategy: this.RECOVERY_STRATEGIES.RETRY,
                executed: true,
                retryCount: (context.retryCount || 0) + 1,
                retryDelay: retryDelay
            };

        } catch (retryError) {
            return {
                strategy: this.RECOVERY_STRATEGIES.RETRY,
                executed: false,
                error: retryError.message
            };
        }
    }

    /**
     * Execute fail-secure recovery strategy
     * @param {Object} context - Error context
     * @returns {Object} Fail-secure result
     */
    executeFailSecureStrategy(context) {
        return {
            strategy: this.RECOVERY_STRATEGIES.FAIL_SECURE,
            executed: true,
            action: 'DENY_ACCESS',
            reason: 'Security-first failure mode activated',
            recommendation: 'Review security logs and retry after verification'
        };
    }

    /**
     * Log error to Firestore
     * @param {Object} errorRecord - Error record to log
     */
    async logErrorToFirestore(errorRecord) {
        try {
            const db = getFirestore();
            await db.collection(this.ERROR_LOG_COLLECTION).add(errorRecord);
        } catch (loggingError) {
            console.error('Failed to log error to Firestore:', loggingError);
        }
    }

    /**
     * Sanitize context to remove sensitive information
     * @param {Object} context - Original context
     * @returns {Object} Sanitized context
     */
    sanitizeContext(context) {
        const sanitized = { ...context };

        // Remove sensitive fields
        delete sanitized.token;
        delete sanitized.password;
        delete sanitized.apiKey;

        // Truncate long values
        Object.keys(sanitized).forEach(key => {
            if (typeof sanitized[key] === 'string' && sanitized[key].length > 1000) {
                sanitized[key] = sanitized[key].substring(0, 1000) + '...';
            }
        });

        return sanitized;
    }

    /**
     * Generate unique error ID
     * @returns {string} Unique error identifier
     */
    generateErrorId() {
        return 'ERR_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex').toUpperCase();
    }

    /**
     * Generate unique event ID
     * @returns {string} Unique event identifier
     */
    generateEventId() {
        return 'EVT_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex').toUpperCase();
    }

    /**
     * Check if error is security-related
     * @param {Error} error - Error object
     * @param {Object} context - Error context
     * @returns {boolean} True if security error
     */
    isSecurityError(error, context) {
        const securityKeywords = ['auth', 'token', 'replay', 'blacklist', 'unauthorized', 'forbidden', 'security', 'violation'];
        const errorMessage = error.message.toLowerCase();

        return securityKeywords.some(keyword => errorMessage.includes(keyword)) ||
               context.securityContext === true ||
               error.name === 'SecurityError';
    }

    /**
     * Check if error is performance-related
     * @param {Error} error - Error object
     * @param {Object} context - Error context
     * @returns {boolean} True if performance error
     */
    isPerformanceError(error, context) {
        const performanceKeywords = ['timeout', 'slow', 'performance', 'latency'];
        const errorMessage = error.message.toLowerCase();

        return performanceKeywords.some(keyword => errorMessage.includes(keyword)) ||
               (context.responseTime && context.responseTime > 5000) ||
               error.name === 'TimeoutError';
    }

    /**
     * Check if error is compliance-related
     * @param {Error} error - Error object
     * @param {Object} context - Error context
     * @returns {boolean} True if compliance error
     */
    isComplianceError(error, context) {
        const complianceKeywords = ['pci', 'compliance', 'gdpr', 'regulation', 'audit'];
        const errorMessage = error.message.toLowerCase();

        return complianceKeywords.some(keyword => errorMessage.includes(keyword)) ||
               context.complianceViolation === true ||
               error.name === 'ComplianceError';
    }

    /**
     * Check if error is network-related
     * @param {Error} error - Error object
     * @returns {boolean} True if network error
     */
    isNetworkError(error) {
        const networkKeywords = ['network', 'connection', 'dns', 'socket', 'econnrefused', 'etimedout'];
        const errorMessage = error.message.toLowerCase();

        return networkKeywords.some(keyword => errorMessage.includes(keyword)) ||
               error.code === 'ECONNREFUSED' ||
               error.code === 'ETIMEDOUT' ||
               error.name === 'NetworkError';
    }

    /**
     * Calculate risk level based on error classification
     * @param {string} type - Error type
     * @param {string} severity - Error severity
     * @param {Object} context - Error context
     * @returns {string} Risk level
     */
    calculateRiskLevel(type, severity, context) {
        if (type === this.ERROR_TYPES.SECURITY && severity === this.SEVERITY_LEVELS.CRITICAL) {
            return 'CRITICAL';
        }

        if (type === this.ERROR_TYPES.COMPLIANCE) {
            return 'HIGH';
        }

        if (severity === this.SEVERITY_LEVELS.HIGH) {
            return 'HIGH';
        }

        if (severity === this.SEVERITY_LEVELS.MEDIUM) {
            return 'MEDIUM';
        }

        return 'LOW';
    }

    /**
     * Trigger security alert for critical events
     * @param {Object} securityEvent - Security event data
     */
    async triggerSecurityAlert(securityEvent) {
        try {
            // Log critical security alert
            console.error('CRITICAL SECURITY ALERT:', {
                eventId: securityEvent.eventId,
                type: securityEvent.type,
                severity: securityEvent.severity,
                timestamp: new Date(securityEvent.timestamp).toISOString()
            });

            // In production, this would integrate with alerting systems
            // like PagerDuty, Slack, or SIEM tools

        } catch (alertError) {
            console.error('Failed to trigger security alert:', alertError);
        }
    }

    /**
     * Trigger compliance alert
     * @param {Object} complianceViolation - Compliance violation data
     */
    async triggerComplianceAlert(complianceViolation) {
        try {
            console.warn('COMPLIANCE VIOLATION DETECTED:', {
                violationType: complianceViolation.violationType,
                requirement: complianceViolation.requirement,
                severity: complianceViolation.severity,
                timestamp: new Date(complianceViolation.timestamp).toISOString()
            });

        } catch (alertError) {
            console.error('Failed to trigger compliance alert:', alertError);
        }
    }

    /**
     * Update security metrics
     * @param {Object} errorRecord - Error record
     */
    async updateSecurityMetrics(errorRecord) {
        try {
            // This would update security dashboards and metrics
            // For now, we'll just log the update
            console.log('Security metrics updated for error:', errorRecord.errorId);

        } catch (metricsError) {
            console.error('Failed to update security metrics:', metricsError);
        }
    }

    /**
     * CRITICAL-003 FIX: Sanitize error names to prevent information disclosure
     * @param {string} errorName - Original error name
     * @returns {string} Sanitized error name
     */
    sanitizeErrorName(errorName) {
        // Map specific error names to generic ones
        const errorNameMap = {
            'TypeError': 'SystemError',
            'ReferenceError': 'SystemError',
            'SyntaxError': 'SystemError',
            'RangeError': 'SystemError',
            'URIError': 'SystemError',
            'MongoError': 'DatabaseError',
            'FirestoreError': 'DatabaseError',
            'ValidationError': 'InputError'
        };

        return errorNameMap[errorName] || 'SystemError';
    }

    /**
     * CRITICAL-003 FIX: Sanitize error messages to prevent information disclosure
     * @param {string} errorMessage - Original error message
     * @returns {string} Sanitized error message
     */
    sanitizeErrorMessage(errorMessage) {
        if (!errorMessage) return 'Unknown error occurred';

        // Remove file paths, database names, and internal details
        let sanitized = errorMessage
            .replace(/\/[^\s]*\.[a-zA-Z]+/g, '[PATH]')  // Remove file paths
            .replace(/C:\\[^\s]*/g, '[PATH]')           // Remove Windows paths
            .replace(/localhost:\d+/g, '[HOST]')        // Remove localhost with ports
            .replace(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, '[IP]')  // Remove IP addresses
            .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[EMAIL]')  // Remove emails
            .replace(/process\.env\.[A-Z_]+/g, '[CONFIG]')  // Remove environment variables
            .replace(/at .+:\d+:\d+/g, '[STACK]')       // Remove stack trace locations
            .replace(/MongoDB|Firestore|PostgreSQL|MySQL/gi, 'Database')  // Generic database references
            .replace(/node_modules[^\s]*/g, '[MODULE]'); // Remove node_modules paths

        // If message contains sensitive keywords, return generic message
        const sensitiveKeywords = [
            'password', 'secret', 'key', 'token', 'credential',
            'internal', 'stack', 'trace', 'debug', 'config',
            'environment', 'variable', 'connection', 'database'
        ];

        const lowerMessage = sanitized.toLowerCase();
        if (sensitiveKeywords.some(keyword => lowerMessage.includes(keyword))) {
            return 'An error occurred while processing your request';
        }

        // Truncate long messages
        if (sanitized.length > 100) {
            return 'An error occurred while processing your request';
        }

        return sanitized || 'Service temporarily unavailable';
    }
}

module.exports = EnterpriseErrorHandler;