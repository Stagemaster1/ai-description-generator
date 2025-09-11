// Security Logger Module
// Centralized security event logging for all endpoints
// SESSION 4D1 Implementation - Security Logging

/**
 * Security Logger for tracking authentication and authorization events
 */
class SecurityLogger {
    constructor() {
        this.logLevel = process.env.SECURITY_LOG_LEVEL || 'INFO';
        this.enabledLevels = this.getEnabledLevels(this.logLevel);
    }

    /**
     * Get enabled log levels based on configuration
     * @param {string} level - Current log level
     * @returns {Set} Set of enabled levels
     */
    getEnabledLevels(level) {
        const levels = {
            'DEBUG': ['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'],
            'INFO': ['INFO', 'WARN', 'ERROR', 'CRITICAL'],
            'WARN': ['WARN', 'ERROR', 'CRITICAL'],
            'ERROR': ['ERROR', 'CRITICAL'],
            'CRITICAL': ['CRITICAL']
        };
        return new Set(levels[level] || levels['INFO']);
    }

    /**
     * Format security log entry
     * @param {string} level - Log level
     * @param {string} event - Event type
     * @param {Object} data - Event data
     * @returns {Object} Formatted log entry
     */
    formatLogEntry(level, event, data = {}) {
        return {
            timestamp: new Date().toISOString(),
            level,
            event,
            service: 'netlify-functions',
            environment: process.env.NODE_ENV || 'production',
            ...data
        };
    }

    /**
     * Log security event
     * @param {string} level - Log level
     * @param {string} event - Event type
     * @param {Object} data - Event data
     */
    log(level, event, data = {}) {
        if (!this.enabledLevels.has(level)) {
            return;
        }

        const logEntry = this.formatLogEntry(level, event, data);
        
        // Different output based on level
        if (level === 'CRITICAL' || level === 'ERROR') {
            console.error('[SECURITY]', JSON.stringify(logEntry, null, 2));
        } else if (level === 'WARN') {
            console.warn('[SECURITY]', JSON.stringify(logEntry, null, 2));
        } else {
            console.log('[SECURITY]', JSON.stringify(logEntry, null, 2));
        }
    }

    /**
     * Log authentication success
     * @param {Object} data - Authentication data
     */
    logAuthSuccess(data) {
        this.log('INFO', 'AUTH_SUCCESS', {
            userId: data.userId,
            email: data.email,
            method: data.method || 'firebase_token',
            clientIP: data.clientIP,
            userAgent: data.userAgent,
            endpoint: data.endpoint
        });
    }

    /**
     * Log authentication failure
     * @param {Object} data - Authentication failure data
     */
    logAuthFailure(data) {
        this.log('WARN', 'AUTH_FAILURE', {
            reason: data.reason,
            error: data.error,
            clientIP: data.clientIP,
            userAgent: data.userAgent,
            endpoint: data.endpoint,
            attemptedMethod: data.method
        });
    }

    /**
     * Log authorization failure
     * @param {Object} data - Authorization failure data
     */
    logAuthzFailure(data) {
        this.log('WARN', 'AUTHZ_FAILURE', {
            userId: data.userId,
            email: data.email,
            reason: data.reason,
            requiredPermission: data.requiredPermission,
            currentPermissions: data.currentPermissions,
            clientIP: data.clientIP,
            endpoint: data.endpoint
        });
    }

    /**
     * Log subscription validation failure
     * @param {Object} data - Subscription failure data
     */
    logSubscriptionFailure(data) {
        this.log('WARN', 'SUBSCRIPTION_FAILURE', {
            userId: data.userId,
            email: data.email,
            subscriptionType: data.subscriptionType,
            currentUsage: data.currentUsage,
            maxUsage: data.maxUsage,
            reason: data.reason,
            clientIP: data.clientIP,
            endpoint: data.endpoint
        });
    }

    /**
     * Log rate limit exceeded
     * @param {Object} data - Rate limit data
     */
    logRateLimitExceeded(data) {
        this.log('WARN', 'RATE_LIMIT_EXCEEDED', {
            clientIP: data.clientIP,
            endpoint: data.endpoint,
            requestCount: data.requestCount,
            timeWindow: data.timeWindow,
            userAgent: data.userAgent
        });
    }

    /**
     * Log webhook verification failure
     * @param {Object} data - Webhook verification data
     */
    logWebhookFailure(data) {
        this.log('ERROR', 'WEBHOOK_VERIFICATION_FAILURE', {
            webhookType: data.webhookType,
            reason: data.reason,
            error: data.error,
            sourceIP: data.sourceIP,
            headers: data.headers,
            bodyHash: data.bodyHash
        });
    }

    /**
     * Log webhook verification success
     * @param {Object} data - Webhook verification data
     */
    logWebhookSuccess(data) {
        this.log('INFO', 'WEBHOOK_VERIFICATION_SUCCESS', {
            webhookType: data.webhookType,
            eventId: data.eventId,
            eventType: data.eventType,
            sourceIP: data.sourceIP,
            transmissionId: data.transmissionId
        });
    }

    /**
     * Log suspicious activity
     * @param {Object} data - Suspicious activity data
     */
    logSuspiciousActivity(data) {
        this.log('CRITICAL', 'SUSPICIOUS_ACTIVITY', {
            activityType: data.activityType,
            description: data.description,
            clientIP: data.clientIP,
            userAgent: data.userAgent,
            userId: data.userId,
            endpoint: data.endpoint,
            additionalData: data.additionalData
        });
    }

    /**
     * Log security configuration issue
     * @param {Object} data - Configuration issue data
     */
    logConfigIssue(data) {
        this.log('ERROR', 'SECURITY_CONFIG_ISSUE', {
            component: data.component,
            issue: data.issue,
            severity: data.severity,
            recommendation: data.recommendation
        });
    }

    /**
     * Log token validation failure
     * @param {Object} data - Token validation data
     */
    logTokenValidationFailure(data) {
        this.log('WARN', 'TOKEN_VALIDATION_FAILURE', {
            tokenType: data.tokenType,
            reason: data.reason,
            error: data.error,
            userId: data.userId,
            clientIP: data.clientIP,
            endpoint: data.endpoint,
            tokenAge: data.tokenAge,
            tokenExpired: data.tokenExpired
        });
    }

    /**
     * Log successful operation
     * @param {Object} data - Operation data
     */
    logOperationSuccess(data) {
        this.log('INFO', 'OPERATION_SUCCESS', {
            operation: data.operation,
            userId: data.userId,
            endpoint: data.endpoint,
            duration: data.duration,
            resourcesAccessed: data.resourcesAccessed
        });
    }

    /**
     * Log failed operation
     * @param {Object} data - Operation failure data
     */
    logOperationFailure(data) {
        this.log('ERROR', 'OPERATION_FAILURE', {
            operation: data.operation,
            userId: data.userId,
            endpoint: data.endpoint,
            error: data.error,
            duration: data.duration,
            stackTrace: data.stackTrace
        });
    }

    /**
     * SESSION 4D3: Log unauthorized admin access attempt
     * @param {Object} data - Unauthorized access data
     */
    logUnauthorizedAdminAccess(data) {
        this.log('CRITICAL', 'UNAUTHORIZED_ADMIN_ACCESS', {
            userId: data.userId,
            email: data.email,
            attemptedResource: data.attemptedResource,
            userRole: data.userRole,
            clientIP: data.clientIP,
            timestamp: data.timestamp,
            reason: data.reason || 'insufficient_privileges'
        });
    }

    /**
     * SESSION 4D3: Log successful admin access
     * @param {Object} data - Admin access data
     */
    logAdminAccess(data) {
        this.log('INFO', 'ADMIN_ACCESS_SUCCESS', {
            userId: data.userId,
            email: data.email,
            adminRole: data.adminRole,
            resourceAccessed: data.resourceAccessed,
            clientIP: data.clientIP,
            timestamp: data.timestamp
        });
    }

    /**
     * SESSION 4D3: Log admin validation error
     * @param {Object} data - Admin validation error data
     */
    logAdminValidationError(data) {
        this.log('ERROR', 'ADMIN_VALIDATION_ERROR', {
            userId: data.userId,
            email: data.email,
            error: data.error,
            timestamp: data.timestamp,
            validationStep: data.validationStep || 'role_check'
        });
    }

    /**
     * Log environment configuration check
     */
    logEnvironmentCheck() {
        const requiredVars = [
            'FIREBASE_PROJECT_ID',
            'FIREBASE_PRIVATE_KEY',
            'FIREBASE_CLIENT_EMAIL',
            'PAYPAL_CLIENT_ID',
            'PAYPAL_CLIENT_SECRET',
            'PAYPAL_WEBHOOK_ID',
            'OPENAI_API_KEY'
        ];

        const missingVars = requiredVars.filter(varName => !process.env[varName]);
        const hasSecrets = requiredVars.filter(varName => process.env[varName]);

        this.log('INFO', 'ENVIRONMENT_CHECK', {
            requiredVariables: requiredVars.length,
            configuredVariables: hasSecrets.length,
            missingVariables: missingVars.length,
            missingVarNames: missingVars,
            environment: process.env.NODE_ENV || 'production'
        });

        if (missingVars.length > 0) {
            this.logConfigIssue({
                component: 'environment_variables',
                issue: `Missing required environment variables: ${missingVars.join(', ')}`,
                severity: 'HIGH',
                recommendation: 'Configure all required environment variables before deployment'
            });
        }
    }
}

// Export singleton instance
const securityLogger = new SecurityLogger();

// Log environment check on module load
securityLogger.logEnvironmentCheck();

module.exports = securityLogger;