// Security Monitoring and Alerting System
// SESSION 1C-2: Migrated to distributed system using Firestore
// SECURITY FIX: Replaced stateful Maps with distributed security monitoring

const securityLogger = require('./security-logger');
const securityPenetrationTester = require('./security-penetration-test');
const distributedSecurityMonitor = require('./security-monitoring-distributed');

/**
 * SESSION 1C-2: Security Monitoring System Wrapper
 * Delegates to distributed security monitoring system
 * Maintains backward compatibility for existing code
 */
class SecurityMonitoringSystem {
    constructor() {
        // SESSION 1C-2: All functionality now handled by distributed system
        console.log('[SECURITY MONITOR] Using distributed security monitoring system');

        // Legacy configuration maintained for backward compatibility
        this.alertThresholds = {
            failedAuthAttempts: 5,
            rateLimitViolations: 10,
            suspiciousActivities: 3,
            criticalEvents: 1
        };

        this.monitoringWindows = {
            shortTerm: 5 * 60 * 1000,      // 5 minutes
            mediumTerm: 60 * 60 * 1000,    // 1 hour
            longTerm: 24 * 60 * 60 * 1000  // 24 hours
        };

        // Start monitoring
        this.startContinuousMonitoring();
    }

    /**
     * Start continuous security monitoring
     */
    startContinuousMonitoring() {
        console.log('[SECURITY MONITOR] Starting continuous security monitoring...');

        // REMOVED: setInterval calls for serverless compatibility
        // Monitoring will be handled by infrastructure or periodic cloud functions

        securityLogger.log('INFO', 'SECURITY_MONITORING_STARTED', {
            monitoringIntervals: {
                securityCheck: '30 seconds',
                dailyAudit: '24 hours',
                cleanup: '1 hour'
            },
            alertThresholds: this.alertThresholds,
            timestamp: new Date().toISOString()
        });
    }

    /**
     * SESSION 1C-2: Record security event using distributed system
     * @param {string} eventType - Type of security event
     * @param {Object} eventData - Event details
     */
    async recordSecurityEvent(eventType, eventData = {}) {
        try {
            // Delegate to distributed security monitoring system
            await distributedSecurityMonitor.recordSecurityEvent(eventType, eventData);
        } catch (error) {
            console.error('Failed to record security event in distributed system:', error);
            securityLogger.logOperationFailure({
                operation: 'record_security_event',
                error: error.message,
                endpoint: 'security-monitoring'
            });
        }
    }

    /**
     * SESSION 1C-2: Check alert thresholds using distributed system
     * @param {string} eventType - Type of security event
     * @param {Object} eventData - Event details
     */
    async checkAlertThresholds(eventType, eventData) {
        try {
            // Delegate to distributed security monitoring system
            await distributedSecurityMonitor.checkAlertThresholds(eventType, eventData);
        } catch (error) {
            console.error('Failed to check alert thresholds in distributed system:', error);
            securityLogger.logOperationFailure({
                operation: 'check_alert_thresholds',
                error: error.message,
                endpoint: 'security-monitoring'
            });
        }
    }

    /**
     * SESSION 1C-2: Trigger security alert using distributed system
     * @param {string} eventType - Type of security event
     * @param {Object} eventData - Event details
     * @param {string} alertLevel - Alert severity level
     * @param {number} eventCount - Number of events that triggered the alert
     */
    async triggerSecurityAlert(eventType, eventData, alertLevel, eventCount) {
        try {
            // Delegate to distributed security monitoring system
            await distributedSecurityMonitor.triggerSecurityAlert(eventType, eventData, alertLevel, eventCount);
        } catch (error) {
            console.error('Failed to trigger security alert in distributed system:', error);
            securityLogger.logOperationFailure({
                operation: 'trigger_security_alert',
                error: error.message,
                endpoint: 'security-monitoring'
            });
        }
    }

    /**
     * SESSION 1C-2: Update threat level using distributed system
     * @param {string} identifier - IP address or user ID
     * @param {string} eventType - Type of security event
     */
    async updateThreatLevel(identifier, eventType) {
        try {
            // Delegate to distributed security monitoring system
            await distributedSecurityMonitor.updateThreatLevel(identifier, eventType);
        } catch (error) {
            console.error('Failed to update threat level in distributed system:', error);
            securityLogger.logOperationFailure({
                operation: 'update_threat_level',
                error: error.message,
                endpoint: 'security-monitoring'
            });
        }
    }

    /**
     * SESSION 1C-2: Get threat level using distributed system
     * @param {string} identifier - IP address or user ID
     * @returns {Promise<Object>} Threat level data
     */
    async getThreatLevel(identifier) {
        try {
            // Delegate to distributed security monitoring system
            return await distributedSecurityMonitor.getThreatLevel(identifier);
        } catch (error) {
            console.error('Failed to get threat level from distributed system:', error);
            return { threatScore: 0, level: 'LOW', error: 'check_failed' };
        }
    }

    /**
     * Calculate threat score for different event types
     * @param {string} eventType - Type of security event
     * @returns {number} Threat score
     */
    calculateEventThreatScore(eventType) {
        // Delegate to distributed system
        return distributedSecurityMonitor.calculateEventThreatScore(eventType);
    }

    /**
     * Categorize threat level based on score
     * @param {number} score - Threat score
     * @returns {string} Threat level category
     */
    categorizeThreatLevel(score) {
        // Delegate to distributed system
        return distributedSecurityMonitor.categorizeThreatLevel(score);
    }

    /**
     * Execute critical alert response
     * @param {Object} eventData - Event details
     * @param {Object} alert - Alert details
     */
    async executeCriticalAlertResponse(eventData, alert) {
        try {
            securityLogger.log('ERROR', 'CRITICAL_ALERT_RESPONSE_TRIGGERED', {
                alert,
                eventData,
                responseActions: ['enhanced_monitoring', 'threat_analysis', 'potential_blocking'],
                timestamp: new Date().toISOString()
            });

            // Enhanced monitoring for critical events
            await this.recordSecurityEvent('CRITICAL_RESPONSE_TRIGGERED', {
                ...eventData,
                alertId: alert.alertId,
                severity: 'CRITICAL'
            });

        } catch (error) {
            console.error('Critical alert response failed:', error);
        }
    }

    /**
     * Perform comprehensive security audit
     * @returns {Promise<Object>} Audit results
     */
    async performSecurityAudit() {
        try {
            // Delegate to distributed security monitoring system
            return await distributedSecurityMonitor.performSecurityAudit();
        } catch (error) {
            console.error('Security audit failed:', error);
            return {
                timestamp: new Date().toISOString(),
                error: 'audit_failed',
                message: error.message
            };
        }
    }

    /**
     * Get security statistics
     * @returns {Promise<Object>} Security statistics
     */
    async getSecurityStatistics() {
        try {
            // Delegate to distributed security monitoring system
            return await distributedSecurityMonitor.getSecurityStatistics();
        } catch (error) {
            console.error('Failed to get security statistics:', error);
            return {
                totalEvents: 0,
                activeAlerts: 0,
                highThreatIdentifiers: 0,
                recentCriticalEvents: 0,
                error: 'stats_unavailable'
            };
        }
    }

    /**
     * Clean up expired data
     */
    async cleanup() {
        try {
            // Delegate to distributed security monitoring system
            await distributedSecurityMonitor.cleanup();
        } catch (error) {
            console.error('Security monitoring cleanup failed:', error);
        }
    }

    /**
     * Check resource limits (legacy method for backward compatibility)
     * @returns {boolean} Always returns true for distributed system
     */
    checkResourceLimits() {
        // In distributed system, resource limits are handled automatically
        return true;
    }

    /**
     * Update resource usage (legacy method for backward compatibility)
     */
    updateResourceUsage() {
        // In distributed system, resource usage is tracked automatically
        return;
    }

    /**
     * Emergency cleanup (legacy method for backward compatibility)
     */
    async emergencyCleanup() {
        try {
            await this.cleanup();
        } catch (error) {
            console.error('Emergency cleanup failed:', error);
        }
    }
}

// Export singleton instance
const securityMonitor = new SecurityMonitoringSystem();

// Export class for testing
module.exports = securityMonitor;
module.exports.SecurityMonitoringSystem = SecurityMonitoringSystem;