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
     * Check if alert thresholds are exceeded
     * @param {string} eventType - Type of security event
     * @param {Object} eventData - Event details
     */
    checkAlertThresholds(eventType, eventData) {
        const now = Date.now();
        const windowStart = now - this.monitoringWindows.shortTerm;
        
        // Count recent events of this type
        let recentEventCount = 0;
        for (const [key, events] of this.eventCounts.entries()) {
            if (key.startsWith(eventType)) {
                recentEventCount += events.filter(event => event.timestamp > windowStart).length;
            }
        }
        
        // Check thresholds and trigger alerts
        switch (eventType) {
            case 'AUTH_FAILURE':
                if (recentEventCount >= this.alertThresholds.failedAuthAttempts) {
                    this.triggerSecurityAlert('MULTIPLE_AUTH_FAILURES', {
                        count: recentEventCount,
                        timeWindow: '5 minutes',
                        ...eventData
                    });
                }
                break;
                
            case 'RATE_LIMIT_EXCEEDED':
                if (recentEventCount >= this.alertThresholds.rateLimitViolations) {
                    this.triggerSecurityAlert('RATE_LIMIT_ATTACK', {
                        count: recentEventCount,
                        timeWindow: '5 minutes',
                        ...eventData
                    });
                }
                break;
                
            case 'SUSPICIOUS_ACTIVITY':
                if (recentEventCount >= this.alertThresholds.suspiciousActivities) {
                    this.triggerSecurityAlert('SUSPICIOUS_BEHAVIOR_PATTERN', {
                        count: recentEventCount,
                        timeWindow: '5 minutes',
                        ...eventData
                    });
                }
                break;
                
            case 'UNAUTHORIZED_ADMIN_ACCESS':
                this.triggerSecurityAlert('ADMIN_ACCESS_VIOLATION', {
                    severity: 'CRITICAL',
                    immediateAction: 'BLOCK_IP',
                    ...eventData
                });
                break;
        }
    }

    /**
     * Trigger security alert
     * @param {string} alertType - Type of alert
     * @param {Object} alertData - Alert details
     */
    triggerSecurityAlert(alertType, alertData) {
        try {
            // SECURITY FIX: Check alert history limits before adding new alerts
            if (this.alertHistory.length >= this.resourceLimits.maxAlertHistory) {
                // Remove oldest alerts to make room (keep 80% of limit)
                const keepCount = Math.floor(this.resourceLimits.maxAlertHistory * 0.8);
                this.alertHistory = this.alertHistory.slice(-keepCount);
                
                securityLogger.log('WARN', 'ALERT_HISTORY_CLEANUP_TRIGGERED', {
                    removedAlerts: this.alertHistory.length - keepCount,
                    remainingAlerts: keepCount,
                    reason: 'resource_limit_reached'
                });
            }

            const alert = {
                id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                type: alertType,
                severity: alertData.severity || this.determineSeverity(alertType),
                timestamp: new Date().toISOString(),
                data: alertData,
                status: 'ACTIVE'
            };
            
            this.alertHistory.push(alert);
            this.resourceUsage.alertHistorySize = this.alertHistory.length;
            
            // Log the alert
            securityLogger.log('CRITICAL', 'SECURITY_ALERT_TRIGGERED', {
                alertId: alert.id,
                alertType: alertType,
                severity: alert.severity,
                clientIP: alertData.clientIP,
                userId: alertData.userId,
                ...alertData
            });
            
            // Take automated response if needed
            this.takeAutomatedResponse(alert);
            
            console.log(`[SECURITY ALERT] ${alertType}: ${JSON.stringify(alertData, null, 2)}`);
            
        } catch (error) {
            securityLogger.logOperationFailure({
                operation: 'trigger_security_alert',
                error: error.message,
                endpoint: 'security-monitoring'
            });
        }
    }

    /**
     * Determine alert severity based on type
     * @param {string} alertType - Type of alert
     * @returns {string} Severity level
     */
    determineSeverity(alertType) {
        const severityMap = {
            'ADMIN_ACCESS_VIOLATION': 'CRITICAL',
            'MULTIPLE_AUTH_FAILURES': 'HIGH',
            'RATE_LIMIT_ATTACK': 'MEDIUM',
            'SUSPICIOUS_BEHAVIOR_PATTERN': 'MEDIUM',
            'WEBHOOK_VERIFICATION_FAILURE': 'HIGH',
            'TOKEN_REPLAY_DETECTED': 'HIGH'
        };
        
        return severityMap[alertType] || 'MEDIUM';
    }

    /**
     * Take automated response to security alerts
     * @param {Object} alert - Security alert object
     */
    takeAutomatedResponse(alert) {
        switch (alert.type) {
            case 'ADMIN_ACCESS_VIOLATION':
                // Log critical violation and prepare IP blocking
                securityLogger.log('CRITICAL', 'AUTOMATED_RESPONSE_ADMIN_VIOLATION', {
                    alertId: alert.id,
                    action: 'IP_BLOCKING_RECOMMENDED',
                    clientIP: alert.data.clientIP
                });
                break;
                
            case 'RATE_LIMIT_ATTACK':
                // Extended rate limiting
                securityLogger.log('WARN', 'AUTOMATED_RESPONSE_RATE_LIMIT', {
                    alertId: alert.id,
                    action: 'EXTENDED_RATE_LIMITING',
                    clientIP: alert.data.clientIP
                });
                break;
                
            case 'MULTIPLE_AUTH_FAILURES':
                // Temporary account lockout consideration
                securityLogger.log('WARN', 'AUTOMATED_RESPONSE_AUTH_FAILURES', {
                    alertId: alert.id,
                    action: 'ACCOUNT_LOCKOUT_CONSIDERED',
                    userId: alert.data.userId
                });
                break;
        }
    }

    /**
     * Update threat level for IP/user
     * @param {string} identifier - IP address or user ID
     * @param {string} eventType - Type of security event
     */
    updateThreatLevel(identifier, eventType) {
        try {
            // SECURITY FIX: Check threat level limits before adding new entries
            if (!this.threatLevels.has(identifier)) {
                if (this.threatLevels.size >= this.resourceLimits.maxThreatLevels) {
                    securityLogger.log('WARN', 'THREAT_LEVEL_LIMIT_REACHED', {
                        identifier: identifier,
                        eventType: eventType,
                        currentThreatLevels: this.threatLevels.size,
                        action: 'threat_level_update_skipped'
                    });
                    return; // Skip adding new threat level entries
                }
                
                this.threatLevels.set(identifier, {
                    level: 0,
                    events: [],
                    lastUpdated: Date.now()
                });
                this.resourceUsage.threatLevelsSize++;
            }
            
            const threat = this.threatLevels.get(identifier);
            
            // Increase threat level based on event type
            const threatIncrease = {
                'AUTH_FAILURE': 2,
                'RATE_LIMIT_EXCEEDED': 3,
                'SUSPICIOUS_ACTIVITY': 5,
                'UNAUTHORIZED_ADMIN_ACCESS': 10,
                'WEBHOOK_VERIFICATION_FAILURE': 4,
                'TOKEN_VALIDATION_FAILURE': 3,
                'TOKEN_REPLAY_ATTACK': 8
            };
            
            threat.level += threatIncrease[eventType] || 1;
            
            // SECURITY FIX: Limit threat event history to prevent memory exhaustion
            threat.events.push({
                type: eventType,
                timestamp: Date.now()
            });
            
            // Keep only last 20 events per threat
            if (threat.events.length > 20) {
                threat.events = threat.events.slice(-20);
            }
            
            threat.lastUpdated = Date.now();
            
            // Cap threat level at 100
            threat.level = Math.min(threat.level, 100);
            
            // Trigger high threat level alert
            if (threat.level >= 50) {
                this.triggerSecurityAlert('HIGH_THREAT_LEVEL', {
                    identifier: identifier,
                    threatLevel: threat.level,
                    recentEvents: threat.events.slice(-5)
                });
            }
            
        } catch (error) {
            securityLogger.logOperationFailure({
                operation: 'update_threat_level',
                error: error.message,
                endpoint: 'security-monitoring',
                identifier: identifier
            });
        }
    }

    /**
     * Perform periodic security check
     */
    performSecurityCheck() {
        const now = Date.now();
        const recentThreshold = now - this.monitoringWindows.shortTerm;
        
        // Count recent security events
        let recentEvents = 0;
        let authFailures = 0;
        let suspiciousActivities = 0;
        
        for (const [key, events] of this.eventCounts.entries()) {
            const recentEventList = events.filter(event => event.timestamp > recentThreshold);
            recentEvents += recentEventList.length;
            
            if (key.includes('AUTH_FAILURE')) {
                authFailures += recentEventList.length;
            }
            if (key.includes('SUSPICIOUS_ACTIVITY')) {
                suspiciousActivities += recentEventList.length;
            }
        }
        
        // Log security status
        securityLogger.log('INFO', 'PERIODIC_SECURITY_CHECK', {
            timeWindow: '5 minutes',
            totalRecentEvents: recentEvents,
            authFailures: authFailures,
            suspiciousActivities: suspiciousActivities,
            activeAlerts: this.alertHistory.filter(alert => alert.status === 'ACTIVE').length,
            monitoredIPs: this.threatLevels.size,
            timestamp: new Date().toISOString()
        });
        
        // Auto-resolve old alerts
        this.autoResolveAlerts();
    }

    /**
     * Perform daily comprehensive security audit
     */
    async performDailySecurityAudit() {
        console.log('[SECURITY MONITOR] Performing daily security audit...');
        
        try {
            // Run penetration tests
            const pentestResults = await securityPenetrationTester.runPenetrationTests();
            
            // Generate security report
            const securityReport = securityPenetrationTester.generateSecurityReport();
            
            // Log daily audit results
            securityLogger.log('INFO', 'DAILY_SECURITY_AUDIT', {
                auditDate: new Date().toISOString(),
                securityScore: securityReport.summary.overallScore,
                vulnerabilities: securityReport.summary.totalVulnerabilities,
                criticalVulnerabilities: securityReport.summary.criticalVulnerabilities,
                testResults: pentestResults.testResults?.length || 0,
                recommendations: securityReport.recommendations?.length || 0
            });
            
            // Trigger alert for low security scores
            if (securityReport.summary.overallScore < 70) {
                this.triggerSecurityAlert('LOW_SECURITY_SCORE', {
                    score: securityReport.summary.overallScore,
                    vulnerabilities: securityReport.summary.totalVulnerabilities,
                    severity: 'HIGH'
                });
            }
            
            // Trigger alert for critical vulnerabilities
            if (securityReport.summary.criticalVulnerabilities > 0) {
                this.triggerSecurityAlert('CRITICAL_VULNERABILITIES_FOUND', {
                    count: securityReport.summary.criticalVulnerabilities,
                    severity: 'CRITICAL'
                });
            }
            
            return securityReport;
            
        } catch (error) {
            securityLogger.log('ERROR', 'DAILY_AUDIT_FAILED', {
                error: error.message,
                stackTrace: error.stack,
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Auto-resolve old alerts
     */
    autoResolveAlerts() {
        const now = Date.now();
        const autoResolveWindow = 60 * 60 * 1000; // 1 hour
        
        this.alertHistory.forEach(alert => {
            if (alert.status === 'ACTIVE') {
                const alertAge = now - new Date(alert.timestamp).getTime();
                if (alertAge > autoResolveWindow) {
                    alert.status = 'AUTO_RESOLVED';
                    
                    securityLogger.log('INFO', 'ALERT_AUTO_RESOLVED', {
                        alertId: alert.id,
                        alertType: alert.type,
                        age: Math.round(alertAge / 1000 / 60) + ' minutes',
                        reason: 'timeout'
                    });
                }
            }
        });
    }

    /**
     * Clean up old monitoring events
     */
    cleanupOldEvents() {
        const now = Date.now();
        const cleanupThreshold = now - this.monitoringWindows.longTerm;
        
        let cleanedEvents = 0;
        let removedEventKeys = 0;
        
        for (const [key, events] of this.eventCounts.entries()) {
            const recentEvents = events.filter(event => event.timestamp > cleanupThreshold);
            cleanedEvents += events.length - recentEvents.length;
            
            if (recentEvents.length === 0) {
                this.eventCounts.delete(key);
                removedEventKeys++;
            } else {
                this.eventCounts.set(key, recentEvents);
            }
        }
        
        // Clean up old threat levels
        let cleanedThreats = 0;
        for (const [identifier, threat] of this.threatLevels.entries()) {
            if (now - threat.lastUpdated > this.monitoringWindows.longTerm) {
                this.threatLevels.delete(identifier);
                cleanedThreats++;
            }
        }
        
        // Update resource usage after cleanup
        this.resourceUsage.eventCountsSize = this.eventCounts.size;
        this.resourceUsage.threatLevelsSize = this.threatLevels.size;
        this.resourceUsage.alertHistorySize = this.alertHistory.length;
        
        securityLogger.log('INFO', 'MONITORING_CLEANUP_COMPLETED', {
            cleanedEvents: cleanedEvents,
            removedEventKeys: removedEventKeys,
            cleanedThreats: cleanedThreats,
            remainingEventKeys: this.eventCounts.size,
            remainingThreats: this.threatLevels.size,
            remainingAlerts: this.alertHistory.length,
            resourceUsage: this.resourceUsage,
            timestamp: new Date().toISOString()
        });
    }

    /**
     * SECURITY FIX: Check resource limits and trigger cleanup if needed
     * @returns {boolean} True if resources are within limits
     */
    checkResourceLimits() {
        const eventCountsUsage = this.eventCounts.size / this.resourceLimits.maxEventEntries;
        const alertHistoryUsage = this.alertHistory.length / this.resourceLimits.maxAlertHistory;
        const threatLevelsUsage = this.threatLevels.size / this.resourceLimits.maxThreatLevels;
        
        const maxUsage = Math.max(eventCountsUsage, alertHistoryUsage, threatLevelsUsage);
        
        // Trigger emergency cleanup if near resource limits
        if (maxUsage >= this.resourceLimits.emergencyCleanupThreshold) {
            securityLogger.log('WARN', 'EMERGENCY_RESOURCE_CLEANUP_TRIGGERED', {
                eventCountsUsage: Math.round(eventCountsUsage * 100) + '%',
                alertHistoryUsage: Math.round(alertHistoryUsage * 100) + '%',
                threatLevelsUsage: Math.round(threatLevelsUsage * 100) + '%',
                maxUsage: Math.round(maxUsage * 100) + '%'
            });
            
            this.performEmergencyCleanup();
            return maxUsage < 1.0; // Still check if within absolute limits
        }
        
        return maxUsage < 1.0; // Return true if within limits
    }

    /**
     * SECURITY FIX: Update resource usage tracking
     */
    updateResourceUsage() {
        this.resourceUsage.eventCountsSize = this.eventCounts.size;
        this.resourceUsage.alertHistorySize = this.alertHistory.length;
        this.resourceUsage.threatLevelsSize = this.threatLevels.size;
        this.resourceUsage.lastResourceCheck = Date.now();
    }

    /**
     * SECURITY FIX: Emergency cleanup to prevent resource exhaustion
     */
    performEmergencyCleanup() {
        const now = Date.now();
        const emergencyThreshold = now - (this.monitoringWindows.mediumTerm * 2); // 2 hours
        
        let emergencyCleanedEvents = 0;
        let emergencyRemovedKeys = 0;
        
        // More aggressive event cleanup
        for (const [key, events] of this.eventCounts.entries()) {
            const recentEvents = events.filter(event => event.timestamp > emergencyThreshold);
            emergencyCleanedEvents += events.length - recentEvents.length;
            
            if (recentEvents.length === 0) {
                this.eventCounts.delete(key);
                emergencyRemovedKeys++;
            } else {
                // Keep only most recent events if still too many
                const maxEvents = Math.floor(this.resourceLimits.maxEventsPerEntry * 0.5);
                this.eventCounts.set(key, recentEvents.slice(-maxEvents));
            }
        }
        
        // Emergency threat level cleanup
        let emergencyCleanedThreats = 0;
        for (const [identifier, threat] of this.threatLevels.entries()) {
            if (now - threat.lastUpdated > this.monitoringWindows.mediumTerm) {
                this.threatLevels.delete(identifier);
                emergencyCleanedThreats++;
            }
        }
        
        // Emergency alert history cleanup
        if (this.alertHistory.length > this.resourceLimits.maxAlertHistory * 0.5) {
            const keepCount = Math.floor(this.resourceLimits.maxAlertHistory * 0.3);
            this.alertHistory = this.alertHistory.slice(-keepCount);
        }
        
        this.updateResourceUsage();
        
        securityLogger.log('CRITICAL', 'EMERGENCY_CLEANUP_COMPLETED', {
            emergencyCleanedEvents: emergencyCleanedEvents,
            emergencyRemovedKeys: emergencyRemovedKeys,
            emergencyCleanedThreats: emergencyCleanedThreats,
            finalResourceUsage: this.resourceUsage,
            reason: 'resource_exhaustion_prevention'
        });
    }

    /**
     * Get current security status
     * @returns {Object} Current security monitoring status
     */
    getSecurityStatus() {
        const now = Date.now();
        const recentThreshold = now - this.monitoringWindows.shortTerm;
        
        // Count recent events
        let recentEvents = 0;
        for (const [key, events] of this.eventCounts.entries()) {
            recentEvents += events.filter(event => event.timestamp > recentThreshold).length;
        }
        
        // Get active alerts
        const activeAlerts = this.alertHistory.filter(alert => alert.status === 'ACTIVE');
        
        // Calculate threat distribution
        const threatDistribution = {
            low: 0,      // 0-25
            medium: 0,   // 26-50
            high: 0,     // 51-75
            critical: 0  // 76-100
        };
        
        for (const [identifier, threat] of this.threatLevels.entries()) {
            if (threat.level <= 25) threatDistribution.low++;
            else if (threat.level <= 50) threatDistribution.medium++;
            else if (threat.level <= 75) threatDistribution.high++;
            else threatDistribution.critical++;
        }
        
        return {
            status: 'MONITORING_ACTIVE',
            timestamp: new Date().toISOString(),
            recentEvents: recentEvents,
            activeAlerts: activeAlerts.length,
            monitoredEntities: this.threatLevels.size,
            threatDistribution: threatDistribution,
            alertHistory: this.alertHistory.slice(-10), // Last 10 alerts
            uptime: process.uptime(),
            // SECURITY FIX: Include resource usage monitoring
            resourceUsage: {
                ...this.resourceUsage,
                limits: this.resourceLimits,
                usagePercentages: {
                    eventCounts: Math.round((this.eventCounts.size / this.resourceLimits.maxEventEntries) * 100),
                    alertHistory: Math.round((this.alertHistory.length / this.resourceLimits.maxAlertHistory) * 100),
                    threatLevels: Math.round((this.threatLevels.size / this.resourceLimits.maxThreatLevels) * 100)
                }
            }
        };
    }

    /**
     * Manual security event reporting for external use
     * @param {string} eventType - Type of security event
     * @param {Object} eventData - Event details
     */
    reportSecurityEvent(eventType, eventData) {
        this.recordSecurityEvent(eventType, eventData);
        
        securityLogger.log('INFO', 'MANUAL_SECURITY_EVENT_REPORTED', {
            eventType: eventType,
            reportedBy: eventData.reportedBy || 'system',
            ...eventData
        });
    }
}

// Export singleton instance for system-wide use
const securityMonitoringSystem = new SecurityMonitoringSystem();

// Export monitoring functions for use in other modules
module.exports = {
    system: securityMonitoringSystem,
    recordEvent: (eventType, eventData) => securityMonitoringSystem.recordSecurityEvent(eventType, eventData),
    getStatus: () => securityMonitoringSystem.getSecurityStatus(),
    reportEvent: (eventType, eventData) => securityMonitoringSystem.reportSecurityEvent(eventType, eventData)
};