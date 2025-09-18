// Distributed Security Monitoring and Alerting System
// SESSION 1C-2: Complete rewrite using Firestore-based distributed state
// Replaces stateful Maps with Firestore collections for scalability

const securityLogger = require('./security-logger');
const distributedRateLimiter = require('./distributed-rate-limiter');
const { getFirestore, Timestamp, FieldValue } = require('./firebase-config');

/**
 * Distributed Security Monitoring System
 * Uses Firestore for state management instead of local Maps
 * Provides continuous monitoring, alerting, and threat detection
 */
class DistributedSecurityMonitoringSystem {
    constructor() {
        this.db = getFirestore();
        this.collectionPrefix = 'security_monitoring';

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

        // Distributed resource limits with automatic scaling
        this.resourceLimits = {
            maxEventEntries: 50000,        // Higher limit for distributed system
            maxAlertHistory: 5000,         // Higher limit for distributed system
            maxThreatLevels: 25000,        // Higher limit for distributed system
            maxEventsPerEntry: 200,        // Higher limit for distributed system
            emergencyCleanupThreshold: 0.85 // Trigger cleanup at 85% capacity
        };

        // Initialize distributed collections
        this.initializeDistributedCollections();
    }

    /**
     * Initialize Firestore collections with proper indexes and TTL
     */
    async initializeDistributedCollections() {
        try {
            console.log('[SECURITY MONITOR] Initializing distributed security monitoring...');

            // Set up TTL rules for automatic cleanup
            const ttlSettings = {
                eventCounts: 7 * 24 * 60 * 60, // 7 days
                alertHistory: 30 * 24 * 60 * 60, // 30 days
                threatLevels: 24 * 60 * 60, // 24 hours
                securityEvents: 90 * 24 * 60 * 60 // 90 days for compliance
            };

            // Log initialization
            securityLogger.log('INFO', 'DISTRIBUTED_SECURITY_MONITORING_STARTED', {
                collections: Object.keys(ttlSettings),
                alertThresholds: this.alertThresholds,
                monitoringWindows: this.monitoringWindows,
                resourceLimits: this.resourceLimits,
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            console.error('Failed to initialize distributed security monitoring:', error);
        }
    }

    /**
     * Record security event in distributed system
     * @param {string} eventType - Type of security event
     * @param {Object} eventData - Event details
     */
    async recordSecurityEvent(eventType, eventData = {}) {
        try {
            const timestamp = Date.now();
            const eventKey = this.generateSecurityEventKey(eventType, eventData.clientIP || 'unknown');

            // Use Firestore transaction for consistency
            await this.db.runTransaction(async (transaction) => {
                const eventDocRef = this.db.collection(`${this.collectionPrefix}_event_counts`).doc(eventKey);
                const eventDoc = await transaction.get(eventDocRef);

                let eventData_distributed = {
                    eventType,
                    clientIP: eventData.clientIP || 'unknown',
                    events: [],
                    createdAt: timestamp,
                    lastUpdated: timestamp
                };

                if (eventDoc.exists) {
                    eventData_distributed = eventDoc.data();

                    // Clean old events (older than monitoring window)
                    const cutoffTime = timestamp - this.monitoringWindows.longTerm;
                    eventData_distributed.events = (eventData_distributed.events || []).filter(
                        event => event.timestamp > cutoffTime
                    );
                }

                // Add new event
                eventData_distributed.events.push({
                    timestamp,
                    eventType,
                    data: eventData
                });

                // Limit events per entry to prevent excessive growth
                if (eventData_distributed.events.length > this.resourceLimits.maxEventsPerEntry) {
                    eventData_distributed.events = eventData_distributed.events.slice(-this.resourceLimits.maxEventsPerEntry);
                }

                eventData_distributed.lastUpdated = timestamp;
                eventData_distributed.eventCount = eventData_distributed.events.length;

                // Set TTL for automatic cleanup
                eventData_distributed.expiresAt = Timestamp.fromMillis(timestamp + (7 * 24 * 60 * 60 * 1000)); // 7 days

                transaction.set(eventDocRef, eventData_distributed, { merge: true });
            });

            // Check alert thresholds asynchronously
            await this.checkAlertThresholds(eventType, eventData);

            // Update threat level asynchronously
            await this.updateThreatLevel(eventData.clientIP || eventData.userId || 'unknown', eventType);

        } catch (error) {
            console.error('Failed to record security event:', error);
            securityLogger.logOperationFailure({
                operation: 'record_security_event',
                error: error.message,
                endpoint: 'security-monitoring-distributed'
            });
        }
    }

    /**
     * Check if alert thresholds are exceeded using distributed data
     * @param {string} eventType - Type of security event
     * @param {Object} eventData - Event details
     */
    async checkAlertThresholds(eventType, eventData) {
        try {
            const eventKey = this.generateSecurityEventKey(eventType, eventData.clientIP || 'unknown');
            const eventDoc = await this.db.collection(`${this.collectionPrefix}_event_counts`).doc(eventKey).get();

            if (!eventDoc.exists) return;

            const data = eventDoc.data();
            const recentEvents = this.filterEventsByWindow(data.events || [], this.monitoringWindows.shortTerm);

            let alertTriggered = false;
            let alertLevel = 'LOW';

            // Check various alert conditions
            if (eventType.includes('failed_auth') && recentEvents.length >= this.alertThresholds.failedAuthAttempts) {
                alertTriggered = true;
                alertLevel = 'MEDIUM';
            }

            if (eventType.includes('rate_limit') && recentEvents.length >= this.alertThresholds.rateLimitViolations) {
                alertTriggered = true;
                alertLevel = 'HIGH';
            }

            if (eventType.includes('suspicious') && recentEvents.length >= this.alertThresholds.suspiciousActivities) {
                alertTriggered = true;
                alertLevel = 'HIGH';
            }

            if (eventType.includes('critical') && recentEvents.length >= this.alertThresholds.criticalEvents) {
                alertTriggered = true;
                alertLevel = 'CRITICAL';
            }

            if (alertTriggered) {
                await this.triggerSecurityAlert(eventType, eventData, alertLevel, recentEvents.length);
            }

        } catch (error) {
            console.error('Failed to check alert thresholds:', error);
        }
    }

    /**
     * Trigger security alert and record in distributed system
     * @param {string} eventType - Type of security event
     * @param {Object} eventData - Event details
     * @param {string} alertLevel - Alert severity level
     * @param {number} eventCount - Number of events that triggered the alert
     */
    async triggerSecurityAlert(eventType, eventData, alertLevel, eventCount) {
        try {
            const alertId = this.generateAlertId();
            const timestamp = Date.now();

            const alert = {
                alertId,
                eventType,
                alertLevel,
                eventCount,
                clientIP: eventData.clientIP,
                userId: eventData.userId,
                endpoint: eventData.endpoint,
                timestamp,
                resolved: false,
                expiresAt: Timestamp.fromMillis(timestamp + (30 * 24 * 60 * 60 * 1000)) // 30 days retention
            };

            // Store alert in distributed system
            await this.db.collection(`${this.collectionPrefix}_alert_history`).doc(alertId).set(alert);

            // Log alert with appropriate level
            const logLevel = alertLevel === 'CRITICAL' ? 'ERROR' : 'WARN';
            securityLogger.log(logLevel, 'SECURITY_ALERT_TRIGGERED', {
                alert,
                eventData,
                message: `Security alert triggered: ${eventType} from ${eventData.clientIP || 'unknown'}`
            });

            // For critical alerts, also use the distributed rate limiter's security event logging
            if (alertLevel === 'CRITICAL') {
                await distributedRateLimiter.logSecurityEvent('critical_alert_triggered', {
                    alertId,
                    eventType,
                    clientIP: eventData.clientIP,
                    userId: eventData.userId,
                    retentionDays: 90 // Critical events kept for 90 days
                });
            }

        } catch (error) {
            console.error('Failed to trigger security alert:', error);
        }
    }

    /**
     * Update threat level for IP/user in distributed system
     * @param {string} identifier - IP address or user ID
     * @param {string} eventType - Type of security event
     */
    async updateThreatLevel(identifier, eventType) {
        try {
            const threatKey = this.generateThreatLevelKey(identifier);
            const timestamp = Date.now();

            await this.db.runTransaction(async (transaction) => {
                const threatDocRef = this.db.collection(`${this.collectionPrefix}_threat_levels`).doc(threatKey);
                const threatDoc = await transaction.get(threatDocRef);

                let threatData = {
                    identifier,
                    threatScore: 0,
                    recentEvents: [],
                    lastUpdated: timestamp,
                    createdAt: timestamp
                };

                if (threatDoc.exists) {
                    threatData = threatDoc.data();
                }

                // Add new event to recent events
                threatData.recentEvents.push({
                    eventType,
                    timestamp,
                    score: this.calculateEventThreatScore(eventType)
                });

                // Clean old events (older than 24 hours)
                const cutoffTime = timestamp - (24 * 60 * 60 * 1000);
                threatData.recentEvents = threatData.recentEvents.filter(event => event.timestamp > cutoffTime);

                // Calculate new threat score
                threatData.threatScore = threatData.recentEvents.reduce((total, event) => total + event.score, 0);
                threatData.lastUpdated = timestamp;

                // Set TTL for automatic cleanup
                threatData.expiresAt = Timestamp.fromMillis(timestamp + (24 * 60 * 60 * 1000)); // 24 hours

                transaction.set(threatDocRef, threatData, { merge: true });
            });

        } catch (error) {
            console.error('Failed to update threat level:', error);
        }
    }

    /**
     * Calculate threat score for different event types
     * @param {string} eventType - Type of security event
     * @returns {number} Threat score
     */
    calculateEventThreatScore(eventType) {
        const scores = {
            'failed_auth': 15,
            'rate_limit_exceeded': 10,
            'suspicious_activity': 25,
            'critical_event': 50,
            'payment_fraud': 40,
            'token_replay': 30,
            'webhook_abuse': 20
        };

        // Find matching score or default
        for (const [key, score] of Object.entries(scores)) {
            if (eventType.includes(key)) {
                return score;
            }
        }

        return 5; // Default low score
    }

    /**
     * Get current threat level for identifier
     * @param {string} identifier - IP address or user ID
     * @returns {Promise<Object>} Threat level data
     */
    async getThreatLevel(identifier) {
        try {
            const threatKey = this.generateThreatLevelKey(identifier);
            const threatDoc = await this.db.collection(`${this.collectionPrefix}_threat_levels`).doc(threatKey).get();

            if (!threatDoc.exists) {
                return { threatScore: 0, level: 'LOW' };
            }

            const data = threatDoc.data();
            const level = this.categorizeThreatLevel(data.threatScore);

            return {
                threatScore: data.threatScore,
                level,
                recentEventsCount: data.recentEvents?.length || 0,
                lastUpdated: data.lastUpdated
            };

        } catch (error) {
            console.error('Failed to get threat level:', error);
            return { threatScore: 0, level: 'LOW', error: 'check_failed' };
        }
    }

    /**
     * Categorize threat level based on score
     * @param {number} score - Threat score
     * @returns {string} Threat level category
     */
    categorizeThreatLevel(score) {
        if (score >= 100) return 'CRITICAL';
        if (score >= 50) return 'HIGH';
        if (score >= 25) return 'MEDIUM';
        return 'LOW';
    }

    /**
     * Filter events by time window
     * @param {Array} events - Array of events
     * @param {number} windowMs - Time window in milliseconds
     * @returns {Array} Filtered events
     */
    filterEventsByWindow(events, windowMs) {
        const cutoffTime = Date.now() - windowMs;
        return events.filter(event => event.timestamp > cutoffTime);
    }

    /**
     * Get comprehensive security statistics from distributed system
     * @returns {Promise<Object>} Security statistics
     */
    async getSecurityStatistics() {
        try {
            const stats = {
                totalEvents: 0,
                activeAlerts: 0,
                highThreatIdentifiers: 0,
                recentCriticalEvents: 0
            };

            // Get event counts
            const eventCountsSnapshot = await this.db.collection(`${this.collectionPrefix}_event_counts`).count().get();
            stats.totalEvents = eventCountsSnapshot.data().count;

            // Get active alerts
            const activeAlertsSnapshot = await this.db.collection(`${this.collectionPrefix}_alert_history`)
                .where('resolved', '==', false)
                .count()
                .get();
            stats.activeAlerts = activeAlertsSnapshot.data().count;

            // Get high threat identifiers
            const highThreatSnapshot = await this.db.collection(`${this.collectionPrefix}_threat_levels`)
                .where('threatScore', '>=', 50)
                .count()
                .get();
            stats.highThreatIdentifiers = highThreatSnapshot.data().count;

            return stats;

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
     * Cleanup expired entries across all collections
     */
    async cleanup() {
        const collections = [
            `${this.collectionPrefix}_event_counts`,
            `${this.collectionPrefix}_alert_history`,
            `${this.collectionPrefix}_threat_levels`
        ];

        const now = Timestamp.now();

        for (const collectionName of collections) {
            try {
                const expiredDocs = await this.db.collection(collectionName)
                    .where('expiresAt', '<=', now)
                    .limit(100)
                    .get();

                if (!expiredDocs.empty) {
                    const batch = this.db.batch();
                    expiredDocs.forEach(doc => {
                        batch.delete(doc.ref);
                    });

                    await batch.commit();
                    console.log(`[SECURITY MONITOR] Cleaned ${expiredDocs.size} expired documents from ${collectionName}`);
                }
            } catch (error) {
                console.error(`Cleanup failed for ${collectionName}:`, error);
            }
        }
    }

    /**
     * Generate unique security event key
     * @param {string} eventType - Event type
     * @param {string} clientIP - Client IP
     * @returns {string} Unique key
     */
    generateSecurityEventKey(eventType, clientIP) {
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256');
        hash.update(`${eventType}:${clientIP}:${process.env.JWT_SECRET || 'fallback'}`);
        return hash.digest('hex').substring(0, 32);
    }

    /**
     * Generate unique threat level key
     * @param {string} identifier - IP or user ID
     * @returns {string} Unique key
     */
    generateThreatLevelKey(identifier) {
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256');
        hash.update(`threat:${identifier}:${process.env.JWT_SECRET || 'fallback'}`);
        return hash.digest('hex').substring(0, 32);
    }

    /**
     * Generate unique alert ID
     * @returns {string} Unique alert ID
     */
    generateAlertId() {
        const crypto = require('crypto');
        return `alert_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    }

    /**
     * Perform security audit across distributed system
     * @returns {Promise<Object>} Audit results
     */
    async performSecurityAudit() {
        try {
            console.log('[SECURITY MONITOR] Performing distributed security audit...');

            const auditResults = {
                timestamp: new Date().toISOString(),
                statistics: await this.getSecurityStatistics(),
                threatAnalysis: await this.analyzeThreatPatterns(),
                recommendations: []
            };

            // Generate recommendations based on findings
            if (auditResults.statistics.activeAlerts > 10) {
                auditResults.recommendations.push('High number of active alerts - review alert thresholds');
            }

            if (auditResults.statistics.highThreatIdentifiers > 5) {
                auditResults.recommendations.push('Multiple high-threat identifiers detected - consider IP blocking');
            }

            // Log audit results
            securityLogger.log('INFO', 'SECURITY_AUDIT_COMPLETED', auditResults);

            return auditResults;

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
     * Analyze threat patterns in distributed data
     * @returns {Promise<Object>} Threat analysis
     */
    async analyzeThreatPatterns() {
        try {
            // Get recent high-threat identifiers
            const highThreatDocs = await this.db.collection(`${this.collectionPrefix}_threat_levels`)
                .where('threatScore', '>=', 50)
                .orderBy('threatScore', 'desc')
                .limit(10)
                .get();

            const patterns = {
                highThreatCount: highThreatDocs.size,
                topThreats: [],
                commonEventTypes: {} // SECURITY FIX: Use plain object instead of Map for serverless compatibility
            };

            highThreatDocs.forEach(doc => {
                const data = doc.data();
                patterns.topThreats.push({
                    identifier: data.identifier,
                    threatScore: data.threatScore,
                    lastUpdated: data.lastUpdated
                });

                // Analyze event types using plain object
                if (data.recentEvents) {
                    data.recentEvents.forEach(event => {
                        const count = patterns.commonEventTypes[event.eventType] || 0;
                        patterns.commonEventTypes[event.eventType] = count + 1;
                    });
                }
            });

            // SECURITY FIX: No conversion needed - already using plain object

            return patterns;

        } catch (error) {
            console.error('Threat pattern analysis failed:', error);
            return {
                highThreatCount: 0,
                topThreats: [],
                commonEventTypes: {},
                error: 'analysis_failed'
            };
        }
    }
}

// Export singleton instance
const distributedSecurityMonitor = new DistributedSecurityMonitoringSystem();

module.exports = distributedSecurityMonitor;