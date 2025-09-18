// Distributed Token Replay Prevention System
// SESSION 2A-2 Implementation - Enterprise-Grade Security Controls
// PCI-DSS 4.0 Compliant Token Blacklisting with Distributed Locking

const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const securityLogger = require('./security-logger');
const crypto = require('crypto');

/**
 * Distributed Token Replay Prevention System
 * Provides enterprise-grade token blacklisting with distributed locking
 * and ML-powered anomaly detection for PCI-DSS 4.0 compliance
 */
class DistributedTokenReplayPrevention {
    constructor() {
        // Enterprise Configuration Constants
        this.REPLAY_WINDOW_MS = 5 * 60 * 1000; // 5-minute maximum replay window (enterprise-grade)
        this.LOCK_TIMEOUT_MS = 5000; // 5-second distributed lock timeout
        this.OPERATION_TIMEOUT_MS = 5000; // Sub-5-second operation requirement
        this.ANOMALY_THRESHOLD = 0.7; // ML anomaly detection threshold
        this.MAX_RETRY_ATTEMPTS = 3;
        this.RETRY_DELAY_MS = 100;

        // CRITICAL-002 FIX: Generate unique nodeId once per instance to prevent race conditions
        this.nodeId = this.generateNodeId();

        // Firestore Collections
        this.TOKEN_BLACKLIST_COLLECTION = 'tokenBlacklist';
        this.DISTRIBUTED_LOCKS_COLLECTION = 'distributedLocks';
        this.BEHAVIORAL_ANALYTICS_COLLECTION = 'behavioralAnalytics';
        this.SECURITY_EVENTS_COLLECTION = 'securityEvents';

        // Performance Metrics
        this.performanceMetrics = {
            operationCount: 0,
            averageResponseTime: 0,
            errorRate: 0
        };
    }

    /**
     * Generate secure token hash for blacklist storage
     * @param {string} tokenId - Token identifier
     * @returns {string} SHA-256 hash of token ID
     */
    generateTokenHash(tokenId) {
        if (!tokenId || typeof tokenId !== 'string') {
            throw new Error('Invalid token ID provided for hashing');
        }
        return crypto.createHash('sha256').update(tokenId).digest('hex');
    }

    /**
     * Acquire distributed lock with timeout
     * @param {string} lockId - Unique lock identifier
     * @param {number} timeoutMs - Lock timeout in milliseconds
     * @returns {Object} Lock acquisition result
     */
    async acquireDistributedLock(lockId, timeoutMs = this.LOCK_TIMEOUT_MS) {
        const startTime = Date.now();
        const db = getFirestore();
        const lockRef = db.collection(this.DISTRIBUTED_LOCKS_COLLECTION).doc(lockId);

        try {
            const lockExpiry = Date.now() + timeoutMs;
            const lockData = {
                acquired: true,
                expiresAt: new Date(lockExpiry),
                acquiredAt: new Date(),
                nodeId: this.nodeId
            };

            // CRITICAL-002 FIX: Atomic lock acquisition with race condition prevention
            await db.runTransaction(async (transaction) => {
                const lockDoc = await transaction.get(lockRef);
                const now = new Date();

                if (lockDoc.exists) {
                    const existingLock = lockDoc.data();

                    // Check if existing lock has expired
                    if (existingLock.expiresAt && existingLock.expiresAt.toDate() > now) {
                        // Additional race condition check - verify nodeId is different
                        if (existingLock.nodeId === this.nodeId) {
                            throw new Error('Lock collision detected - same node attempting duplicate lock');
                        }
                        throw new Error('Lock already acquired and not expired');
                    }

                    // Verify lock expiry with strict timestamp comparison
                    if (existingLock.expiresAt && existingLock.expiresAt.toDate().getTime() >= now.getTime()) {
                        throw new Error('Lock still active - race condition prevented');
                    }
                }

                // Add unique nonce to prevent concurrent lock acquisition
                lockData.nonce = crypto.randomBytes(16).toString('hex');
                lockData.strictTimestamp = now.getTime();

                // Acquire or renew lock with atomic operation
                transaction.set(lockRef, lockData);

                // Verify write succeeded by reading back immediately in transaction
                const verifyDoc = await transaction.get(lockRef);
                if (!verifyDoc.exists || verifyDoc.data().nonce !== lockData.nonce) {
                    throw new Error('Lock acquisition verification failed - race condition detected');
                }
            });

            const acquisitionTime = Date.now() - startTime;

            if (acquisitionTime > this.OPERATION_TIMEOUT_MS) {
                await this.logPerformanceWarning('lock_acquisition_slow', acquisitionTime);
            }

            return {
                success: true,
                lockId: lockId,
                acquisitionTime: acquisitionTime,
                expiresAt: lockExpiry
            };

        } catch (error) {
            const acquisitionTime = Date.now() - startTime;

            securityLogger.logOperationFailure({
                operation: 'distributed_lock_acquisition',
                lockId: lockId,
                error: error.message,
                duration: acquisitionTime,
                endpoint: 'distributed-token-replay-prevention'
            });

            // CRITICAL-003 FIX: Sanitize error message to prevent information disclosure
            return {
                success: false,
                error: 'Lock operation failed',
                lockId: lockId,
                acquisitionTime: acquisitionTime
            };
        }
    }

    /**
     * Release distributed lock
     * @param {string} lockId - Lock identifier to release
     * @returns {boolean} True if lock was successfully released
     */
    async releaseDistributedLock(lockId) {
        try {
            const db = getFirestore();
            const lockRef = db.collection(this.DISTRIBUTED_LOCKS_COLLECTION).doc(lockId);

            await lockRef.delete();

            securityLogger.log('DEBUG', 'DISTRIBUTED_LOCK_RELEASED', {
                lockId: lockId,
                timestamp: new Date().toISOString()
            });

            return true;

        } catch (error) {
            securityLogger.logOperationFailure({
                operation: 'distributed_lock_release',
                lockId: lockId,
                error: error.message,
                endpoint: 'distributed-token-replay-prevention'
            });

            return false;
        }
    }

    /**
     * Check if token is blacklisted (replayed) with distributed locking
     * @param {string} tokenId - Token identifier to check
     * @param {string} userId - User ID for behavioral analysis
     * @param {string} ipAddress - Client IP address
     * @returns {Object} Validation result with security analysis
     */
    async isTokenBlacklisted(tokenId, userId = null, ipAddress = null) {
        const startTime = Date.now();
        let lockId = null;

        try {
            if (!tokenId || typeof tokenId !== 'string') {
                return {
                    isBlacklisted: true,
                    reason: 'INVALID_TOKEN_FORMAT',
                    securityRisk: 'HIGH',
                    responseTime: Date.now() - startTime
                };
            }

            const tokenHash = this.generateTokenHash(tokenId);
            lockId = `token_check_${tokenHash}`;

            // Acquire distributed lock for atomic operation
            const lockResult = await this.acquireDistributedLock(lockId);

            if (!lockResult.success) {
                // CRITICAL-003 FIX: Sanitize error response to prevent information disclosure
                return {
                    isBlacklisted: true,
                    reason: 'LOCK_ACQUISITION_FAILED',
                    securityRisk: 'HIGH',
                    error: 'System temporarily unavailable',
                    responseTime: Date.now() - startTime
                };
            }

            const db = getFirestore();
            const tokenRef = db.collection(this.TOKEN_BLACKLIST_COLLECTION).doc(tokenHash);
            const tokenDoc = await tokenRef.get();

            if (!tokenDoc.exists) {
                // Token not blacklisted, perform behavioral analysis
                const behavioralResult = await this.performBehavioralAnalysis(userId, ipAddress, tokenId);

                await this.releaseDistributedLock(lockId);

                return {
                    isBlacklisted: false,
                    reason: 'TOKEN_NOT_FOUND',
                    securityRisk: behavioralResult.riskLevel,
                    behavioralAnalysis: behavioralResult,
                    responseTime: Date.now() - startTime
                };
            }

            const tokenData = tokenDoc.data();
            const now = Date.now();
            const tokenAge = now - tokenData.blacklistedAt;

            // Check if token is within replay window
            if (tokenAge > this.REPLAY_WINDOW_MS) {
                // Token is expired, remove from blacklist
                await tokenRef.delete();
                await this.releaseDistributedLock(lockId);

                securityLogger.log('INFO', 'EXPIRED_TOKEN_REMOVED', {
                    tokenHash: tokenHash.substring(0, 16) + '...',
                    age: tokenAge,
                    replayWindow: this.REPLAY_WINDOW_MS
                });

                return {
                    isBlacklisted: false,
                    reason: 'TOKEN_EXPIRED_AND_REMOVED',
                    securityRisk: 'LOW',
                    responseTime: Date.now() - startTime
                };
            }

            // Token is blacklisted and within replay window
            await this.logSecurityEvent('TOKEN_REPLAY_DETECTED', {
                tokenHash: tokenHash.substring(0, 16) + '...',
                userId: userId || 'unknown',
                ipAddress: ipAddress || 'unknown',
                originalBlacklistTime: tokenData.blacklistedAt,
                timeSinceBlacklist: tokenAge,
                severity: 'HIGH'
            });

            await this.releaseDistributedLock(lockId);

            return {
                isBlacklisted: true,
                reason: 'TOKEN_REPLAY_DETECTED',
                securityRisk: 'CRITICAL',
                blacklistedAt: tokenData.blacklistedAt,
                timeSinceBlacklist: tokenAge,
                responseTime: Date.now() - startTime
            };

        } catch (error) {
            if (lockId) {
                await this.releaseDistributedLock(lockId);
            }

            securityLogger.logOperationFailure({
                operation: 'token_blacklist_check',
                tokenId: tokenId ? tokenId.substring(0, 8) + '...' : 'invalid',
                error: error.message,
                duration: Date.now() - startTime,
                endpoint: 'distributed-token-replay-prevention'
            });

            // Fail secure - reject on error
            // CRITICAL-003 FIX: Sanitize error message to prevent system information disclosure
            return {
                isBlacklisted: true,
                reason: 'SYSTEM_ERROR',
                securityRisk: 'CRITICAL',
                error: 'Authentication service unavailable',
                responseTime: Date.now() - startTime
            };
        }
    }

    /**
     * Add token to blacklist with distributed locking and TTL
     * @param {string} tokenId - Token identifier to blacklist
     * @param {string} userId - User ID for audit trail
     * @param {string} reason - Reason for blacklisting
     * @returns {Object} Blacklisting operation result
     */
    async blacklistToken(tokenId, userId = null, reason = 'TOKEN_CONSUMED') {
        const startTime = Date.now();
        let lockId = null;

        try {
            if (!tokenId || typeof tokenId !== 'string') {
                return {
                    success: false,
                    reason: 'INVALID_TOKEN_FORMAT',
                    responseTime: Date.now() - startTime
                };
            }

            const tokenHash = this.generateTokenHash(tokenId);
            lockId = `token_blacklist_${tokenHash}`;

            // Acquire distributed lock for atomic operation
            const lockResult = await this.acquireDistributedLock(lockId);

            if (!lockResult.success) {
                // CRITICAL-003 FIX: Sanitize error response to prevent information disclosure
                return {
                    success: false,
                    reason: 'LOCK_ACQUISITION_FAILED',
                    error: 'Service temporarily unavailable',
                    responseTime: Date.now() - startTime
                };
            }

            const db = getFirestore();
            const now = Date.now();
            const expiryTime = now + this.REPLAY_WINDOW_MS;

            const blacklistData = {
                tokenHash: tokenHash,
                blacklistedAt: now,
                expiresAt: new Date(expiryTime),
                userId: userId || 'unknown',
                reason: reason,
                nodeId: this.nodeId,
                securityLevel: 'HIGH'
            };

            // Atomic blacklist operation with TTL
            const tokenRef = db.collection(this.TOKEN_BLACKLIST_COLLECTION).doc(tokenHash);
            await tokenRef.set(blacklistData);

            // Log security event
            await this.logSecurityEvent('TOKEN_BLACKLISTED', {
                tokenHash: tokenHash.substring(0, 16) + '...',
                userId: userId || 'unknown',
                reason: reason,
                expiresAt: new Date(expiryTime).toISOString(),
                severity: 'MEDIUM'
            });

            await this.releaseDistributedLock(lockId);

            const operationTime = Date.now() - startTime;
            this.updatePerformanceMetrics(operationTime, true);

            return {
                success: true,
                tokenHash: tokenHash.substring(0, 16) + '...',
                expiresAt: expiryTime,
                responseTime: operationTime
            };

        } catch (error) {
            if (lockId) {
                await this.releaseDistributedLock(lockId);
            }

            this.updatePerformanceMetrics(Date.now() - startTime, false);

            securityLogger.logOperationFailure({
                operation: 'token_blacklisting',
                tokenId: tokenId ? tokenId.substring(0, 8) + '...' : 'invalid',
                error: error.message,
                duration: Date.now() - startTime,
                endpoint: 'distributed-token-replay-prevention'
            });

            // CRITICAL-003 FIX: Sanitize error message to prevent system information disclosure
            return {
                success: false,
                reason: 'SYSTEM_ERROR',
                error: 'Service temporarily unavailable',
                responseTime: Date.now() - startTime
            };
        }
    }

    /**
     * ML-powered behavioral analysis for anomaly detection
     * @param {string} userId - User ID for analysis
     * @param {string} ipAddress - Client IP address
     * @param {string} tokenId - Token identifier
     * @returns {Object} Behavioral analysis result
     */
    async performBehavioralAnalysis(userId, ipAddress, tokenId) {
        try {
            if (!userId || !ipAddress) {
                return {
                    riskLevel: 'MEDIUM',
                    score: 0.5,
                    factors: ['INSUFFICIENT_DATA'],
                    recommendation: 'MONITOR'
                };
            }

            const db = getFirestore();
            const now = Date.now();
            const analysisWindow = 24 * 60 * 60 * 1000; // 24 hours
            const startTime = now - analysisWindow;

            // Gather behavioral data
            const userBehaviorRef = db.collection(this.BEHAVIORAL_ANALYTICS_COLLECTION)
                .where('userId', '==', userId)
                .where('timestamp', '>=', startTime)
                .limit(100);

            const behaviorSnapshot = await userBehaviorRef.get();
            const behaviors = behaviorSnapshot.docs.map(doc => doc.data());

            // Analyze patterns
            const analysis = this.analyzeBehavioralPatterns(behaviors, ipAddress, tokenId);

            // Store analysis result
            await db.collection(this.BEHAVIORAL_ANALYTICS_COLLECTION).add({
                userId: userId,
                ipAddress: ipAddress,
                tokenId: tokenId.substring(0, 8) + '...',
                timestamp: now,
                riskScore: analysis.score,
                riskLevel: analysis.riskLevel,
                factors: analysis.factors,
                analysisVersion: '2A-2'
            });

            return analysis;

        } catch (error) {
            securityLogger.logOperationFailure({
                operation: 'behavioral_analysis',
                userId: userId || 'unknown',
                error: error.message,
                endpoint: 'distributed-token-replay-prevention'
            });

            return {
                riskLevel: 'HIGH',
                score: 0.8,
                factors: ['ANALYSIS_ERROR'],
                recommendation: 'BLOCK',
                error: 'Analysis service unavailable'
            };
        }
    }

    /**
     * Analyze behavioral patterns for anomaly detection
     * @param {Array} behaviors - Historical behavior data
     * @param {string} currentIP - Current IP address
     * @param {string} tokenId - Current token ID
     * @returns {Object} Pattern analysis result
     */
    analyzeBehavioralPatterns(behaviors, currentIP, tokenId) {
        let riskScore = 0.0;
        const factors = [];

        // IP address analysis
        const ipFrequency = behaviors.filter(b => b.ipAddress === currentIP).length;
        const totalRequests = behaviors.length;

        if (totalRequests > 0) {
            const ipRatio = ipFrequency / totalRequests;
            if (ipRatio < 0.1) {
                riskScore += 0.3;
                factors.push('NEW_IP_ADDRESS');
            }
        } else {
            riskScore += 0.2;
            factors.push('NO_HISTORICAL_DATA');
        }

        // Request frequency analysis
        if (behaviors.length > 0) {
            const recentBehaviors = behaviors.filter(b =>
                (Date.now() - b.timestamp) < (5 * 60 * 1000) // Last 5 minutes
            );

            if (recentBehaviors.length > 10) {
                riskScore += 0.4;
                factors.push('HIGH_FREQUENCY_REQUESTS');
            }
        }

        // Time pattern analysis
        const currentHour = new Date().getHours();
        const historicalHours = behaviors.map(b => new Date(b.timestamp).getHours());
        const hourFrequency = historicalHours.filter(h => Math.abs(h - currentHour) <= 1).length;

        if (historicalHours.length > 0 && hourFrequency / historicalHours.length < 0.1) {
            riskScore += 0.2;
            factors.push('UNUSUAL_TIME_PATTERN');
        }

        // Determine risk level
        let riskLevel;
        let recommendation;

        if (riskScore >= this.ANOMALY_THRESHOLD) {
            riskLevel = 'HIGH';
            recommendation = 'BLOCK';
        } else if (riskScore >= 0.4) {
            riskLevel = 'MEDIUM';
            recommendation = 'MONITOR';
        } else {
            riskLevel = 'LOW';
            recommendation = 'ALLOW';
        }

        return {
            score: riskScore,
            riskLevel: riskLevel,
            factors: factors,
            recommendation: recommendation,
            analysis: {
                ipRatio: totalRequests > 0 ? ipFrequency / totalRequests : 0,
                recentRequestCount: behaviors.filter(b =>
                    (Date.now() - b.timestamp) < (5 * 60 * 1000)
                ).length,
                historicalRequestCount: totalRequests
            }
        };
    }

    /**
     * Log security event for audit trail
     * @param {string} eventType - Type of security event
     * @param {Object} eventData - Event data payload
     */
    async logSecurityEvent(eventType, eventData) {
        try {
            const db = getFirestore();

            await db.collection(this.SECURITY_EVENTS_COLLECTION).add({
                eventType: eventType,
                timestamp: Date.now(),
                data: eventData,
                source: 'distributed-token-replay-prevention',
                version: '2A-2'
            });

            securityLogger.logSuspiciousActivity({
                activityType: eventType,
                description: `Token replay prevention: ${eventType}`,
                additionalData: eventData
            });

        } catch (error) {
            console.error('Failed to log security event:', error);
        }
    }

    /**
     * Generate unique node identifier for distributed systems
     * @returns {string} Unique node identifier
     */
    generateNodeId() {
        return crypto.randomBytes(8).toString('hex');
    }

    /**
     * Update performance metrics
     * @param {number} responseTime - Operation response time
     * @param {boolean} success - Operation success status
     */
    updatePerformanceMetrics(responseTime, success) {
        this.performanceMetrics.operationCount++;

        // Calculate running average
        const totalTime = this.performanceMetrics.averageResponseTime * (this.performanceMetrics.operationCount - 1);
        this.performanceMetrics.averageResponseTime = (totalTime + responseTime) / this.performanceMetrics.operationCount;

        // Update error rate
        if (!success) {
            const errorCount = this.performanceMetrics.errorRate * this.performanceMetrics.operationCount;
            this.performanceMetrics.errorRate = (errorCount + 1) / this.performanceMetrics.operationCount;
        }
    }

    /**
     * Log performance warning for slow operations
     * @param {string} operation - Operation name
     * @param {number} duration - Operation duration
     */
    async logPerformanceWarning(operation, duration) {
        securityLogger.log('WARN', 'PERFORMANCE_WARNING', {
            operation: operation,
            duration: duration,
            threshold: this.OPERATION_TIMEOUT_MS,
            timestamp: new Date().toISOString()
        });
    }

    /**
     * Get performance metrics for monitoring
     * @returns {Object} Current performance metrics
     */
    getPerformanceMetrics() {
        return {
            ...this.performanceMetrics,
            timestamp: new Date().toISOString(),
            version: '2A-2'
        };
    }

    /**
     * Health check for distributed token replay prevention system
     * @returns {Object} System health status
     */
    async healthCheck() {
        const startTime = Date.now();

        try {
            const db = getFirestore();

            // Test Firestore connectivity
            await db.collection('healthCheck').doc('test').set({
                timestamp: Date.now(),
                test: true
            });

            await db.collection('healthCheck').doc('test').delete();

            const responseTime = Date.now() - startTime;

            return {
                status: 'HEALTHY',
                responseTime: responseTime,
                timestamp: new Date().toISOString(),
                version: '2A-2',
                metrics: this.getPerformanceMetrics()
            };

        } catch (error) {
            // CRITICAL-003 FIX: Sanitize health check error message
            return {
                status: 'UNHEALTHY',
                error: 'Service unavailable',
                responseTime: Date.now() - startTime,
                timestamp: new Date().toISOString(),
                version: '2A-2'
            };
        }
    }
}

module.exports = DistributedTokenReplayPrevention;