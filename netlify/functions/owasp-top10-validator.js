/**
 * OWASP TOP 10 2021 VALIDATOR - SESSION 5B
 * Automated validation for OWASP Top 10 2021 security requirements
 * Comprehensive security vulnerability scanning and assessment
 */

const fs = require('fs').promises;
const path = require('path');
const securityLogger = require('./security-logger');

/**
 * OWASP Top 10 2021 Compliance Validator
 * Validates against all 10 OWASP Top 10 2021 categories
 */
class OwaspTop10Validator {
    constructor() {
        this.version = '2021.1.0';
        this.vulnerabilityPatterns = this.initializeVulnerabilityPatterns();
        this.securityBestPractices = this.initializeSecurityBestPractices();
    }

    /**
     * Initialize vulnerability detection patterns for OWASP Top 10 2021
     * @returns {Object} Vulnerability patterns by category
     */
    initializeVulnerabilityPatterns() {
        return {
            // A01:2021 - Broken Access Control
            brokenAccessControl: {
                patterns: [
                    /(?:admin|administrator)\s*[=:]\s*['"](true|1|yes)['"]/gi,
                    /role\s*[=:]\s*['"](admin|root|superuser)['"]/gi,
                    /bypass.*(?:auth|authorization)/gi,
                    /skip.*(?:auth|authorization)/gi,
                    /\.user\s*=\s*(?:null|undefined)/gi,
                    /authorization.*disabled/gi,
                    /auth.*check.*false/gi
                ],
                files: ['*.js', '*.ts', '*.jsx', '*.tsx', '*.php', '*.py', '*.java']
            },

            // A02:2021 - Cryptographic Failures
            cryptographicFailures: {
                patterns: [
                    /md5|sha1(?![\d])/gi,
                    /\.encrypt\(['"][^'"]*['"]\)/gi,
                    /password.*=.*['"]/gi,
                    /secret.*=.*['"]/gi,
                    /key.*=.*['"]/gi,
                    /(?:ssl|tls).*false/gi,
                    /verify.*false/gi,
                    /crypto\.createCipher\(/gi,
                    /DES|3DES/gi
                ],
                files: ['*.js', '*.ts', '*.jsx', '*.tsx', '*.php', '*.py', '*.java', '*.config']
            },

            // A03:2021 - Injection
            injection: {
                patterns: [
                    /\$\{.*\}/g,
                    /eval\s*\(/gi,
                    /new\s+Function\s*\(/gi,
                    /document\.write\s*\(/gi,
                    /innerHTML\s*=\s*[^;]+\+/gi,
                    /outerHTML\s*=\s*[^;]+\+/gi,
                    /\.query\s*\(\s*['"]/gi,
                    /(?:SELECT|INSERT|UPDATE|DELETE).*\+.*\)/gi,
                    /process\.env\[.*\]/gi
                ],
                files: ['*.js', '*.ts', '*.jsx', '*.tsx', '*.sql', '*.php', '*.py']
            },

            // A04:2021 - Insecure Design
            insecureDesign: {
                patterns: [
                    /TODO.*security/gi,
                    /FIXME.*security/gi,
                    /hack|workaround/gi,
                    /temporary.*fix/gi,
                    /bypass.*validation/gi,
                    /skip.*security/gi,
                    /debug.*production/gi
                ],
                files: ['*.js', '*.ts', '*.jsx', '*.tsx', '*.php', '*.py', '*.java']
            },

            // A05:2021 - Security Misconfiguration
            securityMisconfiguration: {
                patterns: [
                    /cors.*origin.*\*/gi,
                    /access-control-allow-origin.*\*/gi,
                    /x-frame-options.*allowall/gi,
                    /debug.*true/gi,
                    /development.*true/gi,
                    /error.*stack.*true/gi,
                    /\.env\.example/gi
                ],
                files: ['*.js', '*.ts', '*.jsx', '*.tsx', '*.config', '*.json', '.env*']
            },

            // A06:2021 - Vulnerable and Outdated Components
            vulnerableComponents: {
                patterns: [
                    /"[^"]*":\s*"[\^~]?\d+\.\d+\.\d+"/g,
                    /require\s*\(\s*['"][^'"]*['"]\s*\)/g,
                    /import.*from\s*['"][^'"]*['"]/g,
                    /npm.*install/gi,
                    /yarn.*add/gi
                ],
                files: ['package.json', 'package-lock.json', 'yarn.lock', '*.js', '*.ts']
            },

            // A07:2021 - Identification and Authentication Failures
            authenticationFailures: {
                patterns: [
                    /password.*length.*[<].*8/gi,
                    /session.*timeout.*null/gi,
                    /remember.*me.*true/gi,
                    /auto.*login/gi,
                    /guest.*user/gi,
                    /anonymous.*access/gi,
                    /token.*never.*expires/gi
                ],
                files: ['*.js', '*.ts', '*.jsx', '*.tsx', '*.php', '*.py', '*.java']
            },

            // A08:2021 - Software and Data Integrity Failures
            integrityFailures: {
                patterns: [
                    /cdn.*http:/gi,
                    /integrity.*false/gi,
                    /crossorigin.*anonymous/gi,
                    /script.*src.*http:/gi,
                    /\.tar\.gz|\.zip.*download/gi,
                    /auto.*update.*true/gi
                ],
                files: ['*.html', '*.js', '*.ts', '*.jsx', '*.tsx', '*.json']
            },

            // A09:2021 - Security Logging and Monitoring Failures
            loggingFailures: {
                patterns: [
                    /console\.log\(/gi,
                    /print\(/gi,
                    /log.*level.*none/gi,
                    /logging.*disabled/gi,
                    /audit.*false/gi,
                    /monitor.*false/gi
                ],
                files: ['*.js', '*.ts', '*.jsx', '*.tsx', '*.php', '*.py', '*.java']
            },

            // A10:2021 - Server-Side Request Forgery (SSRF)
            ssrf: {
                patterns: [
                    /fetch\s*\(\s*.*req\..*\)/gi,
                    /axios\s*\(\s*.*req\..*\)/gi,
                    /request\s*\(\s*.*req\..*\)/gi,
                    /http\.get\s*\(\s*.*req\..*\)/gi,
                    /url.*params/gi,
                    /redirect.*req\./gi
                ],
                files: ['*.js', '*.ts', '*.jsx', '*.tsx', '*.php', '*.py']
            }
        };
    }

    /**
     * Initialize security best practices checks
     * @returns {Object} Security best practices by category
     */
    initializeSecurityBestPractices() {
        return {
            securityHeaders: {
                required: [
                    'Content-Security-Policy',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Strict-Transport-Security',
                    'Referrer-Policy'
                ],
                patterns: [
                    /Content-Security-Policy/gi,
                    /X-Frame-Options/gi,
                    /X-Content-Type-Options/gi,
                    /Strict-Transport-Security/gi,
                    /Referrer-Policy/gi
                ]
            },
            inputValidation: {
                patterns: [
                    /validate\(/gi,
                    /sanitize\(/gi,
                    /escape\(/gi,
                    /filter\(/gi,
                    /trim\(/gi
                ]
            },
            errorHandling: {
                patterns: [
                    /try\s*\{/gi,
                    /catch\s*\(/gi,
                    /finally\s*\{/gi,
                    /throw\s+new\s+Error/gi
                ]
            },
            authentication: {
                patterns: [
                    /bcrypt/gi,
                    /scrypt/gi,
                    /argon2/gi,
                    /jwt\.verify/gi,
                    /password.*hash/gi
                ]
            }
        };
    }

    /**
     * Validate OWASP Top 10 2021 compliance
     * @param {Object} options - Validation options
     * @returns {Object} Comprehensive compliance results
     */
    async validateOwasp2021Compliance(options = {}) {
        const validationId = this.generateValidationId();
        const startTime = Date.now();

        try {
            securityLogger.log('INFO', 'OWASP_VALIDATION_STARTED', {
                validationId,
                timestamp: new Date().toISOString(),
                options
            });

            const codebasePath = options.codebasePath || process.cwd();
            const excludePaths = options.excludePaths || ['node_modules', '.git', 'backups'];

            // Scan codebase for files
            const files = await this.scanCodebase(codebasePath, excludePaths);

            // Run vulnerability assessments for each OWASP Top 10 category
            const assessments = await Promise.all([
                this.assessA01BrokenAccessControl(files),
                this.assessA02CryptographicFailures(files),
                this.assessA03Injection(files),
                this.assessA04InsecureDesign(files),
                this.assessA05SecurityMisconfiguration(files),
                this.assessA06VulnerableComponents(files),
                this.assessA07AuthenticationFailures(files),
                this.assessA08IntegrityFailures(files),
                this.assessA09LoggingFailures(files),
                this.assessA10SSRF(files)
            ]);

            // Compile results
            const results = {
                validationId,
                timestamp: new Date().toISOString(),
                duration: Date.now() - startTime,
                codebasePath,
                filesScanned: files.length,
                assessments: {
                    A01_BrokenAccessControl: assessments[0],
                    A02_CryptographicFailures: assessments[1],
                    A03_Injection: assessments[2],
                    A04_InsecureDesign: assessments[3],
                    A05_SecurityMisconfiguration: assessments[4],
                    A06_VulnerableComponents: assessments[5],
                    A07_AuthenticationFailures: assessments[6],
                    A08_IntegrityFailures: assessments[7],
                    A09_LoggingFailures: assessments[8],
                    A10_SSRF: assessments[9]
                }
            };

            // Calculate overall compliance score
            results.overallScore = this.calculateOverallScore(results.assessments);
            results.riskLevel = this.determineRiskLevel(results.overallScore);
            results.criticalVulnerabilities = this.extractCriticalVulnerabilities(results.assessments);
            results.recommendations = this.generateRecommendations(results.assessments);

            securityLogger.log('INFO', 'OWASP_VALIDATION_COMPLETED', {
                validationId,
                overallScore: results.overallScore,
                riskLevel: results.riskLevel,
                duration: results.duration
            });

            return results;

        } catch (error) {
            securityLogger.logOperationFailure({
                operation: 'owasp_validation',
                validationId,
                error: error.message,
                duration: Date.now() - startTime
            });

            throw new Error(`OWASP validation failed: ${error.message}`);
        }
    }

    /**
     * Scan codebase for relevant files
     * @param {string} basePath - Base path to scan
     * @param {Array} excludePaths - Paths to exclude
     * @returns {Array} List of files to analyze
     */
    async scanCodebase(basePath, excludePaths) {
        const files = [];

        async function scanDirectory(dirPath) {
            try {
                const entries = await fs.readdir(dirPath, { withFileTypes: true });

                for (const entry of entries) {
                    const fullPath = path.join(dirPath, entry.name);
                    const relativePath = path.relative(basePath, fullPath);

                    // Skip excluded paths
                    if (excludePaths.some(exclude => relativePath.includes(exclude))) {
                        continue;
                    }

                    if (entry.isDirectory()) {
                        await scanDirectory(fullPath);
                    } else if (entry.isFile()) {
                        files.push({
                            path: fullPath,
                            relativePath,
                            name: entry.name,
                            extension: path.extname(entry.name)
                        });
                    }
                }
            } catch (error) {
                // Skip directories that can't be read
                console.warn(`Cannot scan directory ${dirPath}: ${error.message}`);
            }
        }

        await scanDirectory(basePath);
        return files;
    }

    /**
     * A01:2021 - Broken Access Control Assessment
     * @param {Array} files - Files to analyze
     * @returns {Object} Assessment results
     */
    async assessA01BrokenAccessControl(files) {
        const findings = [];
        const patterns = this.vulnerabilityPatterns.brokenAccessControl.patterns;

        for (const file of files) {
            if (this.isRelevantFile(file, this.vulnerabilityPatterns.brokenAccessControl.files)) {
                try {
                    const content = await fs.readFile(file.path, 'utf8');

                    for (const pattern of patterns) {
                        const matches = content.match(pattern);
                        if (matches) {
                            findings.push({
                                file: file.relativePath,
                                vulnerability: 'Broken Access Control',
                                severity: 'high',
                                matches: matches.slice(0, 3), // Limit matches
                                pattern: pattern.source,
                                lineNumbers: this.findLineNumbers(content, pattern)
                            });
                        }
                    }
                } catch (error) {
                    // Skip files that can't be read
                }
            }
        }

        return {
            category: 'A01:2021 - Broken Access Control',
            score: this.calculateCategoryScore(findings, files.length),
            findings,
            riskLevel: this.calculateRiskLevel(findings),
            recommendations: this.getA01Recommendations(findings)
        };
    }

    /**
     * A02:2021 - Cryptographic Failures Assessment
     * @param {Array} files - Files to analyze
     * @returns {Object} Assessment results
     */
    async assessA02CryptographicFailures(files) {
        const findings = [];
        const patterns = this.vulnerabilityPatterns.cryptographicFailures.patterns;

        for (const file of files) {
            if (this.isRelevantFile(file, this.vulnerabilityPatterns.cryptographicFailures.files)) {
                try {
                    const content = await fs.readFile(file.path, 'utf8');

                    for (const pattern of patterns) {
                        const matches = content.match(pattern);
                        if (matches) {
                            findings.push({
                                file: file.relativePath,
                                vulnerability: 'Cryptographic Failures',
                                severity: 'high',
                                matches: matches.slice(0, 3),
                                pattern: pattern.source,
                                lineNumbers: this.findLineNumbers(content, pattern)
                            });
                        }
                    }
                } catch (error) {
                    // Skip files that can't be read
                }
            }
        }

        return {
            category: 'A02:2021 - Cryptographic Failures',
            score: this.calculateCategoryScore(findings, files.length),
            findings,
            riskLevel: this.calculateRiskLevel(findings),
            recommendations: this.getA02Recommendations(findings)
        };
    }

    /**
     * A03:2021 - Injection Assessment
     * @param {Array} files - Files to analyze
     * @returns {Object} Assessment results
     */
    async assessA03Injection(files) {
        const findings = [];
        const patterns = this.vulnerabilityPatterns.injection.patterns;

        for (const file of files) {
            if (this.isRelevantFile(file, this.vulnerabilityPatterns.injection.files)) {
                try {
                    const content = await fs.readFile(file.path, 'utf8');

                    for (const pattern of patterns) {
                        const matches = content.match(pattern);
                        if (matches) {
                            findings.push({
                                file: file.relativePath,
                                vulnerability: 'Injection',
                                severity: 'critical',
                                matches: matches.slice(0, 3),
                                pattern: pattern.source,
                                lineNumbers: this.findLineNumbers(content, pattern)
                            });
                        }
                    }
                } catch (error) {
                    // Skip files that can't be read
                }
            }
        }

        return {
            category: 'A03:2021 - Injection',
            score: this.calculateCategoryScore(findings, files.length),
            findings,
            riskLevel: this.calculateRiskLevel(findings),
            recommendations: this.getA03Recommendations(findings)
        };
    }

    /**
     * Calculate category compliance score
     * @param {Array} findings - Security findings
     * @param {number} totalFiles - Total files scanned
     * @returns {number} Compliance score (0-100)
     */
    calculateCategoryScore(findings, totalFiles) {
        if (totalFiles === 0) return 100;

        const severityWeights = {
            critical: 25,
            high: 15,
            medium: 10,
            low: 5,
            info: 1
        };

        const totalPenalty = findings.reduce((penalty, finding) => {
            return penalty + (severityWeights[finding.severity] || 5);
        }, 0);

        const maxPossiblePenalty = totalFiles * 25; // Assuming worst case
        const score = Math.max(0, 100 - (totalPenalty / maxPossiblePenalty * 100));

        return Math.round(score);
    }

    /**
     * Calculate overall compliance score
     * @param {Object} assessments - All category assessments
     * @returns {number} Overall compliance score
     */
    calculateOverallScore(assessments) {
        const categories = Object.values(assessments);
        const totalScore = categories.reduce((sum, category) => sum + category.score, 0);
        return Math.round(totalScore / categories.length);
    }

    /**
     * Determine risk level based on score
     * @param {number} score - Compliance score
     * @returns {string} Risk level
     */
    determineRiskLevel(score) {
        if (score >= 90) return 'low';
        if (score >= 75) return 'medium';
        if (score >= 50) return 'high';
        return 'critical';
    }

    /**
     * Calculate risk level for findings
     * @param {Array} findings - Security findings
     * @returns {string} Risk level
     */
    calculateRiskLevel(findings) {
        const criticalCount = findings.filter(f => f.severity === 'critical').length;
        const highCount = findings.filter(f => f.severity === 'high').length;

        if (criticalCount > 0) return 'critical';
        if (highCount > 3) return 'high';
        if (highCount > 0) return 'medium';
        return 'low';
    }

    /**
     * Extract critical vulnerabilities from all assessments
     * @param {Object} assessments - All category assessments
     * @returns {Array} Critical vulnerabilities
     */
    extractCriticalVulnerabilities(assessments) {
        const critical = [];

        Object.values(assessments).forEach(assessment => {
            const criticalFindings = assessment.findings.filter(f =>
                f.severity === 'critical' || f.severity === 'high'
            );
            critical.push(...criticalFindings);
        });

        return critical.slice(0, 10); // Limit to top 10 critical issues
    }

    /**
     * Generate security recommendations
     * @param {Object} assessments - All category assessments
     * @returns {Array} Security recommendations
     */
    generateRecommendations(assessments) {
        const recommendations = [];

        Object.values(assessments).forEach(assessment => {
            if (assessment.score < 80) {
                recommendations.push(...assessment.recommendations);
            }
        });

        return recommendations.slice(0, 5); // Top 5 recommendations
    }

    /**
     * Check if file is relevant for analysis
     * @param {Object} file - File object
     * @param {Array} patterns - File patterns to match
     * @returns {boolean} True if file is relevant
     */
    isRelevantFile(file, patterns) {
        return patterns.some(pattern => {
            const globPattern = pattern.replace(/\*/g, '.*');
            const regex = new RegExp(globPattern, 'i');
            return regex.test(file.name) || regex.test(file.relativePath);
        });
    }

    /**
     * Find line numbers for pattern matches
     * @param {string} content - File content
     * @param {RegExp} pattern - Pattern to search
     * @returns {Array} Line numbers
     */
    findLineNumbers(content, pattern) {
        const lines = content.split('\n');
        const lineNumbers = [];

        lines.forEach((line, index) => {
            if (pattern.test(line)) {
                lineNumbers.push(index + 1);
            }
        });

        return lineNumbers.slice(0, 5); // Limit to first 5 matches
    }

    /**
     * Get A01 specific recommendations
     * @param {Array} findings - A01 findings
     * @returns {Array} Recommendations
     */
    getA01Recommendations(findings) {
        const recommendations = [
            'Implement proper role-based access control (RBAC)',
            'Use authentication middleware for all protected routes',
            'Validate user permissions on server-side',
            'Implement principle of least privilege'
        ];

        return findings.length > 0 ? recommendations : [];
    }

    /**
     * Get A02 specific recommendations
     * @param {Array} findings - A02 findings
     * @returns {Array} Recommendations
     */
    getA02Recommendations(findings) {
        const recommendations = [
            'Use strong encryption algorithms (AES-256, RSA-2048+)',
            'Implement proper key management',
            'Use bcrypt or Argon2 for password hashing',
            'Enable TLS 1.3 for all connections'
        ];

        return findings.length > 0 ? recommendations : [];
    }

    /**
     * Get A03 specific recommendations
     * @param {Array} findings - A03 findings
     * @returns {Array} Recommendations
     */
    getA03Recommendations(findings) {
        const recommendations = [
            'Use parameterized queries for database operations',
            'Implement input validation and sanitization',
            'Avoid dynamic code execution (eval, Function)',
            'Use CSP headers to prevent XSS attacks'
        ];

        return findings.length > 0 ? recommendations : [];
    }

    // Placeholder methods for remaining OWASP categories
    async assessA04InsecureDesign(files) {
        return this.assessGenericCategory(files, 'insecureDesign', 'A04:2021 - Insecure Design');
    }

    async assessA05SecurityMisconfiguration(files) {
        return this.assessGenericCategory(files, 'securityMisconfiguration', 'A05:2021 - Security Misconfiguration');
    }

    async assessA06VulnerableComponents(files) {
        return this.assessGenericCategory(files, 'vulnerableComponents', 'A06:2021 - Vulnerable and Outdated Components');
    }

    async assessA07AuthenticationFailures(files) {
        return this.assessGenericCategory(files, 'authenticationFailures', 'A07:2021 - Identification and Authentication Failures');
    }

    async assessA08IntegrityFailures(files) {
        return this.assessGenericCategory(files, 'integrityFailures', 'A08:2021 - Software and Data Integrity Failures');
    }

    async assessA09LoggingFailures(files) {
        return this.assessGenericCategory(files, 'loggingFailures', 'A09:2021 - Security Logging and Monitoring Failures');
    }

    async assessA10SSRF(files) {
        return this.assessGenericCategory(files, 'ssrf', 'A10:2021 - Server-Side Request Forgery');
    }

    /**
     * Generic category assessment
     * @param {Array} files - Files to analyze
     * @param {string} categoryKey - Category key
     * @param {string} categoryName - Category display name
     * @returns {Object} Assessment results
     */
    async assessGenericCategory(files, categoryKey, categoryName) {
        const findings = [];
        const patternData = this.vulnerabilityPatterns[categoryKey];

        if (!patternData) {
            return {
                category: categoryName,
                score: 100,
                findings: [],
                riskLevel: 'low',
                recommendations: []
            };
        }

        for (const file of files) {
            if (this.isRelevantFile(file, patternData.files)) {
                try {
                    const content = await fs.readFile(file.path, 'utf8');

                    for (const pattern of patternData.patterns) {
                        const matches = content.match(pattern);
                        if (matches) {
                            findings.push({
                                file: file.relativePath,
                                vulnerability: categoryName,
                                severity: 'medium',
                                matches: matches.slice(0, 3),
                                pattern: pattern.source,
                                lineNumbers: this.findLineNumbers(content, pattern)
                            });
                        }
                    }
                } catch (error) {
                    // Skip files that can't be read
                }
            }
        }

        return {
            category: categoryName,
            score: this.calculateCategoryScore(findings, files.length),
            findings,
            riskLevel: this.calculateRiskLevel(findings),
            recommendations: []
        };
    }

    /**
     * Generate unique validation ID
     * @returns {string} Validation ID
     */
    generateValidationId() {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(2, 8);
        return `OWASP-${timestamp}-${random}`.toUpperCase();
    }
}

// Export singleton instance
const owaspTop10Validator = new OwaspTop10Validator();

module.exports = owaspTop10Validator;