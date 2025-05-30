const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const cheerio = require('cheerio');
const { ESLint } = require('eslint');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

// Initialize DOMPurify
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// ESLint Configuration - Compatible with different ESLint versions
let eslint;
try {
    // Try the newer configuration format first
    eslint = new ESLint({
        baseConfig: {
            env: {
                browser: true,
                es2021: true,
                node: true
            },
            parserOptions: {
                ecmaVersion: 2021,
                sourceType: 'script'
            },
            rules: {
                'no-eval': 'error',
                'no-script-url': 'error',
                'no-implied-eval': 'error',
                'no-alert': 'warn',
                'no-console': 'off'
            }
        }
    });
} catch (error) {
    // Fallback to older configuration format
    try {
        eslint = new ESLint({
            overrideConfig: {
                env: {
                    browser: true,
                    es2021: true,
                    node: true
                },
                parserOptions: {
                    ecmaVersion: 2021,
                    sourceType: 'script'
                },
                rules: {
                    'no-eval': 'error',
                    'no-script-url': 'error',
                    'no-implied-eval': 'error',
                    'no-alert': 'warn',
                    'no-console': 'off'
                }
            }
        });
    } catch (fallbackError) {
        console.warn('ESLint configuration failed, some JavaScript analysis may be limited:', fallbackError.message);
        eslint = null;
    }
}

// Core Analysis Function
async function analyzeCodeSnippet(codeSnippet) {
    const findings = [];
    let jsCodeToAnalyze = '';

    try {
        // Step 1: Check if input is HTML
        const trimmedCode = codeSnippet.trim();
        const isHtml = trimmedCode.startsWith('<') || trimmedCode.includes('<script') || trimmedCode.includes('<html');

        if (isHtml) {
            const $ = cheerio.load(codeSnippet);

            // Extract JavaScript from script tags
            $('script').each((i, el) => {
                const scriptContent = $(el).html();
                if (scriptContent && scriptContent.trim()) {
                    jsCodeToAnalyze += scriptContent + '\n';
                }
            });

            // Check for insecure CSP
            $('meta[http-equiv="Content-Security-Policy"]').each((i, el) => {
                const content = $(el).attr('content');
                if (content && (content.includes('unsafe-inline') || content.includes('unsafe-eval') || content.includes('data:'))) {
                    findings.push({
                        type: "A08: Software and Data Integrity Failures",
                        detail: `Insecure Content-Security-Policy found: "${content}"`,
                        severity: "High",
                        code_snippet: $(el).prop('outerHTML') || content
                    });
                }
            });

            // Check for inline event handlers
            const inlineEventAttrs = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur', 'oninput', 'onchange', 'onsubmit'];
            $('*').each((i, el) => {
                const element = $(el);
                inlineEventAttrs.forEach(attr => {
                    const attrValue = element.attr(attr);
                    if (attrValue) {
                        findings.push({
                            type: "A03: Injection (XSS via Inline Events)",
                            detail: `Found inline event handler '${attr}' with value: ${attrValue}`,
                            severity: "Medium",
                            code_snippet: element.prop('outerHTML')?.substring(0, 150) + '...' || `${attr}="${attrValue}"`
                        });
                    }
                });
            });

            // Check for potentially dangerous attributes
            $('*').each((i, el) => {
                const element = $(el);
                const src = element.attr('src');
                const href = element.attr('href');
                
                if (src && src.startsWith('javascript:')) {
                    findings.push({
                        type: "A03: Injection (JavaScript URL in src)",
                        detail: `Found javascript: URL in src attribute: ${src}`,
                        severity: "High",
                        code_snippet: element.prop('outerHTML')?.substring(0, 100) + '...' || src
                    });
                }
                
                if (href && href.startsWith('javascript:')) {
                    findings.push({
                        type: "A03: Injection (JavaScript URL in href)",
                        detail: `Found javascript: URL in href attribute: ${href}`,
                        severity: "High",
                        code_snippet: element.prop('outerHTML')?.substring(0, 100) + '...' || href
                    });
                }
            });

        } else {
            // Treat as pure JavaScript
            jsCodeToAnalyze = codeSnippet;
        }

        // Step 2: Manual JavaScript Pattern Analysis (as backup/complement to ESLint)
        await performManualJSAnalysis(jsCodeToAnalyze, findings);

        // Step 3: ESLint Analysis (only if ESLint is available)
        if (eslint && jsCodeToAnalyze.trim()) {
            try {
                const results = await eslint.lintText(jsCodeToAnalyze);
                
                for (const result of results) {
                    for (const message of result.messages) {
                        let severity = 'Low';
                        if (message.severity === 2) severity = 'High';
                        else if (message.severity === 1) severity = 'Medium';

                        // Get code snippet context
                        const lines = jsCodeToAnalyze.split('\n');
                        const lineIndex = Math.max(0, (message.line || 1) - 1);
                        const offendingLine = lines[lineIndex] || '';
                        const snippetStart = Math.max(0, (message.column || 1) - 20);
                        const snippetEnd = (message.column || 1) + 20;
                        const contextSnippet = offendingLine.substring(snippetStart, snippetEnd);

                        // Map ESLint rules to OWASP categories
                        let owaspType = "A03: Injection (JavaScript Vulnerability)";
                        let detailMessage = message.message;

                        switch (message.ruleId) {
                            case 'no-eval':
                            case 'no-implied-eval':
                                owaspType = "A03: Injection (Code Execution)";
                                detailMessage = "Usage of eval() or similar detected. This can execute arbitrary code from user input.";
                                break;
                            case 'no-script-url':
                                owaspType = "A03: Injection (Script Protocol)";
                                detailMessage = "javascript: URL detected. This can lead to XSS vulnerabilities.";
                                break;
                            case 'no-alert':
                                owaspType = "A03: Injection (XSS Indicator)";
                                detailMessage = "alert() usage detected. Often used as XSS proof-of-concept.";
                                break;
                        }

                        findings.push({
                            type: owaspType,
                            detail: detailMessage,
                            severity: severity,
                            code_snippet: contextSnippet.trim() || offendingLine.trim(),
                            line: message.line,
                            column: message.column,
                            ruleId: message.ruleId
                        });
                    }
                }
            } catch (eslintError) {
                console.error("ESLint analysis error:", eslintError);
                findings.push({
                    type: "Scanner Warning",
                    detail: `ESLint analysis encountered an issue: ${eslintError.message}`,
                    severity: "Low",
                    code_snippet: "ESLint analysis failed"e
                });
            }
        }

        // Step 4: Additional security checks
        await performAdditionalSecurityChecks(codeSnippet, findings);

    } catch (error) {
        console.error("Analysis error:", error);
        findings.push({
            type: "Scanner Error",
            detail: `Code analysis failed: ${error.message}`,
            severity: "Error",
            code_snippet: codeSnippet.substring(0, 100) + '...'
        });
    }

    // DOMPurify demo
    const sampleVulnerableHtml = '<img src=x onerror=alert(1)><a href="javascript:alert(1)">Click me</a>';
    const safeHtml = DOMPurify.sanitize(sampleVulnerableHtml);

    return { findings, safeHtml, sampleVulnerableHtml };
}

// Manual JavaScript pattern analysis as fallback
async function performManualJSAnalysis(jsCode, findings) {
    if (!jsCode.trim()) return;

    // Check for eval usage
    if (jsCode.includes('eval(')) {
        findings.push({
            type: "A03: Injection (Code Execution)",
            detail: "Usage of eval() detected. This can execute arbitrary code from user input.",
            severity: "High",
            code_snippet: "eval() usage found"
        });
    }

    // Check for setTimeout/setInterval with string arguments
    const timeoutRegex = /set(Timeout|Interval)\s*\(\s*["'`]/;
    if (timeoutRegex.test(jsCode)) {
        findings.push({
            type: "A03: Injection (Implied Eval)",
            detail: "setTimeout/setInterval with string argument detected. This is equivalent to eval().",
            severity: "High",
            code_snippet: "setTimeout/setInterval with string argument"
        });
    }

    // Check for Function constructor
    if (jsCode.includes('new Function(') || jsCode.includes('Function(')) {
        findings.push({
            type: "A03: Injection (Dynamic Code Generation)",
            detail: "Function constructor usage detected. This can execute arbitrary code.",
            severity: "High",
            code_snippet: "Function constructor usage"
        });
    }

    // Check for alert usage
    if (jsCode.includes('alert(')) {
        findings.push({
            type: "A03: Injection (XSS Indicator)",
            detail: "alert() usage detected. Often used as XSS proof-of-concept.",
            severity: "Medium",
            code_snippet: "alert() usage found"
        });
    }
}

// Additional security pattern checks
async function performAdditionalSecurityChecks(codeSnippet, findings) {
    // Check for cookie manipulation without security considerations
    if (codeSnippet.includes('document.cookie')) {
        if (!codeSnippet.includes('HttpOnly') && !codeSnippet.includes('Secure')) {
            findings.push({
                type: "A07: Identification and Authentication Failures",
                detail: "Cookie manipulation detected without security flags (HttpOnly, Secure)",
                severity: "Medium",
                code_snippet: "document.cookie usage without security flags"
            });
        }
    }

    // Check for browser storage usage
    if (codeSnippet.includes('localStorage') || codeSnippet.includes('sessionStorage')) {
        findings.push({
            type: "A02: Cryptographic Failures",
            detail: "Browser storage usage detected. Ensure sensitive data is not stored in client-side storage.",
            severity: "Low",
            code_snippet: "Browser storage usage detected"
        });
    }

    // Check for innerHTML usage (potential XSS)
    if (codeSnippet.includes('innerHTML')) {
        findings.push({
            type: "A03: Injection (DOM XSS)",
            detail: "innerHTML usage detected. This can lead to XSS if user input is not sanitized.",
            severity: "Medium",
            code_snippet: "innerHTML usage found"
        });
    }

    // Check for document.write usage
    if (codeSnippet.includes('document.write')) {
        findings.push({
            type: "A03: Injection (DOM Manipulation)",
            detail: "document.write usage detected. This can be dangerous with unsanitized input.",
            severity: "Medium",
            code_snippet: "document.write usage found"
        });
    }
}

// Routes
app.post('/scan', async (req, res) => {
    try {
        const codeInput = req.body.code_snippet || '';
        
        if (!codeInput.trim()) {
            return res.json({
                findings: [{
                    type: "Input Error",
                    detail: "No code provided for analysis",
                    severity: "Error",
                    code_snippet: ""
                }],
                codeInput: codeInput,
                domPurifyDemo: {
                    original: '<img src=x onerror=alert(1)>',
                    sanitized: DOMPurify.sanitize('<img src=x onerror=alert(1)>')
                }
            });
        }

        const { findings, safeHtml, sampleVulnerableHtml } = await analyzeCodeSnippet(codeInput);
        
        // Sort findings by severity
        const severityOrder = { "High": 1, "Medium": 2, "Low": 3, "Error": 4 };
        findings.sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

        res.json({
            findings: findings,
            codeInput: codeInput,
            domPurifyDemo: {
                original: sampleVulnerableHtml,
                sanitized: safeHtml
            }
        });

    } catch (error) {
        console.error("Route error:", error);
        res.status(500).json({
            findings: [{
                type: "Server Error",
                detail: `Server encountered an error: ${error.message}`,
                severity: "Error",
                code_snippet: ""
            }],
            codeInput: req.body.code_snippet || '',
            domPurifyDemo: {
                original: '',
                sanitized: ''
            }
        });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(port, () => {
    console.log(`OWASP ClientScanPy server listening at http://localhost:${port}`);
    if (!eslint) {
        console.log('Note: ESLint integration is limited due to configuration issues, but manual analysis is still functional.');
    }
});
