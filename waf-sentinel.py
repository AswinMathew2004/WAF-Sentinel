#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╦ ╦╔═╗╔═╗  ╔═╗╔═╗╔╗╔╔╦╗╦╔╗╔╔═╗╦  
║║║╠═╣╠╣   ╚═╗║╣ ║║║ ║ ║║║║║╣ ║  
╚╩╝╩ ╩╚    ╚═╝╚═╝╝╚╝ ╩ ╩╝╚╝╚═╝╩═╝

WAF Sentinel - Advanced Web Application Firewall Fingerprinting Tool
Author : github.com/YOUR_USERNAME
Version: 2.0.0
License: MIT

A powerful reconnaissance tool for identifying and fingerprinting
Web Application Firewalls (WAFs) protecting web targets.
"""

import sys
import os
import argparse
import json
import time
import random
import hashlib
import ssl
import socket
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] 'requests' not installed. Run: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    # Fallback: no color
    class _Stub:
        def __getattr__(self, _): return ""
    Fore = Style = _Stub()

from core.signatures import WAF_SIGNATURES
from core.payloads import DETECTION_PAYLOADS
from core.utils import (
    print_banner, print_status, print_success, print_error,
    print_warning, print_info, print_section, format_table
)


# ───────────────────────── Configuration ─────────────────────────

VERSION = "2.0.0"
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 5
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/125.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


# ───────────────────────── Core Engine ─────────────────────────

class WAFSentinel:
    """Core WAF fingerprinting engine."""

    def __init__(self, target, options=None):
        self.target = self._normalize_url(target)
        self.options = options or {}
        self.timeout = self.options.get("timeout", DEFAULT_TIMEOUT)
        self.threads = self.options.get("threads", DEFAULT_THREADS)
        self.verbose = self.options.get("verbose", False)
        self.aggressive = self.options.get("aggressive", False)
        self.stealth = self.options.get("stealth", False)
        self.output_file = self.options.get("output", None)
        self.proxy = self.options.get("proxy", None)

        self.session = self._build_session()
        self.results = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "detected_wafs": [],
            "headers_analysis": {},
            "cookies_analysis": {},
            "behavior_analysis": {},
            "ssl_analysis": {},
            "score_breakdown": {},
            "raw_evidence": [],
        }

    # ── URL Handling ──

    @staticmethod
    def _normalize_url(url):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    # ── HTTP Session ──

    def _build_session(self):
        s = requests.Session()
        retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503])
        adapter = HTTPAdapter(max_retries=retries)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        if self.proxy:
            s.proxies = {"http": self.proxy, "https": self.proxy}
        s.verify = False
        return s

    def _get_headers(self):
        ua = random.choice(DEFAULT_USER_AGENTS)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
        }
        return headers

    def _request(self, url=None, method="GET", params=None, data=None, headers=None, allow_redirects=True):
        url = url or self.target
        headers = headers or self._get_headers()
        if self.stealth:
            time.sleep(random.uniform(1.0, 3.0))
        try:
            resp = self.session.request(
                method, url,
                params=params, data=data, headers=headers,
                timeout=self.timeout, allow_redirects=allow_redirects
            )
            return resp
        except requests.exceptions.ConnectionError:
            if self.verbose:
                print_error(f"Connection failed: {url}")
            return None
        except requests.exceptions.Timeout:
            if self.verbose:
                print_error(f"Timeout: {url}")
            return None
        except Exception as e:
            if self.verbose:
                print_error(f"Request error: {e}")
            return None

    # ── Detection Modules ──

    def detect_by_headers(self, response):
        """Analyze HTTP response headers for WAF signatures."""
        findings = []
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        self.results["headers_analysis"] = dict(response.headers)

        for waf_name, sig in WAF_SIGNATURES.items():
            score = 0
            evidence = []

            # Check header names
            for hdr in sig.get("headers", []):
                if hdr.lower() in headers:
                    score += 30
                    evidence.append(f"Header present: {hdr}")

            # Check header values
            for hdr, patterns in sig.get("header_values", {}).items():
                val = headers.get(hdr.lower(), "")
                for pat in patterns:
                    if pat.lower() in val.lower():
                        score += 25
                        evidence.append(f"Header '{hdr}' contains '{pat}'")

            # Check Server header
            server = headers.get("server", "")
            for srv_sig in sig.get("server_signatures", []):
                if srv_sig.lower() in server.lower():
                    score += 35
                    evidence.append(f"Server header matches: {srv_sig}")

            if score > 0:
                findings.append({"waf": waf_name, "score": score, "evidence": evidence, "method": "header_analysis"})

        return findings

    def detect_by_cookies(self, response):
        """Analyze cookies for WAF fingerprints."""
        findings = []
        if not response:
            return findings

        cookies = {c.name.lower(): c.value for c in response.cookies}
        self.results["cookies_analysis"] = {c.name: c.value for c in response.cookies}

        for waf_name, sig in WAF_SIGNATURES.items():
            score = 0
            evidence = []
            for cookie_pat in sig.get("cookies", []):
                for cname in cookies:
                    if cookie_pat.lower() in cname:
                        score += 30
                        evidence.append(f"Cookie matches: {cname}")

            if score > 0:
                findings.append({"waf": waf_name, "score": score, "evidence": evidence, "method": "cookie_analysis"})

        return findings

    def detect_by_response_body(self, response):
        """Check response body for WAF block page signatures."""
        findings = []
        if not response or not response.text:
            return findings

        body = response.text.lower()

        for waf_name, sig in WAF_SIGNATURES.items():
            score = 0
            evidence = []
            for body_sig in sig.get("body_signatures", []):
                if body_sig.lower() in body:
                    score += 20
                    evidence.append(f"Body contains: '{body_sig[:60]}...'")

            if score > 0:
                findings.append({"waf": waf_name, "score": score, "evidence": evidence, "method": "body_analysis"})

        return findings

    def detect_by_status_codes(self, response):
        """Analyze response status codes for WAF behaviour."""
        findings = []
        if not response:
            return findings

        code = response.status_code
        for waf_name, sig in WAF_SIGNATURES.items():
            score = 0
            evidence = []
            if code in sig.get("block_codes", []):
                score += 15
                evidence.append(f"Status code {code} matches WAF block pattern")

            if score > 0:
                findings.append({"waf": waf_name, "score": score, "evidence": evidence, "method": "status_analysis"})

        return findings

    def detect_by_payload_trigger(self):
        """Send attack-like payloads and analyze WAF responses."""
        findings = []
        if not self.aggressive:
            return findings

        print_info("Running aggressive payload detection...")

        for payload_info in DETECTION_PAYLOADS:
            name = payload_info["name"]
            payload = payload_info["payload"]
            method = payload_info.get("method", "GET")

            if self.verbose:
                print_status(f"Testing payload: {name}")

            if method == "GET":
                url = f"{self.target}/?test={payload}"
                resp = self._request(url=url)
            else:
                resp = self._request(method="POST", data={"input": payload})

            if not resp:
                continue

            # A blocked response is evidence of a WAF
            if resp.status_code in [403, 406, 419, 429, 451, 501, 503]:
                evidence = [
                    f"Payload '{name}' triggered block (HTTP {resp.status_code})",
                    f"Response length: {len(resp.content)} bytes"
                ]

                # Check which WAF blocked it
                header_findings = self.detect_by_headers(resp)
                body_findings = self.detect_by_response_body(resp)
                cookie_findings = self.detect_by_cookies(resp)

                for f in header_findings + body_findings + cookie_findings:
                    f["score"] += 20  # bonus for payload-triggered detection
                    f["evidence"].extend(evidence)
                    f["method"] = "payload_trigger"
                    findings.append(f)

                # Generic WAF detection if no specific signature matched
                if not header_findings and not body_findings:
                    findings.append({
                        "waf": "Generic / Unknown WAF",
                        "score": 40,
                        "evidence": evidence,
                        "method": "payload_trigger"
                    })

            if self.stealth:
                time.sleep(random.uniform(2, 5))

        return findings

    def detect_by_ssl(self):
        """Inspect TLS certificate for WAF/CDN provider hints."""
        findings = []
        parsed = urlparse(self.target)
        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    der_cert = ssock.getpeercert(binary_form=True)

                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    san = cert.get("subjectAltName", [])

                    cert_info = {
                        "issuer": issuer,
                        "subject": subject,
                        "san": [s[1] for s in san][:10],
                        "serial": cert.get("serialNumber", ""),
                        "fingerprint_sha256": hashlib.sha256(der_cert).hexdigest() if der_cert else "",
                    }
                    self.results["ssl_analysis"] = cert_info

                    # CDN/WAF provider detection via cert
                    cert_str = json.dumps(cert_info).lower()
                    provider_hints = {
                        "Cloudflare": ["cloudflare", "cloudflaressl"],
                        "Akamai": ["akamai", "akamaitech"],
                        "AWS CloudFront": ["amazon", "cloudfront", "aws"],
                        "Fastly": ["fastly", "globalsign"],
                        "Sucuri": ["sucuri"],
                        "Imperva/Incapsula": ["incapsula", "imperva"],
                        "StackPath": ["stackpath", "highwinds"],
                    }
                    for provider, keywords in provider_hints.items():
                        for kw in keywords:
                            if kw in cert_str:
                                findings.append({
                                    "waf": provider,
                                    "score": 20,
                                    "evidence": [f"SSL certificate hints at '{kw}'"],
                                    "method": "ssl_analysis"
                                })
                                break
        except Exception as e:
            if self.verbose:
                print_warning(f"SSL analysis failed: {e}")

        return findings

    def detect_by_timing(self):
        """Detect WAFs through response timing anomalies."""
        findings = []
        timings = []

        # Normal requests
        for _ in range(3):
            start = time.time()
            resp = self._request()
            if resp:
                timings.append(time.time() - start)

        if not timings:
            return findings

        baseline = sum(timings) / len(timings)

        # Malicious-looking request
        evil_url = f"{self.target}/?id=1' OR '1'='1"
        start = time.time()
        resp = self._request(url=evil_url)
        if resp:
            evil_time = time.time() - start
            delta = evil_time - baseline

            self.results["behavior_analysis"]["baseline_avg_ms"] = round(baseline * 1000, 2)
            self.results["behavior_analysis"]["attack_response_ms"] = round(evil_time * 1000, 2)
            self.results["behavior_analysis"]["delta_ms"] = round(delta * 1000, 2)

            # Significant delay or much faster (cached block page) = WAF
            if abs(delta) > 1.0:
                findings.append({
                    "waf": "WAF Detected (Timing Anomaly)",
                    "score": 15,
                    "evidence": [
                        f"Baseline: {baseline*1000:.0f}ms, Attack: {evil_time*1000:.0f}ms, Delta: {delta*1000:.0f}ms"
                    ],
                    "method": "timing_analysis"
                })

        return findings

    def detect_by_dns(self):
        """Check DNS CNAME/NS for known WAF/CDN providers."""
        findings = []
        hostname = urlparse(self.target).hostname

        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", hostname],
                capture_output=True, text=True, timeout=10
            )
            cname = result.stdout.strip()
            if cname:
                cname_lower = cname.lower()
                dns_hints = {
                    "Cloudflare": ["cloudflare"],
                    "AWS WAF / CloudFront": ["cloudfront.net", "awsglobalaccelerator"],
                    "Akamai": ["akamai", "edgekey", "edgesuite"],
                    "Sucuri": ["sucuri"],
                    "Imperva/Incapsula": ["incapdns", "imperva"],
                    "StackPath": ["stackpath"],
                    "Fastly": ["fastly"],
                    "Azure Front Door": ["azurefd", "azureedge", "trafficmanager"],
                    "Google Cloud Armor": ["googleusercontent"],
                }
                for provider, keywords in dns_hints.items():
                    for kw in keywords:
                        if kw in cname_lower:
                            findings.append({
                                "waf": provider,
                                "score": 25,
                                "evidence": [f"DNS CNAME points to: {cname}"],
                                "method": "dns_analysis"
                            })
                            break
        except Exception as e:
            if self.verbose:
                print_warning(f"DNS check skipped: {e}")

        return findings

    # ── Aggregation ──

    def _aggregate(self, all_findings):
        """Merge findings and compute confidence scores."""
        merged = {}
        for f in all_findings:
            waf = f["waf"]
            if waf not in merged:
                merged[waf] = {"score": 0, "evidence": [], "methods": set()}
            merged[waf]["score"] += f["score"]
            merged[waf]["evidence"].extend(f["evidence"])
            merged[waf]["methods"].add(f["method"])

        detected = []
        for waf, data in merged.items():
            # Multi-method detection bonus
            if len(data["methods"]) >= 3:
                data["score"] += 20
            elif len(data["methods"]) >= 2:
                data["score"] += 10

            confidence = min(data["score"], 100)
            if confidence >= 90:
                level = "Definite"
            elif confidence >= 70:
                level = "High"
            elif confidence >= 50:
                level = "Moderate"
            elif confidence >= 30:
                level = "Low"
            else:
                level = "Tentative"

            detected.append({
                "waf": waf,
                "confidence": confidence,
                "confidence_level": level,
                "evidence": list(set(data["evidence"])),
                "detection_methods": list(data["methods"]),
            })

        detected.sort(key=lambda x: x["confidence"], reverse=True)
        return detected

    # ── Main Scan ──

    def scan(self):
        """Run the full WAF fingerprinting scan."""
        print_banner(VERSION)
        print_section("TARGET")
        print_info(f"URL    : {self.target}")
        print_info(f"Mode   : {'Aggressive' if self.aggressive else 'Passive'}{' + Stealth' if self.stealth else ''}")
        print_info(f"Threads: {self.threads}")
        print()

        # Phase 1: Initial request
        print_section("PHASE 1 — Initial Reconnaissance")
        resp = self._request()
        if not resp:
            print_error("Target unreachable. Aborting.")
            return self.results
        print_success(f"Target alive — HTTP {resp.status_code} ({len(resp.content)} bytes)")

        all_findings = []

        # Phase 2: Passive detection
        print_section("PHASE 2 — Passive Analysis")
        print_status("Analyzing response headers...")
        all_findings.extend(self.detect_by_headers(resp))

        print_status("Analyzing cookies...")
        all_findings.extend(self.detect_by_cookies(resp))

        print_status("Analyzing response body...")
        all_findings.extend(self.detect_by_response_body(resp))

        print_status("Analyzing status codes...")
        all_findings.extend(self.detect_by_status_codes(resp))

        print_status("Inspecting SSL/TLS certificate...")
        all_findings.extend(self.detect_by_ssl())

        print_status("Checking DNS records...")
        all_findings.extend(self.detect_by_dns())

        print_status("Timing analysis...")
        all_findings.extend(self.detect_by_timing())

        # Phase 3: Aggressive (optional)
        if self.aggressive:
            print_section("PHASE 3 — Aggressive Payload Testing")
            all_findings.extend(self.detect_by_payload_trigger())

        # Phase 4: Results
        print_section("RESULTS")
        detected = self._aggregate(all_findings)
        self.results["detected_wafs"] = detected
        self.results["raw_evidence"] = all_findings

        if detected:
            print_success(f"Identified {len(detected)} WAF(s):\n")
            for i, d in enumerate(detected, 1):
                conf = d["confidence"]
                level = d["confidence_level"]
                # Color by confidence
                if conf >= 70:
                    color = Fore.GREEN
                elif conf >= 40:
                    color = Fore.YELLOW
                else:
                    color = Fore.RED

                print(f"  {color}[{i}] {d['waf']}{Style.RESET_ALL}")
                print(f"      Confidence : {color}{conf}% ({level}){Style.RESET_ALL}")
                print(f"      Methods    : {', '.join(d['detection_methods'])}")
                for ev in d["evidence"][:5]:
                    print(f"      › {ev}")
                print()
        else:
            print_warning("No WAF detected — target may be unprotected or using unknown WAF.")
            print_info("Try running with --aggressive for deeper analysis.")

        # Save output
        if self.output_file:
            self._save_report()

        return self.results

    def _save_report(self):
        """Export results to JSON."""
        ext = os.path.splitext(self.output_file)[1]
        try:
            with open(self.output_file, "w") as f:
                json.dump(self.results, f, indent=2, default=str)
            print_success(f"Report saved: {self.output_file}")
        except Exception as e:
            print_error(f"Failed to save report: {e}")


# ───────────────────────── CLI ─────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="WAF Sentinel — Advanced WAF Fingerprinting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 waf-sentinel.py -t example.com
  python3 waf-sentinel.py -t https://target.com --aggressive
  python3 waf-sentinel.py -t target.com --stealth --output report.json
  python3 waf-sentinel.py -t target.com -a -v --proxy http://127.0.0.1:8080
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL or domain")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Enable aggressive payload-based detection")
    parser.add_argument("-s", "--stealth", action="store_true", help="Stealth mode (random delays between requests)")
    parser.add_argument("-o", "--output", help="Output JSON report file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Number of threads (default: 5)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")

    args = parser.parse_args()

    options = {
        "aggressive": args.aggressive,
        "stealth": args.stealth,
        "output": args.output,
        "verbose": args.verbose,
        "threads": args.threads,
        "timeout": args.timeout,
        "proxy": args.proxy,
    }

    scanner = WAFSentinel(args.target, options)
    scanner.scan()


if __name__ == "__main__":
    main()
