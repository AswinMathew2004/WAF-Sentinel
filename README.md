# 🛡️ WAF Sentinel

### Advanced Web Application Firewall Fingerprinting Tool

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20kali-orange.svg" alt="Platform">
  <img src="https://img.shields.io/badge/version-2.0.0-red.svg" alt="Version">
</p>

```
 ██╗    ██╗ █████╗ ███████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ██║    ██║██╔══██╗██╔════╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ██║ █╗ ██║███████║█████╗      ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ██║███╗██║██╔══██║██╔══╝      ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ╚███╔███╔╝██║  ██║██║         ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝         ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

A powerful, multi-technique WAF detection and fingerprinting tool designed for penetration testers and security researchers. Identifies **30+ WAF vendors** using 8 parallel detection methods.

---

## 🔥 Features

- **30+ WAF Signatures** — Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, F5 BIG-IP, ModSecurity, Fortinet, Azure, GCP Cloud Armor, Fastly, Barracuda, and many more
- **8 Detection Methods**:
  - HTTP Header Analysis
  - Cookie Fingerprinting
  - Response Body Pattern Matching
  - Status Code Behaviour Analysis
  - SSL/TLS Certificate Inspection
  - DNS CNAME Resolution
  - Response Timing Anomalies
  - Aggressive Payload Triggering
- **Confidence Scoring** — Multi-signal aggregation with cross-method bonuses
- **Stealth Mode** — Randomized delays and user-agent rotation
- **Proxy Support** — Route through Burp Suite, SOCKS, or Tor
- **JSON Reports** — Machine-readable output for CI/CD pipelines
- **Zero Dependencies on Kali** — Works on any Python 3.8+ system

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/waf-sentinel.git
cd waf-sentinel

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x waf-sentinel.py
```

### Kali Linux (pre-installed deps)

```bash
# Most dependencies ship with Kali — just clone and run
git clone https://github.com/YOUR_USERNAME/waf-sentinel.git
cd waf-sentinel
python3 waf-sentinel.py -t example.com
```

---

## 🚀 Usage

### Basic Scan (Passive)
```bash
python3 waf-sentinel.py -t example.com
```

### Aggressive Mode (Payload Testing)
```bash
python3 waf-sentinel.py -t https://target.com --aggressive
```

### Stealth Mode + JSON Report
```bash
python3 waf-sentinel.py -t target.com --stealth --output report.json
```

### Full Scan Through Proxy
```bash
python3 waf-sentinel.py -t target.com -a -v --proxy http://127.0.0.1:8080
```

### All Options

```
Usage: waf-sentinel.py [-h] -t TARGET [-a] [-s] [-o OUTPUT] [-v]
                       [--threads N] [--timeout N] [--proxy URL]

Options:
  -t, --target      Target URL or domain (required)
  -a, --aggressive  Enable aggressive payload-based detection
  -s, --stealth     Stealth mode (random delays between requests)
  -o, --output      Save JSON report to file
  -v, --verbose     Verbose output
  --threads          Number of threads (default: 5)
  --timeout          Request timeout in seconds (default: 10)
  --proxy            HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080)
```

---

## 📊 Detection Methods Explained

| Method | Technique | Stealth Level |
|---|---|---|
| **Header Analysis** | Inspects response headers for WAF-specific names and values | 🟢 Passive |
| **Cookie Fingerprinting** | Matches cookie names/patterns to known WAF signatures | 🟢 Passive |
| **Body Analysis** | Scans HTML for block page signatures and error messages | 🟢 Passive |
| **Status Code Analysis** | Detects WAF-typical HTTP response codes (403, 406, 429…) | 🟢 Passive |
| **SSL/TLS Inspection** | Examines certificate issuer, subject, and SAN for CDN/WAF hints | 🟢 Passive |
| **DNS CNAME Check** | Resolves DNS to identify CDN/WAF infrastructure | 🟢 Passive |
| **Timing Analysis** | Compares response times for normal vs attack-like requests | 🟡 Low Risk |
| **Payload Trigger** | Sends benign attack payloads to provoke WAF block responses | 🔴 Active |

---

## 🎯 Supported WAFs

| WAF | Vendor | Detection |
|---|---|---|
| Cloudflare | Cloudflare, Inc. | ✅ Headers, Cookies, Body, SSL, DNS |
| AWS WAF | Amazon | ✅ Headers, Cookies, Body |
| Akamai Kona | Akamai Technologies | ✅ Headers, Cookies, SSL, DNS |
| Imperva / Incapsula | Imperva | ✅ Headers, Cookies, Body, DNS |
| Sucuri | GoDaddy/Sucuri | ✅ Headers, Cookies, Body, Server |
| F5 BIG-IP ASM | F5 Networks | ✅ Headers, Cookies, Body, Server |
| ModSecurity | Trustwave/OWASP | ✅ Headers, Body, Server |
| Barracuda WAF | Barracuda Networks | ✅ Cookies, Body, Server |
| Fortinet FortiWeb | Fortinet | ✅ Cookies, Body, Server |
| Citrix NetScaler | Citrix | ✅ Headers, Cookies, Body |
| Wordfence | Defiant | ✅ Cookies, Body |
| Azure Front Door | Microsoft | ✅ Headers, Body, Server |
| Google Cloud Armor | Google | ✅ Headers, Body, Server |
| StackPath | StackPath | ✅ Headers, Body |
| DDoS-Guard | DDoS-Guard | ✅ Headers, Cookies, Server |
| Wallarm | Wallarm | ✅ Headers, Body |
| Reblaze | Reblaze | ✅ Headers, Cookies |
| Radware AppWall | Radware | ✅ Headers, Body |
| Fastly WAF | Fastly | ✅ Headers, Body |
| Alibaba Cloud WAF | Alibaba | ✅ Cookies, Server, Body |
| Tencent Cloud WAF | Tencent | ✅ Cookies, Body |
| Palo Alto Networks | Palo Alto | ✅ Body |
| LiteSpeed WAF | LiteSpeed | ✅ Server, Body |
| Comodo WAF | Comodo | ✅ Server, Body |
| Shield Security | Shield | ✅ Body |
| SiteLock TrueShield | SiteLock | ✅ Body |
| Qrator | Qrator Labs | ✅ Cookies, Server |
| Varnish + Security | Varnish Software | ✅ Headers, Body |
| Edgecast / Verizon | Edgecast | ✅ Headers, Server |

---

## 📄 Sample Output

```
  ───────────────────────────────────────────────────────
    RESULTS
  ───────────────────────────────────────────────────────

  [✓] Identified 2 WAF(s):

  [1] Cloudflare
      Confidence : 95% (Definite)
      Methods    : header_analysis, cookie_analysis, body_analysis, ssl_analysis, dns_analysis
      › Header present: cf-ray
      › Server header matches: cloudflare
      › Cookie matches: __cf_bm
      › SSL certificate hints at 'cloudflare'
      › DNS CNAME points to: target.cdn.cloudflare.net

  [2] Generic / Unknown WAF
      Confidence : 40% (Low)
      Methods    : payload_trigger
      › Payload 'SQLi — Union select' triggered block (HTTP 403)
```

---

## 🔧 Project Structure

```
waf-sentinel/
├── waf-sentinel.py          # Main entry point
├── core/
│   ├── __init__.py
│   ├── signatures.py        # WAF signature database (30+ WAFs)
│   ├── payloads.py          # Aggressive detection payloads
│   └── utils.py             # CLI display utilities
├── requirements.txt
├── LICENSE
└── README.md
```

---

## ⚖️ Legal Disclaimer

**This tool is intended for authorized security testing and research only.**

Always obtain proper written authorization before testing any target. Unauthorized testing of systems you do not own or have permission to test is **illegal** and may violate computer fraud and abuse laws in your jurisdiction.

The authors assume no liability and are not responsible for any misuse or damage caused by this tool.

---

## 🤝 Contributing

Contributions are welcome! To add a new WAF signature:

1. Fork the repository
2. Add the signature to `core/signatures.py` following the existing format
3. Test against a known target
4. Submit a pull request

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Made with ☕ for the security community</b><br>
  <i>Star ⭐ this repo if you find it useful!</i>
</p>
