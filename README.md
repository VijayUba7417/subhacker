<div align="center">

# ⚡ SubHacker

### Advanced Subdomain Takeover & Attack Surface Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20WSL2-orange?style=flat-square)](https://kali.org)
[![Version](https://img.shields.io/badge/Version-1.0-cyan?style=flat-square)](CHANGELOG.md)
[![BugBounty](https://img.shields.io/badge/Use%20Case-Bug%20Bounty%20%7C%20VAPT-red?style=flat-square)](https://bugcrowd.com)

<br/>

**SubHacker** is a professional GUI subdomain takeover scanner with a 5-phase attack surface discovery engine.  
It combines passive OSINT, active DNS recon, HTTP probing, extended analysis, and takeover fingerprinting - all in one dark-themed desktop application.

<br/>

> ⚠️ **Authorized testing only.** Only use against targets you own or have explicit written permission to test.

</div>

---

## 🔥 5-Phase Scan Engine

```
Phase 1 ──► Passive Enumeration    14 sources (HTTP APIs + Go tools)
Phase 2 ──► Active Scanning        DNS BF, Zone Transfer, VHost, TLD Perm, Reverse IP, DNS Perm
Phase 3 ──► HTTP Probing           Live host discovery, WAF & tech fingerprinting
Phase 4 ──► Extended Scanning      Port scan, Dir discovery, CORS, Security Headers, AJAX Spider, Cloud Buckets
Phase 5 ──► Takeover Analysis      CNAME/NS/MX dangling with 30+ service fingerprints
```

---

## 📋 Scanning Phases (all toggleable)

| # | Phase | Description |
|---|-------|-------------|
| 1 | DNS Brute-Force | ~260 subdomain words × 120 threads |
| 2 | HTTP Probing | Status codes, titles, WAF & tech stack detection |
| 3 | Port Scan | 10 common ports per live host |
| 4 | Directory Discovery | 35 sensitive paths (.git, admin, .env, phpinfo, etc.) |
| 5 | AJAX Spider | Crawls JS/HTML to extract hidden subdomains from links |
| 6 | Cloud Buckets | S3/Azure/GCS/DO/R2 permutations + NoSuchBucket detection |
| 7 | CORS Check | 4 origin injection variants per host |
| 8 | Security Headers | Audits HSTS, CSP, X-Frame-Options, Referrer-Policy, etc. |
| 9 | Zone Transfer | AXFR attempt on every NS record |
| 10 | DNS Permutation | env-prefix + number variants of existing subdomains |
| 11 | TLD Permutation | Probes 80+ TLDs for live variants |
| 12 | Reverse IP | Co-hosted domain discovery via HackerTarget |
| 13 | VHost Fuzzing | Host-header injection against target IP |
| 14 | NS Record Check | Dangling NS → full zone control (Critical) |
| 15 | MX Record Check | Dangling MX → email interception |

---

## 🌐 Passive Sources (14 total)

| Source | Method |
|--------|--------|
| crt.sh | Certificate Transparency logs |
| Wayback Machine | Historical archived URLs |
| HackerTarget | Passive DNS API |
| AlienVault OTX | Threat intelligence passive DNS |
| RapidDNS | DNS database lookup |
| ThreatCrowd | Historical DNS records |
| BufferOver | DNS dataset |
| URLScan.io | Crawled domain index |
| VirusTotal | Passive DNS *(API key required)* |
| Shodan | Host discovery *(API key required)* |
| subfinder | Multi-source passive Go tool |
| assetfinder | Cert transparency + public APIs |
| amass | Comprehensive OSINT enumeration |
| findomain | Fast multi-source Go tool |

---

## 🛡️ Detection Coverage

**Takeover Fingerprints (30+ services)**

`AWS S3` `AWS ELB` `AWS CloudFront` `GitHub Pages` `Heroku` `Netlify` `Vercel`
`Azure Web Apps` `Azure Blob` `Fastly` `Ghost.io` `Shopify` `Tumblr` `Zendesk`
`ReadMe.io` `Surge.sh` `Bitbucket Pages` `Webflow` `Squarespace` `Pantheon`
`Unbounce` `HubSpot` `Fly.io` `Render` `Railway` `UserVoice` `Strikingly`
`WordPress.com` `Wix` `Tilda` `Cargo` `LaunchRock` `Desk.com`

**WAF Detection (12 products)**

`Cloudflare` `AWS WAF` `Akamai` `Fastly` `Sucuri` `Incapsula` `F5 BIG-IP`
`Barracuda` `ModSecurity` `Imperva` `Fortinet` `Radware`

**Tech Stack Detection (19 technologies)**

`WordPress` `Drupal` `Joomla` `Nginx` `Apache` `IIS` `Django` `Laravel`
`React` `Angular` `Vue` `Node.js` `PHP` `ASP.NET` `Ruby/Rails` `Varnish`
`Shopify` `AWS S3` `Spring`

---

## 🖥️ GUI Features

- **3-tab interface** - Takeover Findings / Live Hosts / Scan Log
- **Live stats bar** - Subdomains / Live Hosts / Vulnerable / Potential / Analyzed
- **Real-time search** - filter findings by any text as you type
- **Status filter** - All / Vulnerable / Potential radio buttons
- **Right-click menu** - Copy subdomain, CNAME, full finding; Open in browser
- **Click-to-detail** - full NS, MX, WAF, tech, ports, CORS, dirs on one click
- **Scan history** - double-click any past scan in the list to reload results
- **Open Folder** - open scan output directory with one click
- **Color-coded phases** - status indicator changes per scan phase
- **Scan timer** - elapsed time shown on completion
- **Summary popup** - stats when scan finishes
- **Export** - JSON / TXT / CSV / Subdomain list

---

## ⚙️ Installation

### Step 1 - Clone the repository
```bash
git clone https://github.com/VijayUba7417/subhacker.git
cd subhacker
```

### Step 2 - Install Python dependencies
```bash
pip3 install -r requirements.txt
```

### Step 3 - Run
```bash
python3 subhacker.py
```

---

## 🚀 Usage

1. Enter your **target domain** (e.g. `example.com`)
2. Toggle **scanning phases** on/off
3. Optionally enter **VirusTotal** / **Shodan** API keys for wider coverage
4. Set **Threads** and **Rate limit**
5. Press **▶ START SCAN** or `Ctrl+S`
6. Watch live output in the **Scan Log** tab
7. 🔴 **RED = VULNERABLE** → claimable, report immediately
8. 🟡 **YELLOW = POTENTIAL** → verify manually before reporting
9. Click any finding for full detail
10. **Export** results (JSON / TXT / CSV)

---

## 📂 Output Structure

Each scan creates a timestamped folder automatically:

```
subhacker_scans/
└── example_com_20250601_143022/
    ├── subdomains.txt    ← all discovered subdomains (deduplicated)
    ├── results.json      ← full structured report (auto-saved)
    └── results.txt       ← human-readable summary (auto-saved)
```

### JSON report format
```json
{
  "tool": "SubHacker",
  "version": "1.0",
  "domain": "example.com",
  "timestamp": "20250601_143022",
  "summary": {
    "subdomains": 312,
    "live_hosts": 74,
    "vulnerable": 2,
    "potential": 5,
    "findings": 7
  },
  "live_hosts": { ... },
  "findings": [ ... ]
}
```

---

## 📋 Requirements

```
Python      3.8+
dnspython   >= 2.4.0
requests    >= 2.31.0
urllib3     >= 2.0.0
tkinter     (included in Python standard library)
```

**Optional Go tools** :
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [amass](https://github.com/owasp-amass/amass)
- [findomain](https://github.com/Findomain/Findomain)

---

## 🔗 References

- [OWASP WSTG - Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- [HackTricks - Subdomain Takeover](https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover)

---

## ⚖️ License

[MIT License](LICENSE) - free to use, modify, and distribute.

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing and educational purposes only**.  
Unauthorized use against systems you do not own or have permission to test is **illegal**.  
The author accepts no responsibility for misuse.

---

<div align="center">

If SubHacker helped you find a vulnerability, please **star ⭐ the repo!**

</div>
