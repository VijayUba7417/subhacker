# Changelog — SubHacker

---

## [v1.0] — 2025

### Initial Release

**Core Engine**
- 5-phase scanning architecture (Passive → Active → HTTP → Extended → Takeover)
- Thread-safe with configurable worker count (default 25)
- Rate limiter (default 15 req/s) to avoid triggering WAF / rate limits
- Per-scan timestamped output directory with auto-save

**Phase 1 — Passive Enumeration (14 sources)**
- crt.sh (certificate transparency)
- Wayback Machine (historical URLs)
- HackerTarget (passive DNS)
- AlienVault OTX (threat intel)
- RapidDNS (DNS database)
- ThreatCrowd (historical DNS)
- BufferOver (DNS dataset)
- URLScan.io (crawled domain data)
- VirusTotal (passive DNS — API key)
- Shodan (host discovery — API key)
- subfinder (Go tool)
- assetfinder (Go tool)
- amass (Go tool)
- findomain (Go tool)

**Phase 2 — Active Scanning**
- DNS Brute-Force (~260 words, 120 threads)
- DNS Permutation (env-prefix + number variants)
- TLD Permutation (80+ TLDs)
- Zone Transfer (AXFR on all NS records)
- Reverse IP (HackerTarget API)
- VHost Fuzzing (Host-header injection)

**Phase 3 — HTTP Probing**
- Live host detection (HTTPS preferred, HTTP fallback)
- Status code + title extraction
- WAF detection (12 products: Cloudflare, AWS WAF, Akamai, Fastly, etc.)
- Tech stack detection (19 technologies: Nginx, Apache, WordPress, React, etc.)

**Phase 4 — Extended Scanning**
- Port Scan (10 common ports per live host)
- Directory Discovery (35 sensitive paths)
- CORS Check (4 origin injection variants)
- Security Headers Audit (8 headers checked)
- AJAX Spider (extract subdomains from JS/HTML)
- Cloud Buckets (S3/Azure/GCS/DO/R2 permutations + NoSuchBucket detection)

**Phase 5 — Takeover Analysis**
- CNAME dangling → NXDOMAIN detection
- 30+ service fingerprints with HTTP body confirmation
- NS record takeover (full zone control)
- MX record takeover (email interception)

**GUI**
- Dark professional hacker theme
- 3-tab interface: Takeover Findings / Live Hosts / Scan Log
- Live stats bar (Subdomains / Live Hosts / Vulnerable / Potential / Analyzed)
- Real-time search + status filter in findings tab
- Right-click context menu (copy subdomain, CNAME, open in browser)
- Keyboard shortcuts (Ctrl+S, Esc, Ctrl+Q, Enter, Ctrl+C)
- Per-phase toggle checkboxes
- Scan history — double-click to reload past scans
- Export: JSON / TXT / CSV / Subdomains TXT
- Scan timer + summary popup on completion
- Color-coded phase status indicator
- About dialog
