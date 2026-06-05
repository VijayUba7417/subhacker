#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#  SubHacker v1.0  —  Advanced Subdomain Takeover & Attack Surface Scanner
#  Author  : https://github.com/YOUR_USERNAME/subhacker
#  License : MIT
#  Usage   : python3 subhacker.py
# ─────────────────────────────────────────────────────────────────────────────

# ── stdlib imports ────────────────────────────────────────────────────────────
import os, sys, re, json, csv, time, socket, queue, threading, subprocess
import datetime, concurrent.futures, urllib.parse, webbrowser
from pathlib import Path
from tkinter import ttk, scrolledtext, messagebox, filedialog
import tkinter as tk

# ── third-party dependency check ──────────────────────────────────────────────
_MISSING = []
try:
    import dns.resolver, dns.exception, dns.query, dns.zone
except ImportError:
    _MISSING.append("dnspython")
try:
    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    _MISSING.append("requests")

if _MISSING:
    print(f"\n[!] Missing packages.  Run:  pip3 install {' '.join(_MISSING)}\n")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════
TOOL    = "SubHacker"
VERSION = "1.0"
SDIR    = Path("subhacker_scans")
SDIR.mkdir(exist_ok=True)

BANNER = r"""
  ____        _     _   _            _
 / ___| _   _| |__ | | | | __ _  ___| | _____ _ __
 \___ \| | | | '_ \| |_| |/ _` |/ __| |/ / _ \ '__|
  ___) | |_| | |_) |  _  | (_| | (__|   <  __/ |
 |____/ \__,_|_.__/|_| |_|\__,_|\___|_|\_\___|_|

           Advanced Subdomain Takeover Scanner
                      -- Vijay Uba
"""

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"

# ── Colour palette ────────────────────────────────────────────────────────────
C = {
    "bg":      "#050a14",
    "bg2":     "#0a1220",
    "bg3":     "#0e1a2c",
    "panel":   "#08131f",
    "border":  "#1e4a6e",
    "border2": "#0f2540",
    "accent":  "#00e5ff",
    "red":     "#ff1744",
    "green":   "#00ff7f",
    "warn":    "#ffb300",
    "purple":  "#d040ff",
    "text":    "#c5d9ea",
    "dim":     "#4a6f8f",
    "white":   "#ffffff",
}

PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 4443, 9443]

TLDS = [
    "com","net","org","in","co","io","info","biz","us","uk","de","fr","jp","cn",
    "br","au","ca","ru","es","it","nl","se","no","fi","dk","pl","at","ch","be",
    "mx","ar","za","sg","hk","nz","ie","pt","gr","hu","ro","tr","il","ae","sa",
    "qa","pk","bd","co.uk","co.in","co.jp","co.nz","co.za","com.au","com.br",
    "com.ar","com.mx","com.sg","com.hk","com.tw","com.tr","com.pk","org.uk",
    "me","app","dev","tech","cloud","site","online","store","shop","ai","pro",
    "xyz","club","space","tools","zone","network","systems","codes","works",
]

WORDLIST = [
    "www","mail","ftp","webmail","smtp","pop","pop3","imap","ns","ns1","ns2","ns3",
    "ns4","mx","mx1","mx2","cpanel","whm","webdisk","autodiscover","autoconfig",
    "test","dev","dev2","dev3","staging","stage","preprod","uat","qa","demo",
    "sandbox","beta","alpha","canary","rc","preview","lab","labs","admin",
    "administrator","manage","management","portal","dashboard","panel","control",
    "cp","backend","backoffice","staff","internal","intranet","secure","private",
    "restricted","corporate","app","app2","apps","web","web2","www2","www3","m",
    "mobile","wap","api","api2","api3","apiv1","apiv2","rest","graphql","gateway",
    "proxy","edge","lb","loadbalancer","waf","vpn","vpn2","remote","rdp","ssh",
    "bastion","cloud","k8s","kubernetes","docker","jenkins","ci","gitlab","git",
    "svn","monitor","monitoring","metrics","grafana","kibana","elastic","ops",
    "devops","infra","db","database","mysql","postgres","sql","backup","storage",
    "files","uploads","assets","static","cdn","media","images","img","video",
    "docs","download","data","blog","news","shop","store","checkout","cart",
    "payment","billing","account","support","helpdesk","help","status","auth",
    "login","sso","oauth","id","crm","analytics","stats","tracking","ads",
    "marketing","email","mail2","exchange","owa","calendar","meet","chat","forum",
    "old","new","legacy","archive","temp","2","3","4","us","eu","ap","uk","in",
    "prod","prod1","prod2","web1","web2","web3","us1","us2","eu1","eu2","ap1",
    "us-east","us-west","eu-west","eu-central","ap-south","vault","secrets",
    "security","soc","health","uptime","feedback","redirect","link","status2",
    "test2","staging2","vpn3","media2","cdn2","api4","v1","v2","v3","uat2",
    "preprod2","sandbox2","beta2","alpha2","demo2","dev4","stage2","qa2","rc2",
]

DIRS = [
    "admin","login","dashboard","api","v1","v2","v3","config","backup","test",
    ".git","wp-admin","wp-content","phpmyadmin","manager","console","panel",
    "upload","uploads","files","static","assets","media","images","js","css",
    "robots.txt","sitemap.xml",".env","web.config","server-status","info.php",
    "phpinfo.php","readme.md","README.md","CHANGELOG","LICENSE","composer.json",
    "package.json",".htaccess","crossdomain.xml","clientaccesspolicy.xml",
]

BUCKET_SUFFIXES = [
    ".s3.amazonaws.com",
    ".s3-website-us-east-1.amazonaws.com",
    ".s3-website-us-west-2.amazonaws.com",
    ".s3-website-eu-west-1.amazonaws.com",
    ".blob.core.windows.net",
    ".azurewebsites.net",
    ".storage.googleapis.com",
    ".appspot.com",
    ".digitaloceanspaces.com",
    ".r2.cloudflarestorage.com",
]

SEC_HEADERS = [
    "Strict-Transport-Security","Content-Security-Policy",
    "X-Frame-Options","X-Content-Type-Options",
    "Referrer-Policy","Permissions-Policy",
    "X-XSS-Protection","Cross-Origin-Opener-Policy",
]

# ── Takeover fingerprints ──────────────────────────────────────────────────────
FP = {
    "AWS S3":        {"pat":[r"\.s3\.amazonaws\.com$",r"\.s3-website.*\.amazonaws\.com$"],
                      "body":["NoSuchBucket","The specified bucket does not exist"],"codes":[403,404]},
    "AWS ELB":       {"pat":[r"\.elb\.amazonaws\.com$",r"\.[a-z]+-[a-z]+-[0-9]+\.elb\.amazonaws\.com$"],
                      "body":[],"codes":[],"nx":True},
    "AWS CloudFront":{"pat":[r"\.cloudfront\.net$"],"body":["Bad request"],"codes":[403]},
    "GitHub Pages":  {"pat":[r"\.github\.io$"],"body":["There isn't a GitHub Pages site here."],"codes":[404]},
    "Heroku":        {"pat":[r"\.herokuapp\.com$"],"body":["No such app"],"codes":[404]},
    "Netlify":       {"pat":[r"\.netlify\.app$",r"\.netlify\.com$"],"body":["Not Found - Request ID"],"codes":[404]},
    "Vercel":        {"pat":[r"\.vercel\.app$",r"\.now\.sh$"],"body":["DEPLOYMENT_NOT_FOUND","The deployment could not be found"],"codes":[404]},
    "Azure":         {"pat":[r"\.azurewebsites\.net$",r"\.cloudapp\.azure\.com$",r"\.trafficmanager\.net$",r"\.blob\.core\.windows\.net$"],"body":["404 Web Site not found"],"codes":[404]},
    "Fastly":        {"pat":[r"\.fastly\.net$"],"body":["Fastly error: unknown domain"],"codes":[404]},
    "Ghost":         {"pat":[r"\.ghost\.io$"],"body":["The thing you were looking for is no longer here"],"codes":[404]},
    "Shopify":       {"pat":[r"\.myshopify\.com$"],"body":["Sorry, this shop is currently unavailable"],"codes":[404]},
    "Tumblr":        {"pat":[r"\.tumblr\.com$"],"body":["There's nothing here."],"codes":[404]},
    "Zendesk":       {"pat":[r"\.zendesk\.com$"],"body":["Help Center Closed"],"codes":[404]},
    "ReadMe.io":     {"pat":[r"\.readme\.io$",r"\.readmessl\.com$"],"body":["Project doesnt exist"],"codes":[404]},
    "Surge.sh":      {"pat":[r"\.surge\.sh$"],"body":["project not found"],"codes":[404]},
    "Bitbucket":     {"pat":[r"\.bitbucket\.io$"],"body":["Repository not found"],"codes":[404]},
    "Webflow":       {"pat":[r"\.webflow\.io$"],"body":["The page you are looking for doesn't exist"],"codes":[404]},
    "Squarespace":   {"pat":[r"\.squarespace\.com$"],"body":["No Such Account"],"codes":[404]},
    "Pantheon":      {"pat":[r"\.pantheonsite\.io$"],"body":["The gods are wise"],"codes":[404]},
    "Unbounce":      {"pat":[r"\.unbounce\.com$"],"body":["The requested URL was not found"],"codes":[404]},
    "HubSpot":       {"pat":[r"\.hubspot\.net$",r"\.hs-sites\.com$"],"body":["Domain not found"],"codes":[404]},
    "Fly.io":        {"pat":[r"\.fly\.dev$"],"body":["404 Not Found"],"codes":[404]},
    "Render":        {"pat":[r"\.onrender\.com$"],"body":["not found"],"codes":[404]},
    "Railway":       {"pat":[r"\.railway\.app$"],"body":["not found"],"codes":[404]},
    "UserVoice":     {"pat":[r"\.uservoice\.com$"],"body":["This UserVoice subdomain is currently available"],"codes":[404]},
    "Strikingly":    {"pat":[r"\.strikingly\.com$"],"body":["page not found"],"codes":[404]},
    "WordPress.com": {"pat":[r"\.wordpress\.com$"],"body":["Do you want to register"],"codes":[404]},
    "Wix":           {"pat":[r"\.wixsite\.com$"],"body":["Error 404"],"codes":[404]},
    "Tilda":         {"pat":[r"\.tilda\.ws$"],"body":["Please renew your subscription"],"codes":[404]},
    "Cargo":         {"pat":[r"\.cargo\.site$",r"\.cargocollective\.com$"],"body":["404"],"codes":[404]},
    "LaunchRock":    {"pat":[r"\.launchrock\.com$"],"body":["It looks like you may have taken a wrong turn"],"codes":[404]},
    "Desk.com":      {"pat":[r"\.desk\.com$"],"body":["Sorry, We Couldn't Find That Page"],"codes":[404]},
}

WAF_SIG = {
    "Cloudflare":  ["cf-ray","cloudflare","__cfduid","cf-cache-status"],
    "AWS WAF":     ["x-amzn-requestid","awselb","x-amz-cf-id"],
    "Akamai":      ["akamai","x-check-cacheable","x-akamai-transformed"],
    "Fastly":      ["x-fastly","fastly-io-info","surrogate-key"],
    "Sucuri":      ["x-sucuri-id","sucuri"],
    "Incapsula":   ["incap_ses","visid_incap","x-iinfo"],
    "F5 BIG-IP":   ["bigipserver","f5-bigip"],
    "Barracuda":   ["barra_counter_session"],
    "ModSecurity": ["mod_security","modsecurity"],
    "Imperva":     ["x-iinfo","imperva"],
    "Fortinet":    ["fortigate","fortiwebcookie"],
    "Radware":     ["x-sl-compstate","rdwr"],
}

TECH_SIG = {
    "WordPress":  ["wp-content","wp-includes","wordpress"],
    "Drupal":     ["drupal","sites/default","x-drupal-cache"],
    "Joomla":     ["joomla","/components/com_"],
    "Nginx":      ["nginx"],
    "Apache":     ["apache"],
    "IIS":        ["iis","x-aspnet"],
    "Django":     ["django","csrfmiddlewaretoken"],
    "Laravel":    ["laravel"],
    "React":      ["react","__next","_next/static"],
    "Angular":    ["ng-version","angular"],
    "Vue":        ["__vue__","vue.min.js"],
    "Node.js":    ["x-powered-by: express","x-powered-by: node"],
    "PHP":        ["x-powered-by: php","phpsessid"],
    "ASP.NET":    ["x-powered-by: asp.net","x-aspnetmvc"],
    "Ruby/Rails": ["x-powered-by: phusion passenger"],
    "Varnish":    ["x-varnish","via: 1.1 varnish"],
    "Shopify":    ["shopify","myshopify"],
    "AWS S3":     ["x-amz-request-id","s3.amazonaws"],
    "Spring":     ["x-application-context"],
}

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def valid_sub(s):
    return bool(re.match(r'^[a-z0-9][a-z0-9._-]*\.[a-z]{2,}$', s))


def make_resolver():
    r = dns.resolver.Resolver()
    r.timeout = r.lifetime = 3
    r.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '8.8.4.4']
    return r


def fast_resolve(host):
    """Quick A-record probe for bruteforce — uses short timeout."""
    try:
        r = dns.resolver.Resolver()
        r.timeout = r.lifetime = 1
        r.nameservers = ['8.8.8.8', '1.1.1.1']
        r.resolve(host, "A")
        return True
    except Exception:
        return False


def http_get(url, timeout=8):
    try:
        return requests.get(
            url, timeout=timeout, verify=False, allow_redirects=True,
            headers={"User-Agent": UA,
                     "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                     "Accept-Language": "en-US,en;q=0.5"})
    except Exception:
        return None


def http_head(url, timeout=5):
    try:
        return requests.head(
            url, timeout=timeout, verify=False, allow_redirects=False,
            headers={"User-Agent": UA})
    except Exception:
        return None


def extract_title(html):
    m = re.search(r'<title[^>]*>([^<]{1,120})</title>', html, re.I)
    return m.group(1).strip() if m else ""


def detect_waf_tech(resp):
    if resp is None:
        return [], []
    combo = str(resp.headers).lower() + resp.text[:4000].lower()
    waf  = [w for w, sigs in WAF_SIG.items()  if any(s in combo for s in sigs)]
    tech = [t for t, sigs in TECH_SIG.items() if any(s in combo for s in sigs)]
    srv  = resp.headers.get("Server", "")
    if srv and f"Server:{srv}" not in tech:
        tech.append(f"Server:{srv}")
    return waf, tech


def fp_cname(cname):
    """Return (service_name, requires_nxdomain_check) or (None, False)."""
    if not cname:
        return None, False
    for svc, info in FP.items():
        for pat in info["pat"]:
            if re.search(pat, cname, re.I):
                return svc, info.get("nx", False)
    return None, False


# ══════════════════════════════════════════════════════════════════════════════
#  RATE LIMITER
# ══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, rps=15):
        self._delay = 1.0 / max(rps, 1)
        self._last  = 0.0
        self._lock  = threading.Lock()

    def wait(self):
        with self._lock:
            gap = self._delay - (time.time() - self._last)
            if gap > 0:
                time.sleep(gap)
            self._last = time.time()


# ══════════════════════════════════════════════════════════════════════════════
#  SCAN SESSION
# ══════════════════════════════════════════════════════════════════════════════

class ScanSession:
    def __init__(self, domain, opts, on_log, on_result, on_prog, on_done):
        self.domain = re.sub(r'^https?://', '', domain.strip().lower()).rstrip('/')
        self.opts   = opts
        self._log   = on_log
        self._res   = on_result
        self._prog  = on_prog
        self._done  = on_done

        self.subdomains = set()
        self.live_hosts = {}          # sub -> dict
        self.findings   = []
        self.stop       = threading.Event()
        self._lock      = threading.Lock()
        self._rl        = RateLimiter(opts.get("rate", 15))
        self._resolver  = make_resolver()

        self.ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.sdir = SDIR / f"{self.domain}_{self.ts}"
        self.sdir.mkdir(exist_ok=True)

    # ── low-level DNS ─────────────────────────────────────────────────────────
    def _dns(self, host, rtype="A"):
        try:
            return [str(x) for x in self._resolver.resolve(host, rtype)]
        except Exception:
            return []

    def _get_cname(self, host):
        try:
            return str(self._resolver.resolve(host, "CNAME")[0].target).rstrip(".")
        except dns.resolver.NXDOMAIN:
            return "NXDOMAIN"
        except Exception:
            return None

    def _is_nxdomain(self, host):
        try:
            self._resolver.resolve(host, "A")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return False

    def _wildcard(self):
        test = f"noexist{int(time.time())}.{self.domain}"
        ips  = self._dns(test)
        return bool(ips), ips

    # ── add finding ───────────────────────────────────────────────────────────
    def _add(self, entry):
        with self._lock:
            self.findings.append(entry)
        self._res(entry)

    def log(self, msg, tag="text"):
        self._log(msg, tag)

    # ══════════════════════════════════════════════════════════════════════════
    #  PHASE 1 — PASSIVE ENUMERATION (14 sources)
    # ══════════════════════════════════════════════════════════════════════════

    def _p_crtsh(self):
        self.log("[crt.sh] Certificate transparency...", "info")
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json",
                             timeout=25, verify=False)
            if r.status_code == 200:
                for e in r.json():
                    for n in e.get("name_value", "").split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if self.domain in n and valid_sub(n):
                            with self._lock:
                                self.subdomains.add(n)
        except Exception as e:
            self.log(f"  crt.sh error: {e}", "dim")

    def _p_wayback(self):
        self.log("[Wayback Machine] Historical URLs...", "info")
        try:
            url = (f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}"
                   f"&output=text&fl=original&collapse=urlkey&limit=100000")
            r = requests.get(url, timeout=35, verify=False)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    try:
                        h = urllib.parse.urlparse(line.strip()).netloc.lower().split(":")[0]
                        if h and self.domain in h and valid_sub(h):
                            with self._lock:
                                self.subdomains.add(h)
                    except Exception:
                        pass
        except Exception as e:
            self.log(f"  Wayback error: {e}", "dim")

    def _p_hackertarget(self):
        self.log("[HackerTarget] Passive DNS...", "info")
        try:
            r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                             timeout=15, verify=False)
            if r.status_code == 200 and "error" not in r.text[:50].lower():
                for line in r.text.splitlines():
                    p = line.strip().split(",")
                    if p and self.domain in p[0]:
                        s = p[0].lower()
                        if valid_sub(s):
                            with self._lock:
                                self.subdomains.add(s)
        except Exception as e:
            self.log(f"  HackerTarget error: {e}", "dim")

    def _p_alienvault(self):
        self.log("[AlienVault OTX] Threat intel DNS...", "info")
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
                timeout=15, verify=False, headers={"User-Agent": UA})
            if r.status_code == 200:
                for e in r.json().get("passive_dns", []):
                    h = e.get("hostname", "").lower()
                    if h and self.domain in h and valid_sub(h):
                        with self._lock:
                            self.subdomains.add(h)
        except Exception as e:
            self.log(f"  AlienVault error: {e}", "dim")

    def _p_rapiddns(self):
        self.log("[RapidDNS] DNS database...", "info")
        try:
            r = requests.get(f"https://rapiddns.io/subdomain/{self.domain}?full=1#result",
                             timeout=15, verify=False, headers={"User-Agent": UA})
            if r.status_code == 200:
                for m in re.findall(
                        r'<td>([a-zA-Z0-9._-]+\.' + re.escape(self.domain) + r')</td>',
                        r.text):
                    s = m.lower()
                    if valid_sub(s):
                        with self._lock:
                            self.subdomains.add(s)
        except Exception as e:
            self.log(f"  RapidDNS error: {e}", "dim")

    def _p_threatcrowd(self):
        self.log("[ThreatCrowd] Historical DNS...", "info")
        try:
            r = requests.get(
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}",
                timeout=15, verify=False)
            if r.status_code == 200:
                for s in r.json().get("subdomains", []):
                    s = s.strip().lower()
                    if s and self.domain in s and valid_sub(s):
                        with self._lock:
                            self.subdomains.add(s)
        except Exception as e:
            self.log(f"  ThreatCrowd error: {e}", "dim")

    def _p_bufferover(self):
        self.log("[BufferOver] DNS dataset...", "info")
        try:
            r = requests.get(f"https://dns.bufferover.run/dns?q=.{self.domain}",
                             timeout=15, verify=False)
            if r.status_code == 200:
                data = r.json()
                for entry in data.get("FDNS_A", []) + data.get("RDNS", []):
                    parts = entry.split(",")
                    if len(parts) >= 2:
                        h = parts[1].strip().lower().rstrip(".")
                        if h and self.domain in h and valid_sub(h):
                            with self._lock:
                                self.subdomains.add(h)
        except Exception as e:
            self.log(f"  BufferOver error: {e}", "dim")

    def _p_urlscan(self):
        self.log("[URLScan.io] Crawled domain data...", "info")
        try:
            r = requests.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000",
                timeout=20, verify=False, headers={"User-Agent": UA})
            if r.status_code == 200:
                for e in r.json().get("results", []):
                    h = e.get("task", {}).get("domain", "").lower()
                    if h and self.domain in h and valid_sub(h):
                        with self._lock:
                            self.subdomains.add(h)
        except Exception as e:
            self.log(f"  URLScan error: {e}", "dim")

    def _p_virustotal(self):
        key = self.opts.get("vt_key", "")
        if not key:
            self.log("[VirusTotal] No API key — skipped", "dim")
            return
        self.log("[VirusTotal] Passive DNS...", "info")
        try:
            r = requests.get(
                f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={key}&domain={self.domain}",
                timeout=15, verify=False)
            if r.status_code == 200:
                for s in r.json().get("subdomains", []):
                    s = s.strip().lower()
                    if s and valid_sub(s):
                        with self._lock:
                            self.subdomains.add(s)
        except Exception as e:
            self.log(f"  VirusTotal error: {e}", "dim")

    def _p_shodan(self):
        key = self.opts.get("shodan_key", "")
        if not key:
            self.log("[Shodan] No API key — skipped", "dim")
            return
        self.log("[Shodan] Host/subdomain lookup...", "info")
        try:
            r = requests.get(
                f"https://api.shodan.io/dns/domain/{self.domain}?key={key}",
                timeout=15, verify=False)
            if r.status_code == 200:
                for e in r.json().get("subdomains", []):
                    s = f"{e}.{self.domain}".lower()
                    if valid_sub(s):
                        with self._lock:
                            self.subdomains.add(s)
        except Exception as e:
            self.log(f"  Shodan error: {e}", "dim")

    def _p_subfinder(self):
        if not self.opts.get("use_subfinder", True):
            return
        if not self._bin("subfinder"):
            self.log("[subfinder] Not found. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "warn")
            return
        self.log("[subfinder] Running...", "info")
        out = self._run(f"subfinder -d {self.domain} -silent -all -t 100 -timeout 20", 120)
        for line in out.splitlines():
            line = line.strip().lower()
            if self.domain in line and valid_sub(line):
                with self._lock:
                    self.subdomains.add(line)

    def _p_assetfinder(self):
        if not self.opts.get("use_assetfinder", True):
            return
        if not self._bin("assetfinder"):
            self.log("[assetfinder] Not found. Install: go install github.com/tomnomnom/assetfinder@latest", "warn")
            return
        self.log("[assetfinder] Running...", "info")
        out = self._run(f"assetfinder --subs-only {self.domain}", 60)
        for line in out.splitlines():
            line = line.strip().lower()
            if self.domain in line and valid_sub(line):
                with self._lock:
                    self.subdomains.add(line)

    def _p_amass(self):
        if not self.opts.get("use_amass", True):
            return
        if not self._bin("amass"):
            self.log("[amass] Not found. Install: go install github.com/owasp-amass/amass/v4/...@master", "warn")
            return
        self.log("[amass] Running passive enum...", "info")
        out = self._run(f"amass enum -passive -d {self.domain} -timeout 3", 180)
        for line in out.splitlines():
            line = line.strip().lower()
            if self.domain in line and valid_sub(line):
                with self._lock:
                    self.subdomains.add(line)

    def _p_findomain(self):
        if not self.opts.get("use_findomain", True):
            return
        if not self._bin("findomain"):
            self.log("[findomain] Not found. See: https://github.com/Findomain/Findomain/releases", "warn")
            return
        self.log("[findomain] Running...", "info")
        out = self._run(f"findomain -t {self.domain} -q", 60)
        for line in out.splitlines():
            line = line.strip().lower()
            if self.domain in line and valid_sub(line):
                with self._lock:
                    self.subdomains.add(line)

    # ══════════════════════════════════════════════════════════════════════════
    #  PHASE 2 — ACTIVE SCANNING
    # ══════════════════════════════════════════════════════════════════════════

    def _a_dns_bf(self):
        if not self.opts.get("ph_dns_bf", True):
            return
        self.log(f"[DNS Brute-Force] {len(WORDLIST)} words × 120 threads...", "info")
        prev = len(self.subdomains)

        def probe(word):
            if self.stop.is_set():
                return
            s = f"{word}.{self.domain}"
            if fast_resolve(s):
                with self._lock:
                    self.subdomains.add(s)

        with concurrent.futures.ThreadPoolExecutor(max_workers=120) as ex:
            ex.map(probe, WORDLIST)
        self.log(f"  DNS BF done → +{len(self.subdomains)-prev} new", "dim")

    def _a_dns_perm(self):
        if not self.opts.get("ph_dns_perm", True):
            return
        self.log("[DNS Permutation] Building and resolving permutations...", "info")
        prev  = len(self.subdomains)
        envs  = ["dev","staging","prod","test","uat","qa","beta","old","new","v2","api","www"]
        perms = set()
        for s in list(self.subdomains)[:300]:
            base = s.replace(f".{self.domain}", "").split(".")[0]
            for e in envs:
                perms.add(f"{e}-{base}.{self.domain}")
                perms.add(f"{base}-{e}.{self.domain}")
                perms.add(f"{base}{e}.{self.domain}")
            for n in ["2", "3", "1", "01", "02"]:
                perms.add(f"{base}{n}.{self.domain}")
        todo = perms - self.subdomains

        def probe(p):
            if self.stop.is_set():
                return
            if fast_resolve(p):
                with self._lock:
                    self.subdomains.add(p)

        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
            ex.map(probe, todo)
        self.log(f"  DNS Permutation done → +{len(self.subdomains)-prev} new", "dim")

    def _a_tld_perm(self):
        if not self.opts.get("ph_tld", True):
            return
        base = self.domain.split(".")[0]
        self.log(f"[TLD Permutation] Probing {len(TLDS)} TLDs for '{base}'...", "info")
        prev = len(self.subdomains)

        def probe(tld):
            if self.stop.is_set():
                return
            v = f"{base}.{tld}"
            if v != self.domain and fast_resolve(v):
                with self._lock:
                    self.subdomains.add(v)
                self.log(f"  [tld] {v} is LIVE", "warn")

        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
            ex.map(probe, TLDS)
        self.log(f"  TLD Permutation done → +{len(self.subdomains)-prev} new", "dim")

    def _a_zone_transfer(self):
        if not self.opts.get("ph_zone_transfer", True):
            return
        self.log("[Zone Transfer] Attempting AXFR on all nameservers...", "info")
        ns_list = self._dns(self.domain, "NS")
        if not ns_list:
            self.log("  No NS records found", "dim")
            return
        for ns in ns_list:
            ns = ns.rstrip(".")
            self.log(f"  Trying AXFR → {ns} ...", "dim")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=5))
                for name in z.nodes:
                    sub = f"{name}.{self.domain}".lower().lstrip("@.")
                    if sub and self.domain in sub and valid_sub(sub):
                        with self._lock:
                            self.subdomains.add(sub)
                        self.log(f"  [AXFR-HIT] {sub}", "warn")
                self.log(f"  [!!!] ZONE TRANSFER SUCCESSFUL on {ns}", "vuln")
            except Exception as e:
                self.log(f"  {ns}: refused ({type(e).__name__})", "dim")

    def _a_reverse_ip(self):
        if not self.opts.get("ph_reverse_ip", True):
            return
        self.log("[Reverse IP] Looking up co-hosted domains...", "info")
        ips = self._dns(self.domain, "A")
        if not ips:
            self.log("  No A records found", "dim")
            return
        for ip in ips[:3]:
            self.log(f"  Querying HackerTarget for {ip}...", "dim")
            try:
                r = requests.get(
                    f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                    timeout=12, verify=False)
                if r.status_code == 200 and "error" not in r.text[:30].lower():
                    for line in r.text.splitlines():
                        host = line.strip().lower()
                        if host and valid_sub(host):
                            if self.domain in host:
                                with self._lock:
                                    self.subdomains.add(host)
                            self.log(f"  [rev-ip] {host} @ {ip}", "dim")
            except Exception as e:
                self.log(f"  Reverse IP error: {e}", "dim")

    def _a_vhost(self):
        if not self.opts.get("ph_vhost", True):
            return
        self.log("[VHost Fuzzing] Host header injection...", "info")
        ips = self._dns(self.domain) or self._dns(f"www.{self.domain}")
        if not ips:
            self.log("  No IP resolved — skipping VHost", "warn")
            return
        ip = ips[0]
        self.log(f"  Target IP: {ip}", "dim")
        try:
            base_r = requests.get(
                f"http://{ip}",
                headers={"Host": f"noexist{int(time.time())}.{self.domain}",
                         "User-Agent": UA},
                timeout=6, verify=False, allow_redirects=False)
            b_code = base_r.status_code
            b_len  = len(base_r.text)
        except Exception:
            self.log("  VHost baseline failed — skipping", "warn")
            return
        self.log(f"  Baseline: HTTP {b_code}, {b_len}b", "dim")
        prev = len(self.subdomains)

        def probe(word):
            if self.stop.is_set():
                return
            vhost = f"{word}.{self.domain}"
            try:
                r = requests.get(f"http://{ip}",
                    headers={"Host": vhost, "User-Agent": UA},
                    timeout=5, verify=False, allow_redirects=False)
                if r.status_code != b_code or abs(len(r.text) - b_len) > 200:
                    with self._lock:
                        self.subdomains.add(vhost)
                    self.log(f"  [vhost] {vhost}  HTTP {r.status_code}  {len(r.text)}b", "purple")
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            ex.map(probe, WORDLIST)
        self.log(f"  VHost Fuzzing done → +{len(self.subdomains)-prev} discovered", "dim")

    # ══════════════════════════════════════════════════════════════════════════
    #  PHASE 3 — HTTP PROBING
    # ══════════════════════════════════════════════════════════════════════════

    def _phase_http(self, subs):
        if not self.opts.get("ph_http", True):
            return {}
        self.log(f"[HTTP Probing] {len(subs)} subdomains...", "info")
        live = {}
        threads = self.opts.get("threads", 25)

        def probe(sub):
            if self.stop.is_set():
                return
            self._rl.wait()
            ips = self._dns(sub)
            if not ips:
                return
            for scheme in ["https", "http"]:
                resp = http_get(f"{scheme}://{sub}")
                if resp is not None:
                    waf, tech = detect_waf_tech(resp)
                    with self._lock:
                        live[sub] = {
                            "ip":     ips[0],
                            "scheme": scheme,
                            "code":   resp.status_code,
                            "title":  extract_title(resp.text)[:80],
                            "waf":    ", ".join(waf),
                            "tech":   ", ".join(tech[:4]),
                            "length": len(resp.text),
                        }
                    return

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            ex.map(probe, subs)
        self.log(f"  HTTP Probing done → {len(live)} live hosts", "dim")
        return live

    # ══════════════════════════════════════════════════════════════════════════
    #  PHASE 4 — EXTENDED SCANS
    # ══════════════════════════════════════════════════════════════════════════

    def _e_port_scan(self, live):
        if not self.opts.get("ph_port", True):
            return
        self.log(f"[Port Scan] {len(live)} hosts × {len(PORTS)} ports...", "info")

        def scan(item):
            sub, info = item
            if self.stop.is_set():
                return
            open_ports = []
            for port in PORTS:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    if s.connect_ex((info["ip"], port)) == 0:
                        open_ports.append(port)
                    s.close()
                except Exception:
                    pass
            if open_ports:
                with self._lock:
                    info["ports"] = open_ports
                self.log(f"  [port] {sub} ({info['ip']}) → {open_ports}", "dim")

        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
            ex.map(scan, list(live.items()))

    def _e_dir_discovery(self, live):
        if not self.opts.get("ph_dir", True):
            return
        targets = list(live.items())[:30]
        self.log(f"[Directory Discovery] {len(targets)} hosts...", "info")

        def probe(item):
            sub, info = item
            if self.stop.is_set():
                return
            scheme = info.get("scheme", "https")
            found  = []
            for path in DIRS:
                if self.stop.is_set():
                    break
                resp = http_head(f"{scheme}://{sub}/{path}", timeout=4)
                if resp and resp.status_code in [200, 201, 204, 301, 302, 401, 403]:
                    found.append(f"/{path} [{resp.status_code}]")
            if found:
                with self._lock:
                    info["dirs"] = found
                self.log(f"  [dir] {sub}: {' | '.join(found[:4])}", "dim")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            ex.map(probe, targets)

    def _e_cors(self, live):
        if not self.opts.get("ph_cors", True):
            return
        targets = list(live.items())[:50]
        self.log(f"[CORS Check] {len(targets)} hosts...", "info")

        def check(item):
            sub, info = item
            if self.stop.is_set():
                return
            scheme = info.get("scheme", "https")
            test_origins = [
                f"https://evil.{self.domain}",
                "https://attacker.com",
                f"https://{self.domain}.attacker.com",
                "null",
            ]
            for origin in test_origins:
                try:
                    resp = requests.get(f"{scheme}://{sub}/",
                        timeout=5, verify=False, allow_redirects=False,
                        headers={"Origin": origin, "User-Agent": UA})
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                    if acao and (acao == origin or acao == "*" or "attacker" in acao.lower()):
                        issue = f"CORS ACAO={acao} ACAC={acac}"
                        with self._lock:
                            info.setdefault("issues", [])
                            if issue not in info["issues"]:
                                info["issues"].append(issue)
                        self.log(f"  [cors] {sub} — {acao} (creds:{acac})", "warn")
                except Exception:
                    pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            ex.map(check, targets)

    def _e_sec_headers(self, live):
        if not self.opts.get("ph_sec_headers", True):
            return
        targets = list(live.items())[:50]
        self.log(f"[Security Headers] {len(targets)} hosts...", "info")

        def check(item):
            sub, info = item
            if self.stop.is_set():
                return
            scheme = info.get("scheme", "https")
            try:
                resp = requests.head(f"{scheme}://{sub}/",
                    timeout=5, verify=False, allow_redirects=True,
                    headers={"User-Agent": UA})
                missing = [h for h in SEC_HEADERS if h not in resp.headers]
                if missing:
                    with self._lock:
                        info["missing_headers"] = missing
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            ex.map(check, targets)

    def _e_ajax_spider(self, live):
        if not self.opts.get("ph_ajax", True):
            return
        targets = list(live.items())[:20]
        self.log(f"[AJAX Spider] Crawling {len(targets)} hosts for hidden subdomains...", "info")
        found = 0

        def crawl(item):
            sub, info = item
            if self.stop.is_set():
                return
            scheme = info.get("scheme", "https")
            resp   = http_get(f"{scheme}://{sub}")
            if resp is None:
                return
            links = re.findall(
                r'(?:href|src|action|data-url|data-src)=["\']([^"\']{4,200})["\']',
                resp.text, re.I)
            nonlocal found
            for link in links:
                try:
                    if not link.startswith("http"):
                        link = f"{scheme}://{sub}{link}"
                    h = urllib.parse.urlparse(link).netloc.lower().split(":")[0]
                    if h and self.domain in h and valid_sub(h) and h != sub:
                        with self._lock:
                            if h not in self.subdomains:
                                self.subdomains.add(h)
                                found += 1
                                self.log(f"  [spider] new host from JS: {h}", "dim")
                except Exception:
                    pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            ex.map(crawl, targets)
        self.log(f"  AJAX Spider done → +{found} new from JS/links", "dim")

    def _e_cloud_buckets(self):
        if not self.opts.get("ph_cloud", True):
            return
        self.log("[Cloud Buckets] Probing S3/Azure/GCS/DO/R2 permutations...", "info")
        base  = self.domain.replace(".", "")
        parts = self.domain.split(".")
        names = [
            base, parts[0],
            f"{parts[0]}-assets", f"{parts[0]}-static",
            f"{parts[0]}-media",  f"{parts[0]}-backup",
            f"{parts[0]}-files",  f"{parts[0]}-uploads",
            f"{parts[0]}-dev",    f"{parts[0]}-prod",
            f"{parts[0]}-staging",f"{parts[0]}-data",
            f"{base}-assets",     f"{base}-backup",
            f"{base}-static",     f"{base}-dev",
        ]
        found = 0

        def probe(args):
            name, suffix = args
            if self.stop.is_set():
                return
            url = f"https://{name}{suffix}"
            resp = http_head(url, timeout=5)
            if resp is None:
                return
            nonlocal found
            if resp.status_code in [200, 403, 301, 302]:
                found += 1
                self.log(f"  [bucket] {url}  HTTP {resp.status_code}", "warn")
                with self._lock:
                    self.subdomains.add(f"{name}{suffix}".lstrip("."))
            elif resp.status_code == 404 and "s3" in suffix:
                r2 = http_get(url, timeout=5)
                if r2 and "NoSuchBucket" in r2.text:
                    self.log(f"  [BUCKET TAKEOVER] {url} → NoSuchBucket!", "vuln")
                    found += 1

        combos = [(n, s) for n in names for s in BUCKET_SUFFIXES]
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            ex.map(probe, combos)
        self.log(f"  Cloud Buckets done → {found} found", "dim")

    # ══════════════════════════════════════════════════════════════════════════
    #  PHASE 5 — TAKEOVER ANALYSIS
    # ══════════════════════════════════════════════════════════════════════════

    def _analyse(self, sub, http_info):
        if self.stop.is_set():
            return
        self._rl.wait()

        cname = self._get_cname(sub)
        ns    = self._dns(sub, "NS")
        mx    = self._dns(sub, "MX")

        base = {
            "subdomain": sub,
            "cname":     cname or "",
            "ns":        ", ".join(ns[:2]),
            "mx":        ", ".join(mx[:2]),
            "ip":        (http_info or {}).get("ip", ""),
            "code":      str((http_info or {}).get("code", "")),
            "title":     (http_info or {}).get("title", ""),
            "waf":       (http_info or {}).get("waf", ""),
            "tech":      (http_info or {}).get("tech", ""),
            "ports":     str((http_info or {}).get("ports", "")),
            "cors":      str((http_info or {}).get("issues", "")),
            "dirs":      str((http_info or {}).get("dirs", "")),
            "timestamp": datetime.datetime.now().isoformat(),
        }

        # ── CNAME dangling ────────────────────────────────────────────────────
        if cname:
            is_nx       = (cname == "NXDOMAIN")
            service, nx = fp_cname("" if is_nx else cname)

            if is_nx or (service and nx and self._is_nxdomain(cname)):
                self.log(f"  [VULN] {sub} → CNAME:{cname} → NXDOMAIN", "vuln")
                self._add({**base, "service": service or "Unknown",
                           "status": "VULNERABLE",
                           "note": f"CNAME→NXDOMAIN ({cname}) — resource unclaimed"})
                return

            if service:
                confirmed = self._confirm(sub, service)
                status    = "VULNERABLE" if confirmed else "POTENTIAL"
                note      = (f"HTTP error fingerprint matched [{service}]" if confirmed
                             else f"CNAME points to {service} — verify manually")
                self.log(f"  [{status}] {sub} → [{service}]",
                         "vuln" if confirmed else "pot")
                self._add({**base, "service": service, "status": status, "note": note})
                return

        # ── NS takeover ───────────────────────────────────────────────────────
        if self.opts.get("check_ns", True) and ns:
            for n in ns:
                n = n.rstrip(".")
                if not self._dns(n):
                    self.log(f"  [NS-VULN] {sub} NS→{n}→NXDOMAIN", "vuln")
                    self._add({**base, "service": "NS Takeover",
                               "status": "VULNERABLE",
                               "note": f"NS {n} → NXDOMAIN — full zone control possible"})
                    return

        # ── MX takeover ───────────────────────────────────────────────────────
        if self.opts.get("check_mx", True) and mx:
            for m in mx:
                m = m.rstrip(".")
                if not self._dns(m):
                    self.log(f"  [MX-DANGLE] {sub} MX→{m}→NXDOMAIN", "pot")
                    self._add({**base, "service": "MX Takeover",
                               "status": "POTENTIAL",
                               "note": f"MX {m} → NXDOMAIN — email interception possible"})

    def _confirm(self, sub, service):
        fp    = FP.get(service, {})
        inds  = fp.get("body", [])
        codes = fp.get("codes", [])
        if not inds and not codes:
            return False
        for scheme in ["https", "http"]:
            resp = http_get(f"{scheme}://{sub}")
            if resp and resp.status_code in codes:
                if not inds or any(i.lower() in resp.text.lower() for i in inds):
                    return True
        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  MAIN RUN LOOP
    # ══════════════════════════════════════════════════════════════════════════

    def run(self):
        div = "═" * 64
        self.log(div, "dim")
        self.log(f"  {TOOL} v{VERSION}  —  Scan Started", "accent")
        self.log(f"  Target  : {self.domain}", "info")
        self.log(f"  Started : {self.ts}", "dim")
        self.log(div, "dim")

        # Wildcard DNS check
        self.log("\n[*] Wildcard DNS check...", "info")
        wc, wc_ips = self._wildcard()
        if wc:
            self.log(f"  [!] Wildcard DNS active ({wc_ips[0]}) — false positives possible!", "warn")
        else:
            self.log("  [✓] No wildcard DNS detected", "safe")

        # ── PHASE 1: PASSIVE ──────────────────────────────────────────────────
        self.log(f"\n{'─'*64}", "dim")
        self.log("  PHASE 1 — PASSIVE ENUMERATION", "accent")
        self.log(f"{'─'*64}", "dim")
        for fn in [self._p_crtsh, self._p_wayback, self._p_hackertarget,
                   self._p_alienvault, self._p_rapiddns, self._p_threatcrowd,
                   self._p_bufferover, self._p_urlscan,
                   self._p_virustotal, self._p_shodan,
                   self._p_subfinder, self._p_assetfinder,
                   self._p_amass, self._p_findomain]:
            if self.stop.is_set():
                break
            prev = len(self.subdomains)
            try:
                fn()
            except Exception as e:
                self.log(f"  Error in {fn.__name__}: {e}", "dim")
            gained = len(self.subdomains) - prev
            if gained:
                self.log(f"  → +{gained}  (total {len(self.subdomains)})", "safe")
            self._prog(len(self.subdomains), "passive")

        # ── PHASE 2: ACTIVE ───────────────────────────────────────────────────
        self.log(f"\n{'─'*64}", "dim")
        self.log("  PHASE 2 — ACTIVE SCANNING", "accent")
        self.log(f"{'─'*64}", "dim")
        for fn in [self._a_dns_bf, self._a_dns_perm, self._a_tld_perm,
                   self._a_zone_transfer, self._a_reverse_ip, self._a_vhost]:
            if self.stop.is_set():
                break
            prev = len(self.subdomains)
            try:
                fn()
            except Exception as e:
                self.log(f"  Error in {fn.__name__}: {e}", "dim")
            gained = len(self.subdomains) - prev
            if gained:
                self.log(f"  → +{gained}  (total {len(self.subdomains)})", "safe")
            self._prog(len(self.subdomains), "active")

        # Save subdomains.txt
        subs_sorted = sorted(self.subdomains)
        (self.sdir / "subdomains.txt").write_text("\n".join(subs_sorted))
        self.log(f"\n[✓] {len(self.subdomains)} unique subdomains saved → {self.sdir/'subdomains.txt'}", "safe")

        if not self.subdomains:
            self.log("[!] No subdomains found — check domain and installed tools.", "warn")
            self._done(self.findings, str(self.sdir))
            return

        # ── PHASE 3: HTTP PROBING ─────────────────────────────────────────────
        self.log(f"\n{'─'*64}", "dim")
        self.log(f"  PHASE 3 — HTTP PROBING  ({len(self.subdomains)} targets)", "accent")
        self.log(f"{'─'*64}", "dim")
        live = self._phase_http(subs_sorted)
        self.live_hosts.update(live)
        self._prog(len(live), "http")

        # ── PHASE 4: EXTENDED SCANS ───────────────────────────────────────────
        self.log(f"\n{'─'*64}", "dim")
        self.log("  PHASE 4 — EXTENDED SCANNING", "accent")
        self.log(f"{'─'*64}", "dim")
        try:
            self._e_port_scan(live)
        except Exception as e:
            self.log(f"  Port scan error: {e}", "dim")
        try:
            self._e_dir_discovery(live)
        except Exception as e:
            self.log(f"  Dir discovery error: {e}", "dim")
        try:
            self._e_cors(live)
        except Exception as e:
            self.log(f"  CORS check error: {e}", "dim")
        try:
            self._e_sec_headers(live)
        except Exception as e:
            self.log(f"  Security headers error: {e}", "dim")
        try:
            self._e_ajax_spider(live)
        except Exception as e:
            self.log(f"  AJAX spider error: {e}", "dim")
        try:
            self._e_cloud_buckets()
        except Exception as e:
            self.log(f"  Cloud buckets error: {e}", "dim")

        # If AJAX spider found new subs, probe them too
        new_subs = self.subdomains - set(subs_sorted)
        if new_subs:
            self.log(f"[+] {len(new_subs)} new subdomains from extended scans — probing...", "info")
            extra = self._phase_http(list(new_subs))
            live.update(extra)
            self.live_hosts.update(extra)

        # ── PHASE 5: TAKEOVER ANALYSIS ────────────────────────────────────────
        self.log(f"\n{'─'*64}", "dim")
        self.log(f"  PHASE 5 — TAKEOVER ANALYSIS  ({len(self.subdomains)} subdomains)", "accent")
        self.log(f"{'─'*64}", "dim")
        threads = self.opts.get("threads", 25)
        done_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            fts = {ex.submit(self._analyse, s, live.get(s)): s
                   for s in self.subdomains}
            for f in concurrent.futures.as_completed(fts):
                if self.stop.is_set():
                    break
                done_count += 1
                self._prog(done_count, "takeover")
                try:
                    f.result()
                except Exception:
                    pass

        # Save results
        self._save(live)

        # Summary
        vuln = [r for r in self.findings if r["status"] == "VULNERABLE"]
        pot  = [r for r in self.findings if r["status"] == "POTENTIAL"]
        self.log(f"\n{div}", "dim")
        self.log(f"  {TOOL} — SCAN COMPLETE", "accent")
        self.log(f"  Subdomains  : {len(self.subdomains)}", "info")
        self.log(f"  Live hosts  : {len(live)}", "info")
        self.log(f"  VULNERABLE  : {len(vuln)}", "vuln" if vuln else "dim")
        self.log(f"  POTENTIAL   : {len(pot)}", "warn" if pot else "dim")
        self.log(f"  Findings    : {len(self.findings)}", "info")
        self.log(f"  Output dir  : {self.sdir}", "dim")
        self.log(div, "dim")
        if vuln:
            self.log("\n  ─── VULNERABLE SUBDOMAINS ───", "vuln")
            for r in vuln:
                self.log(f"  !! {r['subdomain']}  →  {r['cname']}  [{r['service']}]", "vuln")
                self.log(f"     {r['note']}", "dim")

        self._done(self.findings, str(self.sdir))

    def _save(self, live):
        report = {
            "tool": TOOL, "version": VERSION,
            "domain": self.domain, "timestamp": self.ts,
            "summary": {
                "subdomains": len(self.subdomains),
                "live_hosts": len(live),
                "vulnerable": sum(1 for r in self.findings if r["status"] == "VULNERABLE"),
                "potential":  sum(1 for r in self.findings if r["status"] == "POTENTIAL"),
                "findings":   len(self.findings),
            },
            "live_hosts": live,
            "findings":   self.findings,
        }
        (self.sdir / "results.json").write_text(json.dumps(report, indent=2))
        lines = [f"{TOOL} v{VERSION}\nDomain: {self.domain}\n{'='*60}\n"]
        for r in self.findings:
            lines.append(f"[{r['status']}] {r['subdomain']}\n"
                         f"  CNAME  : {r['cname']}\n"
                         f"  Service: {r.get('service','')}\n"
                         f"  Note   : {r.get('note','')}\n"
                         f"  WAF    : {r.get('waf','')}  Tech: {r.get('tech','')}\n")
        (self.sdir / "results.txt").write_text("\n".join(lines))

    def _run(self, cmd, timeout=120):
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return (p.stdout + p.stderr).strip()
        except Exception:
            return ""

    def _bin(self, name):
        return subprocess.run(f"which {name}", shell=True, capture_output=True).returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
#  GUI APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class App:

    def __init__(self, root):
        self.root     = root
        self.root.title(f"{TOOL} v{VERSION}")
        self.root.configure(bg=C["bg"])
        self.root.geometry("1460x920")
        self.root.minsize(1200, 760)

        self.scanner   = None
        self._thread   = None
        self._q        = queue.Queue()
        self._results  = []
        self._scan_t0  = 0.0

        # keyboard shortcuts
        self.root.bind("<Control-s>", lambda e: self._start())
        self.root.bind("<Escape>",    lambda e: self._stop())
        self.root.bind("<Control-q>", lambda e: self.root.quit())

        self._style()
        self._build_ui()
        self._tick()

    # ── ttk styles ────────────────────────────────────────────────────────────
    def _style(self):
        s = ttk.Style()
        s.theme_use("clam")
        # treeview
        s.configure("H.Treeview",
                    background=C["bg2"], foreground=C["text"],
                    fieldbackground=C["bg2"], font=("Consolas", 10),
                    rowheight=26, borderwidth=0)
        s.configure("H.Treeview.Heading",
                    background=C["bg3"], foreground=C["accent"],
                    font=("Consolas", 10, "bold"), relief="flat")
        s.map("H.Treeview",
              background=[("selected", C["border"])],
              foreground=[("selected", C["accent"])])
        # progressbar — use standard style to avoid TclError
        s.configure("TProgressbar",
                    background=C["accent"], troughcolor=C["bg3"],
                    borderwidth=0, thickness=12)
        # checkbutton
        s.configure("D.TCheckbutton",
                    background=C["panel"], foreground=C["text"],
                    font=("Consolas", 10), selectcolor=C["bg3"],
                    activebackground=C["panel"], activeforeground=C["accent"])

    # ── widget factories ──────────────────────────────────────────────────────
    def _btn(self, parent, label, cmd, fg=None, small=False, width=None):
        fg   = fg or C["accent"]
        size = 10 if small else 11
        pad  = (8, 3) if small else (14, 6)
        b = tk.Button(parent, text=label, command=cmd,
                      font=("Consolas", size, "bold"),
                      bg=C["bg3"], fg=fg,
                      activebackground=C["border"], activeforeground=C["white"],
                      relief="flat", padx=pad[0], pady=pad[1],
                      cursor="hand2", bd=0,
                      highlightthickness=1,
                      highlightcolor=fg, highlightbackground=C["border2"])
        if width:
            b.config(width=width)
        b.bind("<Enter>", lambda e: b.config(bg=C["border"]))
        b.bind("<Leave>", lambda e: b.config(bg=C["bg3"]))
        return b

    def _section(self, parent, title):
        f = tk.Frame(parent, bg=C["panel"], bd=0,
                     highlightthickness=1, highlightbackground=C["border2"])
        tk.Frame(f, bg=C["accent"], height=2).pack(fill="x")
        tk.Label(f, text=f"  {title}", font=("Consolas", 10, "bold"),
                 bg=C["bg3"], fg=C["accent"], pady=4).pack(fill="x")
        return f

    def _stat_widget(self, parent, label, value, color):
        f = tk.Frame(parent, bg=C["bg2"], padx=18)
        f.pack(side="left", fill="y")
        lbl = tk.Label(f, text=value, font=("Consolas", 19, "bold"),
                       bg=C["bg2"], fg=color)
        lbl.pack(pady=(5, 0))
        tk.Label(f, text=label, font=("Consolas", 8),
                 bg=C["bg2"], fg=C["dim"]).pack()
        tk.Frame(parent, bg=C["border"], width=1).pack(side="left", fill="y")
        return lbl

    # ── full UI build ─────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── top bar ───────────────────────────────────────────────────────────
        top = tk.Frame(self.root, bg=C["bg2"], height=58)
        top.pack(fill="x")
        top.pack_propagate(False)
        tk.Label(top, text="⚡", font=("Segoe UI Emoji", 22),
                 bg=C["bg2"], fg=C["accent"]).pack(side="left", padx=(14, 4))
        tk.Label(top, text=TOOL, font=("Consolas", 18, "bold"),
                 bg=C["bg2"], fg=C["white"]).pack(side="left")
        tk.Label(top, text=f"  v{VERSION}  |  Advanced Subdomain Takeover & Attack Surface Scanner",
                 font=("Consolas", 10), bg=C["bg2"], fg=C["dim"]).pack(side="left")
        self._btn(top, "?", self._about, C["dim"], small=True).pack(side="right", padx=(0, 16))
        self.status_lbl = tk.Label(top, text="● READY", font=("Consolas", 12, "bold"),
                                   bg=C["bg2"], fg=C["green"])
        self.status_lbl.pack(side="right", padx=8)
        tk.Frame(self.root, bg=C["accent"], height=2).pack(fill="x")

        # ── body ──────────────────────────────────────────────────────────────
        body = tk.Frame(self.root, bg=C["bg"])
        body.pack(fill="both", expand=True)

        # left sidebar (fixed width, scrollable)
        side_outer = tk.Frame(body, bg=C["bg"], width=298)
        side_outer.pack(side="left", fill="y", padx=(8, 4), pady=8)
        side_outer.pack_propagate(False)
        self._build_sidebar(side_outer)

        # right content
        content = tk.Frame(body, bg=C["bg"])
        content.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)
        self._build_content(content)

        # ── footer ────────────────────────────────────────────────────────────
        footer = tk.Frame(self.root, bg=C["bg2"], height=26)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        tk.Label(footer,
                 text="  Ctrl+S = Start  |  Esc = Stop  |  Ctrl+Q = Quit  "
                      "|  Enter = Start  |  Ctrl+C = Copy  |  Right-Click = Menu",
                 font=("Consolas", 9), bg=C["bg2"], fg=C["dim"],
                 anchor="w").pack(fill="x", padx=8, pady=4)

    def _build_sidebar(self, parent):
        canvas = tk.Canvas(parent, bg=C["bg"], highlightthickness=0, bd=0)
        sb     = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner  = tk.Frame(canvas, bg=C["bg"])
        win    = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _resize(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(win, width=canvas.winfo_width())
        inner.bind("<Configure>", _resize)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))

        # ── Target ────────────────────────────────────────────────────────────
        s = self._section(inner, "TARGET DOMAIN")
        s.pack(fill="x", pady=(0, 6))
        tk.Label(s, text="  Domain  (e.g. example.com):", font=("Consolas", 10),
                 bg=C["panel"], fg=C["dim"]).pack(anchor="w", pady=(4, 2))
        self._domain_var = tk.StringVar(value="example.com")
        self._domain_ent = tk.Entry(s, textvariable=self._domain_var,
                                    font=("Consolas", 13), bg=C["bg"],
                                    fg=C["accent"], insertbackground=C["accent"],
                                    relief="flat", bd=4)
        self._domain_ent.pack(fill="x", padx=8, pady=(0, 6))
        self._domain_ent.bind("<FocusIn>", lambda e: (
            self._domain_ent.delete(0, "end")
            if self._domain_var.get() == "example.com" else None))
        self._domain_ent.bind("<Return>", lambda e: self._start())

        bf = tk.Frame(s, bg=C["panel"])
        bf.pack(fill="x", padx=8, pady=(0, 8))
        self._start_btn = self._btn(bf, "▶  START SCAN", self._start, C["green"])
        self._start_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self._stop_btn  = self._btn(bf, "■  STOP", self._stop, C["red"])
        self._stop_btn.pack(side="left")
        self._stop_btn.config(state="disabled")

        # ── Scanning Phases ───────────────────────────────────────────────────
        s2 = self._section(inner, "SCANNING PHASES")
        s2.pack(fill="x", pady=(0, 6))
        self._phase_vars = {}
        phases = [
            ("ph_dns_bf",       "DNS Brute-Force"),
            ("ph_http",         "HTTP Probing"),
            ("ph_port",         "Port Scan"),
            ("ph_dir",          "Directory Discovery"),
            ("ph_ajax",         "AJAX Spider"),
            ("ph_cloud",        "Cloud Buckets"),
            ("ph_cors",         "CORS Check"),
            ("ph_sec_headers",  "Security Headers"),
            ("ph_zone_transfer","Zone Transfer"),
            ("ph_dns_perm",     "DNS Permutation"),
            ("ph_tld",          "TLD Permutation"),
            ("ph_reverse_ip",   "Reverse IP"),
            ("ph_vhost",        "VHost Fuzzing"),
            ("check_ns",        "NS Record Check"),
            ("check_mx",        "MX Record Check"),
        ]
        grid = tk.Frame(s2, bg=C["panel"])
        grid.pack(fill="x", padx=6, pady=4)
        for i, (key, label) in enumerate(phases):
            var = tk.BooleanVar(value=(key != "ph_sec_headers"))
            self._phase_vars[key] = var
            ttk.Checkbutton(grid, text=label, variable=var,
                            style="D.TCheckbutton").grid(
                row=i // 2, column=i % 2, sticky="w", padx=4, pady=2)
        bf2 = tk.Frame(s2, bg=C["panel"])
        bf2.pack(fill="x", padx=8, pady=(2, 6))
        self._btn(bf2, "All On",  lambda: [v.set(True)  for v in self._phase_vars.values()],
                  C["dim"], small=True).pack(side="left", padx=(0, 4))
        self._btn(bf2, "All Off", lambda: [v.set(False) for v in self._phase_vars.values()],
                  C["dim"], small=True).pack(side="left")

        # ── Passive Sources ───────────────────────────────────────────────────
        s3 = self._section(inner, "PASSIVE SOURCES")
        s3.pack(fill="x", pady=(0, 6))
        tk.Label(s3, text="  HTTP API sources:", font=("Consolas", 10),
                 bg=C["panel"], fg=C["dim"]).pack(anchor="w", padx=8, pady=(4, 1))
        self._all_passive = tk.BooleanVar(value=True)
        ttk.Checkbutton(s3,
            text="crt.sh · Wayback · HackerTarget · OTX\n"
                 "RapidDNS · ThreatCrowd · BufferOver · URLScan",
            variable=self._all_passive,
            style="D.TCheckbutton").pack(anchor="w", padx=12, pady=(0, 4))
        tk.Label(s3, text="  Go tools:", font=("Consolas", 10),
                 bg=C["panel"], fg=C["dim"]).pack(anchor="w", padx=8)
        self._go_vars = {}
        for key, label in [("use_subfinder", "subfinder"),
                            ("use_assetfinder", "assetfinder"),
                            ("use_amass", "amass"),
                            ("use_findomain", "findomain")]:
            var = tk.BooleanVar(value=True)
            self._go_vars[key] = var
            ttk.Checkbutton(s3, text=label, variable=var,
                            style="D.TCheckbutton").pack(anchor="w", padx=14, pady=1)
        tk.Label(s3, text="  API Keys (optional):", font=("Consolas", 10),
                 bg=C["panel"], fg=C["dim"]).pack(anchor="w", padx=8, pady=(6, 1))
        self._vt_var     = tk.StringVar()
        self._shodan_var = tk.StringVar()
        for lbl, var in [("VirusTotal:", self._vt_var), ("Shodan:", self._shodan_var)]:
            tk.Label(s3, text=f"  {lbl}", font=("Consolas", 10),
                     bg=C["panel"], fg=C["dim"]).pack(anchor="w", padx=8)
            tk.Entry(s3, textvariable=var, font=("Consolas", 10), bg=C["bg"],
                     fg=C["accent"], insertbackground=C["accent"],
                     relief="flat", bd=3, show="*").pack(fill="x", padx=8, pady=(0, 3))
        tk.Frame(s3, bg=C["panel"], height=4).pack()

        # ── Performance ───────────────────────────────────────────────────────
        s4 = self._section(inner, "PERFORMANCE")
        s4.pack(fill="x", pady=(0, 6))
        self._thr_var  = tk.StringVar(value="25")
        self._rate_var = tk.StringVar(value="15")
        for label, var, lo, hi in [
            ("Threads:", self._thr_var, 5, 200),
            ("Rate (req/s):", self._rate_var, 1, 100),
        ]:
            row = tk.Frame(s4, bg=C["panel"])
            row.pack(fill="x", padx=8, pady=4)
            tk.Label(row, text=label, font=("Consolas", 10),
                     bg=C["panel"], fg=C["dim"]).pack(side="left")
            tk.Spinbox(row, from_=lo, to=hi, textvariable=var, width=6,
                       font=("Consolas", 11), bg=C["bg"], fg=C["accent"],
                       relief="flat", buttonbackground=C["bg3"],
                       bd=0).pack(side="right")
        tk.Frame(s4, bg=C["panel"], height=4).pack()

        # ── Export ────────────────────────────────────────────────────────────
        s5 = self._section(inner, "EXPORT")
        s5.pack(fill="x", pady=(0, 6))
        tk.Label(s5, text="  Export findings:", font=("Consolas", 10),
                 bg=C["panel"], fg=C["dim"]).pack(anchor="w", padx=8, pady=(4, 2))
        ef = tk.Frame(s5, bg=C["panel"])
        ef.pack(fill="x", padx=8, pady=(0, 4))
        for fmt in ["JSON", "TXT", "CSV"]:
            self._btn(ef, fmt, lambda f=fmt.lower(): self._export(f),
                      C["accent"], small=True).pack(side="left", padx=(0, 4))
        tk.Label(s5, text="  Export subdomains:", font=("Consolas", 10),
                 bg=C["panel"], fg=C["dim"]).pack(anchor="w", padx=8, pady=(4, 2))
        sf = tk.Frame(s5, bg=C["panel"])
        sf.pack(fill="x", padx=8, pady=(0, 6))
        self._btn(sf, "TXT List", self._export_subs, C["green"], small=True).pack(side="left")
        tk.Frame(s5, bg=C["panel"], height=4).pack()

        # ── Recent Scans ──────────────────────────────────────────────────────
        s6 = self._section(inner, "RECENT SCANS")
        s6.pack(fill="x", pady=(0, 6))
        self._scans_lb = tk.Listbox(s6, font=("Consolas", 10), bg=C["bg"],
                                    fg=C["dim"], selectbackground=C["border"],
                                    selectforeground=C["accent"],
                                    relief="flat", bd=0, height=7, activestyle="none")
        self._scans_lb.pack(fill="x", padx=8, pady=(4, 2))
        self._scans_lb.bind("<Double-Button-1>", self._load_scan)
        self._refresh_scans()
        rf = tk.Frame(s6, bg=C["panel"])
        rf.pack(fill="x", padx=8, pady=(0, 8))
        self._btn(rf, "⟳ Refresh",    self._refresh_scans, C["dim"], small=True).pack(side="left")
        self._btn(rf, "Open Folder",  self._open_folder,  C["dim"], small=True).pack(side="left", padx=(4, 0))

    def _build_content(self, parent):
        # ── stats bar ─────────────────────────────────────────────────────────
        stats = tk.Frame(parent, bg=C["bg2"], height=58)
        stats.pack(fill="x", pady=(0, 6))
        stats.pack_propagate(False)
        self._s_subs = self._stat_widget(stats, "SUBDOMAINS", "0", C["accent"])
        self._s_live = self._stat_widget(stats, "LIVE HOSTS",  "0", C["green"])
        self._s_vuln = self._stat_widget(stats, "VULNERABLE",  "0", C["red"])
        self._s_pot  = self._stat_widget(stats, "POTENTIAL",   "0", C["warn"])
        self._s_done = self._stat_widget(stats, "ANALYZED",    "0", C["purple"])
        self._prog_lbl = tk.Label(stats, text="", font=("Consolas", 10),
                                  bg=C["bg2"], fg=C["dim"])
        self._prog_lbl.pack(side="right", padx=8)
        self._pbar = ttk.Progressbar(stats, mode="indeterminate",
                                     style="TProgressbar", length=120)
        self._pbar.pack(side="right", padx=(0, 8), pady=14)

        # ── notebook ──────────────────────────────────────────────────────────
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)
        self._nb = nb

        t1 = tk.Frame(nb, bg=C["bg"])
        nb.add(t1, text="  🎯  Takeover Findings  ")
        self._build_findings(t1)

        t2 = tk.Frame(nb, bg=C["bg"])
        nb.add(t2, text="  🌐  Live Hosts  ")
        self._build_live(t2)

        t3 = tk.Frame(nb, bg=C["bg"])
        nb.add(t3, text="  📋  Scan Log  ")
        self._build_log(t3)

    def _build_findings(self, parent):
        hdr = tk.Frame(parent, bg=C["bg2"])
        hdr.pack(fill="x")
        tk.Label(hdr, text=" TAKEOVER FINDINGS", font=("Consolas", 11, "bold"),
                 bg=C["bg2"], fg=C["accent"], pady=5).pack(side="left")
        self._filt = tk.StringVar(value="ALL")
        for val, lbl, col in [("ALL", "All", C["text"]),
                               ("VULNERABLE", "Vuln", C["red"]),
                               ("POTENTIAL",  "Potential", C["warn"])]:
            tk.Radiobutton(hdr, text=lbl, variable=self._filt, value=val,
                           font=("Consolas", 10), bg=C["bg2"], fg=col,
                           selectcolor=C["bg3"], activebackground=C["bg2"],
                           command=self._filter).pack(side="left", padx=6)
        tk.Label(hdr, text=" Search:", font=("Consolas", 9),
                 bg=C["bg2"], fg=C["dim"]).pack(side="left", padx=(10, 2))
        self._search_var = tk.StringVar()
        self._search_var.trace("w", lambda *_: self._filter())
        tk.Entry(hdr, textvariable=self._search_var, font=("Consolas", 9),
                 bg=C["bg"], fg=C["accent"], insertbackground=C["accent"],
                 relief="flat", bd=2, width=20).pack(side="left", padx=2)
        self._btn(hdr, "Clear", self._clear_findings, C["dim"], small=True).pack(side="right", padx=8)

        tf = tk.Frame(parent, bg=C["bg"])
        tf.pack(fill="both", expand=True)
        cols   = ("subdomain", "cname", "service", "status", "waf", "tech", "ports", "note")
        widths = dict(subdomain=195, cname=160, service=110, status=90,
                      waf=100, tech=130, ports=80, note=285)
        heads  = dict(subdomain="Subdomain", cname="CNAME / Target", service="Service",
                      status="Status", waf="WAF", tech="Tech Stack", ports="Ports", note="Note")
        self._tree = ttk.Treeview(tf, columns=cols, show="headings", style="H.Treeview")
        for c in cols:
            self._tree.heading(c, text=heads[c])
            self._tree.column(c, width=widths[c], anchor="w")
        self._tree.tag_configure("VULNERABLE", foreground=C["red"])
        self._tree.tag_configure("POTENTIAL",  foreground=C["warn"])
        vsb = ttk.Scrollbar(tf, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<ButtonRelease-1>", self._on_row_click)
        self._tree.bind("<Double-Button-1>",  self._copy_row)
        self._tree.bind("<Control-c>",        self._copy_row)

        # right-click menu
        self._ctx = tk.Menu(self._tree, tearoff=0, bg=C["bg3"], fg=C["text"],
                            activebackground=C["border"], activeforeground=C["accent"])
        self._ctx.add_command(label="Copy Full Finding  (Ctrl+C)", command=self._copy_row)
        self._ctx.add_command(label="Copy Subdomain",               command=self._copy_sub)
        self._ctx.add_command(label="Copy CNAME Target",            command=self._copy_cname)
        self._ctx.add_separator()
        self._ctx.add_command(label="Open in Browser",              command=self._open_browser)
        self._tree.bind("<Button-3>", lambda e: self._ctx.tk_popup(e.x_root, e.y_root))

        self._detail = tk.Label(parent,
                                text="Click a finding to see full details",
                                font=("Consolas", 10), bg=C["bg3"], fg=C["dim"],
                                anchor="w", padx=12, pady=5)
        self._detail.pack(fill="x")

    def _build_live(self, parent):
        tf = tk.Frame(parent, bg=C["bg"])
        tf.pack(fill="both", expand=True)
        cols   = ("host", "ip", "code", "title", "waf", "tech", "ports", "cors", "dirs")
        widths = dict(host=195, ip=120, code=55, title=180,
                      waf=100, tech=130, ports=90, cors=50, dirs=200)
        heads  = dict(host="Host", ip="IP", code="HTTP", title="Title",
                      waf="WAF", tech="Tech", ports="Ports", cors="CORS", dirs="Notable Dirs")
        self._live_tree = ttk.Treeview(tf, columns=cols, show="headings", style="H.Treeview")
        for c in cols:
            self._live_tree.heading(c, text=heads[c])
            self._live_tree.column(c, width=widths[c], anchor="w")
        vsb = ttk.Scrollbar(tf, orient="vertical",   command=self._live_tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self._live_tree.xview)
        self._live_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._live_tree.pack(fill="both", expand=True)

    def _build_log(self, parent):
        hdr = tk.Frame(parent, bg=C["bg2"])
        hdr.pack(fill="x")
        tk.Label(hdr, text=" SCAN LOG", font=("Consolas", 11, "bold"),
                 bg=C["bg2"], fg=C["accent"], pady=5).pack(side="left")
        self._btn(hdr, "Save Log",  self._save_log,  C["dim"], small=True).pack(side="right", padx=4)
        self._btn(hdr, "Clear Log", self._clear_log, C["dim"], small=True).pack(side="right")

        self._log_box = scrolledtext.ScrolledText(
            parent, font=("Consolas", 10), bg=C["bg"], fg=C["text"],
            insertbackground=C["accent"], relief="flat", bd=0,
            wrap="none", state="disabled")
        self._log_box.pack(fill="both", expand=True)
        for tag, col in [("accent", C["accent"]), ("vuln", C["red"]),
                         ("pot",    C["warn"]),   ("safe", C["green"]),
                         ("info",   C["accent"]), ("warn", C["warn"]),
                         ("dim",    C["dim"]),    ("purple", C["purple"]),
                         ("text",   C["text"])]:
            self._log_box.tag_config(tag, foreground=col)

    # ── scan control ──────────────────────────────────────────────────────────
    def _start(self):
        domain = self._domain_var.get().strip()
        if not domain or domain == "example.com":
            messagebox.showwarning("Input Required", "Please enter a target domain.")
            return
        # reset UI
        self._clear_findings()
        self._clear_log()
        self._results.clear()
        for w in [self._s_subs, self._s_live, self._s_vuln, self._s_pot, self._s_done]:
            w.config(text="0")
        for row in self._live_tree.get_children():
            self._live_tree.delete(row)

        opts = {
            "threads":   int(self._thr_var.get()),
            "rate":      int(self._rate_var.get()),
            "vt_key":    self._vt_var.get(),
            "shodan_key":self._shodan_var.get(),
            **{k: v.get() for k, v in self._phase_vars.items()},
            **{k: v.get() for k, v in self._go_vars.items()},
            # map the "all passive" toggle to individual source flags
            "use_crtsh":       self._all_passive.get(),
            "use_wayback":     self._all_passive.get(),
            "use_hackertarget":self._all_passive.get(),
            "use_alienvault":  self._all_passive.get(),
            "use_rapiddns":    self._all_passive.get(),
            "use_threatcrowd": self._all_passive.get(),
            "use_bufferover":  self._all_passive.get(),
            "use_urlscan":     self._all_passive.get(),
        }
        self.scanner   = ScanSession(
            domain, opts,
            on_log    = lambda m, t="text": self._q.put(("log",    m, t)),
            on_result = lambda r:           self._q.put(("result", r)),
            on_prog   = lambda n, ph:       self._q.put(("prog",   n, ph)),
            on_done   = lambda rs, sd:      self._q.put(("done",  rs, sd)),
        )
        self._scan_t0 = time.time()
        self._start_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self.status_lbl.config(text="● SCANNING", fg=C["accent"])
        self._pbar.start(10)
        self._thread = threading.Thread(target=self.scanner.run, daemon=True)
        self._thread.start()

    def _stop(self):
        if self.scanner:
            self.scanner.stop.set()
        self._q.put(("log", "[!] Scan stopped by user.", "warn"))
        self._reset_ui()

    def _reset_ui(self):
        self._start_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._pbar.stop()

    # ── queue tick (runs every 80 ms in main thread) ──────────────────────────
    def _tick(self):
        PHASE_COLORS = {
            "passive":  C["accent"],
            "active":   C["warn"],
            "http":     C["green"],
            "takeover": C["purple"],
        }
        PHASE_LABELS = {
            "passive":  "Passive Enum",
            "active":   "Active Scan",
            "http":     "HTTP Probing",
            "takeover": "Takeover Analysis",
        }
        try:
            while True:
                item = self._q.get_nowait()
                kind = item[0]

                if kind == "log":
                    _, msg, tag = item
                    self._log_box.config(state="normal")
                    self._log_box.insert("end", msg + "\n", tag)
                    self._log_box.see("end")
                    self._log_box.config(state="disabled")

                elif kind == "result":
                    r = item[1]
                    self._results.append(r)
                    self._insert_row(r)
                    v = sum(1 for x in self._results if x["status"] == "VULNERABLE")
                    p = sum(1 for x in self._results if x["status"] == "POTENTIAL")
                    self._s_vuln.config(text=str(v))
                    self._s_pot.config(text=str(p))

                elif kind == "prog":
                    _, n, phase = item
                    if self.scanner:
                        self._s_subs.config(text=str(len(self.scanner.subdomains)))
                    self._s_done.config(text=str(n))
                    self._prog_lbl.config(text=f"{PHASE_LABELS.get(phase, phase)}: {n}")
                    self.status_lbl.config(
                        text=f"● {PHASE_LABELS.get(phase,'SCANNING').upper()}",
                        fg=PHASE_COLORS.get(phase, C["accent"]))

                elif kind == "done":
                    _, results, sdir = item
                    self._reset_ui()
                    elapsed    = time.time() - self._scan_t0
                    m, s       = divmod(int(elapsed), 60)
                    time_str   = f"{m}m {s}s" if m else f"{s}s"
                    self.status_lbl.config(text=f"● DONE ({time_str})", fg=C["green"])
                    self._refresh_scans()
                    # fill live-hosts tab
                    if self.scanner and self.scanner.live_hosts:
                        self._s_live.config(text=str(len(self.scanner.live_hosts)))
                        for sub, info in self.scanner.live_hosts.items():
                            cors = "YES" if info.get("issues") else ""
                            dirs = "; ".join(info.get("dirs", [])[:2]) if info.get("dirs") else ""
                            self._live_tree.insert("", "end", values=(
                                sub,
                                info.get("ip", ""),
                                info.get("code", ""),
                                info.get("title", "")[:60],
                                info.get("waf",   ""),
                                info.get("tech",  "")[:40],
                                str(info.get("ports", "")),
                                cors,
                                dirs[:60]))
                    # summary popup
                    v = sum(1 for r in results if r["status"] == "VULNERABLE")
                    p = sum(1 for r in results if r["status"] == "POTENTIAL")
                    if v or p:
                        messagebox.showinfo(
                            "Scan Complete",
                            f"{TOOL} — Scan Finished\n\n"
                            f"Time       : {time_str}\n"
                            f"Subdomains : {len(self.scanner.subdomains) if self.scanner else 0}\n"
                            f"Live hosts : {len(self.scanner.live_hosts) if self.scanner else 0}\n\n"
                            f"VULNERABLE : {v}\n"
                            f"POTENTIAL  : {p}\n\n"
                            f"Output → {sdir}")

        except queue.Empty:
            pass
        self.root.after(80, self._tick)

    # ── tree helpers ──────────────────────────────────────────────────────────
    def _insert_row(self, r):
        filt   = self._filt.get()
        search = self._search_var.get().lower()
        if filt != "ALL" and r["status"] != filt:
            return
        if search:
            hay = f"{r['subdomain']} {r.get('cname','')} {r.get('service','')} {r.get('note','')}".lower()
            if search not in hay:
                return
        self._tree.insert("", "end",
                          values=(r["subdomain"], r.get("cname", "")[:45],
                                  r.get("service", ""), r["status"],
                                  r.get("waf", ""), r.get("tech", "")[:30],
                                  r.get("ports", ""), r.get("note", "")[:80]),
                          tags=(r["status"],))

    def _filter(self):
        for row in self._tree.get_children():
            self._tree.delete(row)
        for r in self._results:
            self._insert_row(r)

    def _on_row_click(self, _event=None):
        sel = self._tree.selection()
        if not sel:
            return
        idx  = self._tree.index(sel[0])
        filt = self._filt.get()
        srch = self._search_var.get().lower()
        data = [r for r in self._results
                if (filt == "ALL" or r["status"] == filt)
                and (not srch or srch in (r["subdomain"] + r.get("cname","")).lower())]
        if idx < len(data):
            r   = data[idx]
            txt = (f"  Sub: {r['subdomain']}   CNAME: {r['cname']}   "
                   f"Service: {r.get('service','')}   Status: {r['status']}   "
                   f"WAF: {r.get('waf','—')}   Tech: {r.get('tech','—')}   "
                   f"NS: {r.get('ns','—')}   MX: {r.get('mx','—')}   "
                   f"Ports: {r.get('ports','—')}   Note: {r.get('note','')}")
            col = C["red"] if r["status"] == "VULNERABLE" else C["warn"]
            self._detail.config(text=txt, fg=col)

    def _selected_result(self):
        sel = self._tree.selection()
        if not sel:
            return None
        idx  = self._tree.index(sel[0])
        filt = self._filt.get()
        data = [r for r in self._results if filt == "ALL" or r["status"] == filt]
        return data[idx] if idx < len(data) else None

    def _copy_row(self, _event=None):
        r = self._selected_result()
        if r:
            txt = f"{r['subdomain']} → {r.get('cname','')} [{r.get('service','')}] — {r.get('note','')}"
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)
            self._q.put(("log", f"[✓] Copied: {r['subdomain']}", "safe"))

    def _copy_sub(self):
        r = self._selected_result()
        if r:
            self.root.clipboard_clear()
            self.root.clipboard_append(r["subdomain"])
            self._q.put(("log", f"[✓] Copied subdomain: {r['subdomain']}", "safe"))

    def _copy_cname(self):
        r = self._selected_result()
        if r and r.get("cname"):
            self.root.clipboard_clear()
            self.root.clipboard_append(r["cname"])
            self._q.put(("log", f"[✓] Copied CNAME: {r['cname']}", "safe"))

    def _open_browser(self):
        r = self._selected_result()
        if r:
            webbrowser.open(f"https://{r['subdomain']}")
            self._q.put(("log", f"[✓] Opened: https://{r['subdomain']}", "safe"))

    def _clear_findings(self):
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._detail.config(text="Click a finding to see full details", fg=C["dim"])

    # ── log helpers ───────────────────────────────────────────────────────────
    def _clear_log(self):
        self._log_box.config(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.config(state="disabled")

    def _save_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")],
            initialfile=f"subhacker_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if path:
            with open(path, "w") as f:
                f.write(self._log_box.get("1.0", "end"))
            messagebox.showinfo("Saved", f"Log saved:\n{path}")

    # ── export ────────────────────────────────────────────────────────────────
    def _export(self, fmt):
        if not self._results:
            messagebox.showinfo("No Results", "No findings to export yet.")
            return
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        dm = self._domain_var.get().replace(".", "_")
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[(fmt.upper(), f"*.{fmt}"), ("All", "*.*")],
            initialfile=f"subhacker_{dm}_{ts}.{fmt}")
        if not path:
            return
        if fmt == "json":
            with open(path, "w") as f:
                json.dump({"tool": TOOL, "version": VERSION,
                           "domain": self._domain_var.get(),
                           "timestamp": ts, "findings": self._results}, f, indent=2)
        elif fmt == "txt":
            with open(path, "w") as f:
                f.write(f"{TOOL} v{VERSION}\n{'='*60}\n\n")
                for r in self._results:
                    f.write(f"[{r['status']}] {r['subdomain']}  →  {r.get('cname','')}\n"
                            f"  Service: {r.get('service','')}   Note: {r.get('note','')}\n"
                            f"  WAF: {r.get('waf','')}   Tech: {r.get('tech','')}\n\n")
        elif fmt == "csv":
            fields = ["subdomain", "cname", "service", "status",
                      "waf", "tech", "ns", "mx", "ports", "cors", "dirs", "note", "timestamp"]
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                for r in self._results:
                    w.writerow({k: str(r.get(k, "")) for k in fields})
        messagebox.showinfo("Exported", f"Saved to:\n{path}")

    def _export_subs(self):
        if not self.scanner or not self.scanner.subdomains:
            messagebox.showinfo("No Data", "Run a scan first to collect subdomains.")
            return
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        dm = self._domain_var.get().replace(".", "_")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")],
            initialfile=f"subdomains_{dm}_{ts}.txt")
        if path:
            with open(path, "w") as f:
                f.write("\n".join(sorted(self.scanner.subdomains)))
            messagebox.showinfo("Exported",
                                f"{len(self.scanner.subdomains)} subdomains saved:\n{path}")

    # ── recent scans ──────────────────────────────────────────────────────────
    def _refresh_scans(self):
        self._scans_lb.delete(0, "end")
        try:
            dirs = sorted([d for d in SDIR.iterdir() if d.is_dir()], reverse=True)
            for d in dirs[:20]:
                self._scans_lb.insert("end", d.name)
        except Exception:
            pass

    def _load_scan(self, _event=None):
        sel = self._scans_lb.curselection()
        if not sel:
            return
        path = SDIR / self._scans_lb.get(sel[0]) / "results.json"
        if not path.exists():
            messagebox.showinfo("Not Found", "No results.json in this scan folder.")
            return
        with open(path) as f:
            data = json.load(f)
        results = data.get("findings", [])
        self._clear_findings()
        self._results = results
        for r in results:
            self._insert_row(r)
        v = sum(1 for r in results if r["status"] == "VULNERABLE")
        p = sum(1 for r in results if r["status"] == "POTENTIAL")
        self._s_vuln.config(text=str(v))
        self._s_pot.config(text=str(p))
        self._s_subs.config(text=str(len(results)))
        self._s_done.config(text=str(len(results)))
        self._q.put(("log", f"[✓] Loaded scan: {path.parent.name} ({len(results)} findings)", "safe"))

    def _open_folder(self):
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(SDIR))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(SDIR)])
            else:
                subprocess.Popen(["xdg-open", str(SDIR)])
        except Exception:
            messagebox.showinfo("Scan Folder", str(SDIR))

    # ── about ─────────────────────────────────────────────────────────────────
    def _about(self):
        w = tk.Toplevel(self.root)
        w.title(f"About {TOOL}")
        w.configure(bg=C["bg2"])
        w.geometry("520x520")
        w.resizable(False, False)
        w.update_idletasks()
        x = (w.winfo_screenwidth()  - 520) // 2
        y = (w.winfo_screenheight() - 520) // 2
        w.geometry(f"+{x}+{y}")
        text = (
            f"\n  ⚡ {TOOL} v{VERSION}\n\n"
            "  Advanced Subdomain Takeover\n"
            "  & Attack Surface Scanner\n\n"
            "  5-Phase Scan Engine:\n"
            "   Phase 1 — Passive Enumeration (14 sources)\n"
            "   Phase 2 — Active Scanning\n"
            "   Phase 3 — HTTP Probing\n"
            "   Phase 4 — Extended Scans\n"
            "   Phase 5 — Takeover Analysis\n\n"
            "  17 scanning phases\n"
            "  30+ service fingerprints\n"
            "  WAF & tech stack detection\n"
            "  CORS, Security Headers, Cloud Buckets\n"
            "  Zone Transfer, DNS Permutation\n\n"
            "  github.com/YOUR_USERNAME/subhacker\n\n"
            "  For authorized testing only.\n"
        )
        tk.Label(w, text=text, font=("Consolas", 10),
                 bg=C["bg2"], fg=C["text"], justify="left",
                 padx=20, pady=10).pack(fill="both", expand=True)
        self._btn(w, "Close", w.destroy, C["accent"]).pack(pady=(0, 20))


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    # Print banner
    print(BANNER)
    print(f"  {TOOL} v{VERSION}  |  Subdomain Takeover & Attack Surface Scanner")
    print(f"  github.com/YOUR_USERNAME/subhacker\n")

    # WSL2 display check
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        print("\n[!] No DISPLAY variable set.")
        print("    For WSL2, run:")
        print("    export DISPLAY=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}'):0")
        print("\n    Or run on native Linux / Kali desktop — no setup needed.\n")
        sys.exit(1)

    root = tk.Tk()
    app  = App(root)

    # Center window
    root.update_idletasks()
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    ww, wh = 1460, 920
    root.geometry(f"{ww}x{wh}+{(sw-ww)//2}+{(sh-wh)//2}")
    root.mainloop()


if __name__ == "__main__":
    main()
