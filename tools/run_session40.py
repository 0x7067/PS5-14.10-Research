#!/usr/bin/env python3
"""Session driver for probe 40 (TCP connect-back fuzz), v2.

Problem solved here: when the PS5 connects to the PC's real IP, the
Windows TCP stack sees the SYN for a port it doesn't own and sends a RST,
killing the connection before scapy's crafted SYN-ACK can matter.

Fix (no admin needed): the PS5 connects to a FAKE IP on the LAN
(default 10.0.0.250). This script answers ARP for that IP with our MAC,
sniffs the PS5's TCP segments off the wire, and replies with crafted
packets sourced FROM the fake IP. The Windows stack ignores traffic for
an IP it doesn't own — no RST interference.

Usage:  python tools/run_session40.py [--ps5-ip 10.0.0.96] [--fake-ip 10.0.0.250]
"""

import os
import sys
import argparse
import socket
import struct
import threading
import time

os.environ.setdefault("ProgramFiles", r"C:\Program Files")
os.environ.setdefault("ProgramFiles(x86)", r"C:\Program Files (x86)")
os.environ.setdefault("ProgramW6432", r"C:\Program Files")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def local_ip(ps5_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ps5_ip, 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def patch_probe(target_ip):
    src = os.path.join(ROOT, "probes", "40_tcp_connectback.lua")
    with open(src, "r", encoding="utf-8") as f:
        text = f.read()
    o = target_ip.split(".")
    newline = f"local PC_IP = {{{o[0]}, {o[1]}, {o[2]}, {o[3]}}}"
    out = [newline if line.strip().startswith("local PC_IP") else line
           for line in text.splitlines()]
    tmp = os.path.join(ROOT, "probes", "_40_patched.lua")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    return tmp

class FakeHost:
    """ARP responder + raw TCP endpoint for a fake LAN IP."""
    def __init__(self, fake_ip, ps5_ip, port, log):
        from scapy.all import conf, get_if_hwaddr
        self.fake_ip = fake_ip
        self.ps5_ip = ps5_ip
        self.port = port
        self.log = log
        self.conf_iface = conf.iface
        self.mac = get_if_hwaddr(conf.iface)
        self.stop = threading.Event()
        self.state = {"seq": 1000, "ack": 0, "dport": 0, "established": False}

    def arp_responder(self):
        from scapy.all import sniff, sendp, Ether, ARP
        def handle(p):
            if self.stop.is_set():
                return True
            if ARP in p and p[ARP].op == 1 and p[ARP].pdst == self.fake_ip:
                reply = (Ether(dst=p[ARP].psrc and p[Ether].src or "ff:ff:ff:ff:ff:ff",
                               src=self.mac)
                         / ARP(op=2, hwsrc=self.mac, psrc=self.fake_ip,
                               hwdst=p[ARP].hwsrc, pdst=p[ARP].psrc))
                sendp(reply, iface=self.conf_iface, verbose=0)
                self.log(f"[pc] ARP reply: {self.fake_ip} is-at {self.mac}")
            return False
        try:
            sniff(filter="arp", prn=handle, store=False,
                  timeout=150, iface=self.conf_iface)
        except Exception as e:
            self.log(f"[!] ARP responder died: {e}")

    def tcp_session(self):
        from scapy.all import IP, TCP, Raw, sniff, send
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        from tcp_fuzz_server import build_data_variants

        filt = (f"tcp and host {self.ps5_ip} and dst host {self.fake_ip} "
                f"and tcp port {self.port}")
        self.log(f"[pc] waiting for SYN -> {self.fake_ip}:{self.port}")
        try:
            pkts = sniff(filter=filt + " and tcp[tcpflags] & tcp-syn != 0 "
                             "and tcp[tcpflags] & tcp-ack == 0",
                         count=1, timeout=140, iface=self.conf_iface)
        except Exception as e:
            self.log(f"[!] SYN sniff failed: {e}")
            return
        if not pkts:
            self.log("[pc] no SYN in 140s")
            return

        syn = pkts[0]
        st = self.state
        st["dport"] = syn[TCP].sport
        st["ack"] = syn[TCP].seq + 1
        self.log(f"[pc] SYN: ps5 port {st['dport']} seq {syn[TCP].seq:#x}")

        def seg(flags, seq=None, ack=None, **kw):
            return (IP(src=self.fake_ip, dst=self.ps5_ip)
                    / TCP(sport=self.port, dport=st["dport"], flags=flags,
                          seq=seq if seq is not None else st["seq"],
                          ack=ack if ack is not None else st["ack"], **kw))

        send(seg("SA", seq=st["seq"]))
        self.log("[pc] SYN-ACK sent")

        # wait for handshake ACK
        try:
            acks = sniff(filter=filt + " and tcp[tcpflags] & tcp-ack != 0",
                         count=1, timeout=20, iface=self.conf_iface)
        except Exception:
            acks = []
        if not acks:
            self.log("[pc] handshake ACK never arrived")
            return
        st["ack"] = acks[0][TCP].seq
        st["seq"] = 1001
        st["established"] = True
        self.log(f"[pc] ESTABLISHED (peer ack={st['ack']:#x}) — fuzz run begins")

        # NOTE: build_data_variants builds segments with sport/dport/seq/ack;
        # we wrap them with our fake src IP.
        variants = build_data_variants(self.port, st["dport"], st["seq"], st["ack"])
        for rnd in range(2):
            for i, (name, tcpseg) in enumerate(variants):
                if self.stop.is_set():
                    break
                self.log(f"[pc] r{rnd+1} v{i}: {name}")
                send(IP(src=self.fake_ip, dst=self.ps5_ip) / tcpseg)
                time.sleep(0.5)

        self.log("[pc] fuzz done; FIN")
        send(seg("FA"))
        st["seq"] += 1

def send_probe(path, ps5_ip, port, log):
    with open(path, "r", encoding="utf-8") as f:
        payload = f.read().encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    log(f"[ps5] connecting to loader {ps5_ip}:{port}")
    try:
        sock.connect((ps5_ip, port))
    except Exception as e:
        log(f"[ps5] loader connect failed: {e}")
        return b""
    sock.sendall(struct.pack("<Q", len(payload)) + payload)
    log(f"[ps5] probe sent ({len(payload)} bytes)")
    buf = b""
    end = time.time() + 170
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            for line in chunk.decode("utf-8", errors="replace").splitlines():
                log(f"[ps5] {line}")
        except socket.timeout:
            continue
    sock.close()
    return buf

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ps5-ip", default="10.0.0.96")
    ap.add_argument("--fake-ip", default="10.0.0.250")
    ap.add_argument("--port", type=int, default=31337)
    ap.add_argument("--loader-port", type=int, default=9026)
    args = ap.parse_args()

    print(f"[*] PC real IP: {local_ip(args.ps5_ip)}  fake host: {args.fake_ip}")

    lock = threading.Lock()
    def log(msg):
        with lock:
            print(msg, flush=True)

    try:
        host = FakeHost(args.fake_ip, args.ps5_ip, args.port, log)
    except Exception as e:
        print(f"[!] scapy/Npcap init failed: {e}")
        print("[!] Install Npcap (https://npcap.com) and retry.")
        return
    print(f"[*] iface MAC: {host.mac}")

    probe = patch_probe(args.fake_ip)
    print(f"[*] probe patched to target {args.fake_ip}")

    t_arp = threading.Thread(target=host.arp_responder, daemon=True)
    t_tcp = threading.Thread(target=host.tcp_session, daemon=True)
    t_arp.start()
    t_tcp.start()
    time.sleep(2)

    out = send_probe(probe, args.ps5_ip, args.loader_port, log)

    host.stop.set()
    t_tcp.join(timeout=10)
    t_arp.join(timeout=5)

    ts = time.strftime("%Y%m%d_%H%M%S")
    res = os.path.join(ROOT, "results", f"40_tcp_connectback_{ts}.txt")
    with open(res, "wb") as f:
        f.write(out)
    print(f"[*] saved: {res}")
    try:
        os.remove(probe)
    except OSError:
        pass
    print("[*] done — nothing left running")

if __name__ == "__main__":
    main()
