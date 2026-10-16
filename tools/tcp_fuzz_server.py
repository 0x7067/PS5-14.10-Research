#!/usr/bin/env python3
"""TCP malformed-response fuzz server for PS5 probe 40 (Tier 2).

The PS5 connects to this server; we complete the handshake and then send
crafted TCP segments whose headers/options are parsed by the PS5 kernel's
tcp_input()/tcp_dooptions() — outside its syscall sandbox.

Usage:
    pip install scapy
    python tcp_fuzz_server.py --ps5-ip 10.0.0.96 [--port 31337] [--variant N]

Requires Npcap (Windows) or root (Linux) for raw packet send/sniff.
Run the PS5 side with:  python send_probe.py probes/40_tcp_connectback.lua
(after editing PC_IP in the probe to this machine's LAN IP).

Variant list cycles automatically unless --variant pins one. The server
logs every variant sent — if the console hangs/reboots, the last logged
variant is your suspect.
"""

import argparse
import sys
import time

try:
    from scapy.all import IP, TCP, Raw, sniff, send, conf
except ImportError:
    print("[!] scapy not installed: pip install scapy")
    sys.exit(1)

LOG = []

def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    LOG.append(line)


def build_synack_variants(sport, dport, seq, ack):
    """Return list of (name, tcp_layer) SYN-ACK variants with hostile options."""
    return [
        ("normal",            TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack,
                                  options=[("MSS", 1460)])),
        ("wscale_14",         TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack,
                                  options=[("MSS", 1460), ("WScale", 14)])),
        ("wscale_255_badlen", TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack,
                                  options=[("MSS", 1460), (252, b"\xff" * 40)])),
        ("sack_perm_ts",      TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack,
                                  options=[("SAckOK", b""), ("Timestamp", (0xffffffff, 0))])),
        ("unknown_opt_255",   TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack,
                                  options=[(255, b"\x00" * 38)])),
        ("mss_1",             TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack,
                                  options=[("MSS", 1)])),
    ]


def build_data_variants(sport, dport, seq, ack):
    """Malformed in-connection segments."""
    base = dict(sport=sport, dport=dport, ack=ack)
    return [
        ("data_normal",      TCP(**base, flags="PA", seq=seq) / Raw(b"A" * 64)),
        ("urg_data",         TCP(**base, flags="PAU", seq=seq, urgptr=1) / Raw(b"B" * 64)),
        ("urg_ptr_max",      TCP(**base, flags="PAU", seq=seq, urgptr=0xFFFF) / Raw(b"C" * 64)),
        ("sack_impossible",  TCP(**base, flags="PA", seq=seq,
                                 options=[("SAck", (0xFFFFFFFF, 0x7FFFFFFF))]) / Raw(b"D" * 8)),
        ("seq_overlap",      TCP(**base, flags="PA", seq=seq - 32) / Raw(b"E" * 64)),
        ("seq_far_future",   TCP(**base, flags="PA", seq=seq + 0x100000) / Raw(b"F" * 64)),
        ("zero_window_then", TCP(**base, flags="A", seq=seq, window=0)),
        ("window_max",       TCP(**base, flags="PA", seq=seq, window=0xFFFF) / Raw(b"G" * 64)),
        ("syn_with_data",    TCP(**base, flags="SPA", seq=seq) / Raw(b"H" * 32)),
        ("fin_rst_combo",    TCP(**base, flags="FPRA", seq=seq) / Raw(b"I" * 16)),
        ("all_flags",        TCP(**base, flags="FSRPAUEC", seq=seq, urgptr=32) / Raw(b"J" * 16)),
        ("ts_bad_len",       TCP(**base, flags="PA", seq=seq,
                                 options=[("Timestamp", (1, 2)), (30, b"\xff" * 2)]) / Raw(b"K" * 8)),
        ("rst_with_data",    TCP(**base, flags="RA", seq=seq) / Raw(b"L" * 32)),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ps5-ip", required=True, help="PS5 LAN IP")
    ap.add_argument("--port", type=int, default=31337, help="listen port (default 31337)")
    ap.add_argument("--variant", type=int, default=-1,
                    help="pin a single data-variant index (default: cycle all)")
    ap.add_argument("--rounds", type=int, default=3, help="rounds through variant list")
    args = ap.parse_args()

    conf.verb = 0
    log(f"waiting for SYN from {args.ps5_ip} to port {args.port}")
    log("(start probe 40 on the PS5 now)")

    # Wait for the PS5's SYN
    syn = sniff(filter=f"tcp and host {args.ps5_ip} and tcp port {args.port} "
                       f"and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
                count=1, timeout=300)
    if not syn:
        log("no SYN received in 300s — exiting")
        return
    syn = syn[0]
    sport, dport = args.port, syn[TCP].sport
    ps5_seq = syn[TCP].seq
    log(f"SYN received: ps5 port {dport} seq {ps5_seq:#x}")

    # SYN-ACK variants: send 'normal' first so the connection establishes,
    # then the hostile ones only matter if the PS5 re-SYNs (keep it simple:
    # hostile SYN-ACK variants are for future use; log them as available).
    synack_vars = build_synack_variants(sport, dport, 1000, ps5_seq + 1)
    log(f"{len(synack_vars)} SYN-ACK variants prepared (sent: normal)")
    name, synack = synack_vars[0]
    send(IP(dst=args.ps5_ip) / synack)

    # Wait for ACK completing handshake
    ack_pkt = sniff(filter=f"tcp and host {args.ps5_ip} and tcp port {args.port} "
                           f"and tcp[tcpflags] & tcp-ack != 0",
                    count=1, timeout=30)
    if not ack_pkt:
        log("handshake ACK never arrived")
        return
    ack_pkt = ack_pkt[0]
    log("handshake complete — connection established")

    srv_seq = 1001
    cli_ack = ack_pkt[TCP].seq

    data_vars = build_data_variants(sport, dport, srv_seq, cli_ack)
    if args.variant >= 0:
        data_vars = [data_vars[args.variant % len(data_vars)]]

    for rnd in range(args.rounds):
        for i, (name, seg) in enumerate(data_vars):
            log(f"round {rnd + 1} variant {i}: {name}")
            send(IP(dst=args.ps5_ip) / seg)
            time.sleep(0.6)   # give the console time to choke if it will

    # Clean close
    log("sending FIN")
    send(IP(dst=args.ps5_ip) / TCP(sport=sport, dport=dport, flags="FA",
                                   seq=srv_seq + 1, ack=cli_ack))
    log("done. If the console died mid-run, the last logged variant is the suspect.")


if __name__ == "__main__":
    main()
