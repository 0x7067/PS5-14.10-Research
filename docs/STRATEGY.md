# Exploit Strategy Assessment — PS5 14.10

## Current Position

We have **userland code execution** via a Lua 5.1 loader on TCP port 9026. The goal is **kernel R/W** to enable hypervisor bypass (Byepervisor).

## Why This Is Hard

The PS5 14.10 sandbox eliminates the three most common FreeBSD kernel exploit strategies:

1. **No threading** → no race conditions (TOCTOU, UAF-via-race, refcount races)
2. **W^X + XOM** → no code injection, no gadget scanning from userland
3. **Minimal syscall surface** → sysctl, ioctl, dup, fstat, AIO all blocked

## Tier 1: RAW Socket Packet Injection (Most Promising)

**Status:** RAW socket + IP_HDRINCL confirmed working. Crafted UDP packets reach kernel `ip_input()`.

**Why:** Bypasses the syscall sandbox entirely. The kernel parses our crafted packet data in network stack context, not behind the syscall filter. The network input path is orders of magnitude larger than the syscall surface we can reach directly.

**Attack vectors within this path:**
- **IP fragment reassembly (`ip_reass()`)** — historically one of the most bug-prone areas in BSD kernels. Overlapping fragments, tiny fragments, fragment timeout interactions. *Status: testing blocked by bind() issue, needs retry.*
- **IP options parsing (`ip_dooptions()`)** — LSRR, SSRR, record-route, timestamp options hit complex allocation and copy code paths. These don't need fragment reassembly.
- **Protocol demux** — unusual protocol numbers, ICMP input processing
- **UDP input edge cases** — malformed UDP headers, zero-length payloads, broadcast addresses

**Next steps:**
1. Fix the bind() issue (try port 31338 which worked in probe 34, or investigate port restrictions)
2. Test IP options (LSRR/SSRR/record-route/timestamp) — no reassembly needed
3. Retry fragment reassembly with a working listener
4. Test ICMP injection

## Tier 2: TCP Connect-Back (Network-Side Attack)

**Status:** Not yet attempted.

**Why:** Connect the PS5 back to our machine via TCP, then send malformed TCP from the attacker side using scapy. The kernel's `tcp_input()` is enormous.

**Attack vectors:**
- TCP SACK processing (CVE-2019-11477 "SACK Panic" class)
- TCP urgent/OOB data state machine
- TCP option parsing loop (`tcp_dooptions()`)
- Malformed TCP window scaling
- TIME_WAIT state manipulation

**Requirement:** Scapy or raw socket on attacker machine to craft TCP packets.

## Tier 3: Unprobed Syscalls

**Status:** Never tested.

| Syscall | Why interesting |
|---------|----------------|
| `ktimer_create/settime` (235-238) | POSIX timers create kernel objects with complex lifecycle. Timer callbacks run in kernel context. |
| `accept4` (541) | TCP accept with flags — different sandbox path than accept? |
| `preadv/pwritev` (289-290) | Vectored I/O with offset — different kernel path than readv/writev |
| `copy_file_range` (580) | File-to-file copy in kernel — complex VFS interaction |
| `cap_rights_limit/get` (533+) | Capsicum capabilities may interact oddly with PS5 sandbox |
| `msync` (226) | Caused crash in probe 30 — never isolated |
| `minherit` (250) | Never tested |

## Tier 4: Long Shots

- **SCM_RIGHTS queue exhaustion** — rapid fd passing without receiving. Stresses fd table and mbuf allocation, but no threads = hard to create race.
- **SO_TIMESTAMP on TCP sockets** — might deliver cmsg with kernel timestamp addresses (untested on network sockets, only tested on UNIX where it gives nothing)
- **PS5 custom socket flags during active I/O** — toggling 0x2000/0x10000 mid-transfer might hit untested paths, but they're just boolean flags

## Dead Ends (Do Not Retry)

| Attack | Why dead |
|--------|----------|
| sigaltstack kernel write | copyout() validates, kills process |
| sigprocmask manipulation | Complete no-op |
| W^X bypass / mprotect EXEC | Always denied |
| Code page gadget scan | XOM — SIGBUS on read |
| Threading / race conditions | fork/rfork/thr_new all blocked |
| AIO exploitation | All AIO syscalls sandbox-killed |
| kqueue/kevent | kevent always -1 |
| ioctl/sysctl | Blocked |
| F_SETFL bypass | Cosmetic only — kernel ignores flags |
| F_SETOWN/SIGIO | Truly blocked |
| IPv6 extension header injection | sendmsg blocked for HBH/RTHDR/DSTOPTS |
| TCP_INFO pointer leak | No kernel pointers in 236-byte struct |
| PS5 custom socket options | Simple boolean toggles, no complex parsing |
| SNDBUF=1 overflow | Kernel handles correctly, partial writes clean |
