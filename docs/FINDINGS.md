# Detailed Technical Findings — PS5 14.10

## Finding 1: W^X + Execute-Only Memory (XOM)

**Probes:** 26, 26b, 26c, 26d, 26e

The PS5 enforces write-XOR-execute strictly:
- `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)` → grants `RW` only (EXEC stripped)
- `mprotect(PROT_EXEC)` → always fails with -1
- Code pages are **execute-only**: attempting to read from the code segment causes SIGBUS
- The crash handler at address `0x533118f4` handles SIGILL/SIGBUS/SIGSEGV; output starts with `77` followed by binary data

**Impact:** No ROP/JOP gadget scanning from userland. No code injection. Must find kernel R/W through data-only paths.

---

## Finding 2: Threading Completely Blocked

**Probe:** 27

All threading primitives return -1:
- `fork()` — blocked
- `rfork()` — blocked  
- `thr_new()` — blocked

**Impact:** No race conditions possible. Eliminates TOCTOU, UAF-via-race, refcount race classes entirely.

---

## Finding 3: sigaltstack Kernel Write is Dead

**Probes:** 22, 23, 24, 25, 25b

The classic sigaltstack trick (set altstack to kernel address → signal delivery writes sigframe there) fails because:
- `copyout()` validates the destination address during signal frame delivery
- Writing to a kernel address triggers EFAULT
- The kernel then kills the process

`sigprocmask` is also a no-op — returns 0 but the signal mask is never modified.

---

## Finding 4: F_SETFL is Cosmetic Only

**Probes:** 30b, 30c, 33a–33c

`fcntl(F_SETFL, O_NONBLOCK)` returns -1 but **updates the visible flags word** (F_GETFL shows the change). However the kernel **does not honor the flags**:
- O_NONBLOCK has no effect on actual read/write behavior
- O_APPEND flag also set but not honored  
- O_ASYNC flag also set but not honored
- Each F_SETFL call REPLACES the flags word (not bitwise OR)

The sandbox intercepts F_SETFL, rejects it (returns -1), but patches the userland-visible flags struct field. The actual kernel I/O path checks a separate internal socket state.

`F_SETOWN` is truly blocked — returns -1 AND the value is not applied (F_GETOWN stays -1). No SIGIO possible.

---

## Finding 5: MSG_DONTWAIT is the Real Nonblocking Mechanism

**Probes:** 33d, 33e, 33f

Since F_SETFL O_NONBLOCK is fake, nonblocking I/O must use per-call flags:
- `sendmsg(fd, msg, MSG_DONTWAIT)` with `MSG_DONTWAIT = 0x80`
- `recvmsg(fd, msg, MSG_DONTWAIT)` with `MSG_DONTWAIT = 0x80`

Confirmed behavior:
- `recv(empty socket)` → returns -1 immediately (EAGAIN)
- `send(full buffer)` → returns -1 immediately (EAGAIN)
- SNDBUF=1 partial writes work correctly (request 4 bytes → rv=1)
- 100x rapid send/recv cycling: 100/100 success
- Both buffers=1, 50x cycling: 50/50 success

**CRITICAL:** `sendto` (syscall 133) and `recvfrom` (syscall 29) **crash the Lua loader** when registered in `syscall.resolve()`. Use only `sendmsg`/`recvmsg`.

---

## Finding 6: SCM_RIGHTS fd Passing Works Correctly

**Probes:** 28, 30b

Unix domain socket credential passing via SCM_RIGHTS is fully functional:
- Can pass 16+ file descriptors in a single message
- 5x send/recv cycle: all 5 correct (refcounts accurate)
- No refcount leak or double-free observed
- Passed fds are usable (can read/write/close)

---

## Finding 7: RAW Socket + IP_HDRINCL = Kernel Packet Injection

**Probe:** 34

This is the **most significant finding** for exploit development:
- `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` succeeds → fd allocated
- `setsockopt(IP_HDRINCL)` → rv=0 (reads back as 8 = INP_HDRINCL)
- `sendmsg()` with crafted IP+UDP packet to 127.0.0.1 → **packet reaches UDP listener**
- Confirmed: `BEEFCAFE` payload data arrived intact
- RAW socket `bind()` and `connect()` to loopback both work

TCP SYN packet was dropped — likely due to invalid TCP checksum (sent 0). TCP requires valid checksums even on loopback.

**Impact:** We can inject arbitrary IP packets into the kernel's `ip_input()` path. This opens:
- IP fragment reassembly (`ip_reass()`)
- IP options parsing (`ip_dooptions()`)
- Protocol demultiplexing
- ICMP input processing
- Any protocol handler reachable via loopback

---

## Finding 8: Fragment Reassembly — Inconclusive (Bind Issue)

**Probes:** 35, 35b

All fragment reassembly tests returned no data. However, probe 35b revealed the root cause: **`bind()` was returning -1** for the UDP listener port. Without a valid listener, no packets can be received regardless of reassembly.

The bind failure may be due to:
- Port range restrictions on the PS5
- Socket/fd limit reached
- Specific port number filtering

**Status:** Needs re-testing with verified bind success before concluding anything about fragment reassembly.

---

## Finding 9: PS5 Custom Socket Options are Benign

**Probe:** 31c

Five Sony-extended SOL_SOCKET options exist:
```
0x2000, 0x10000, 0x20000, 0x40000, 0x100000
```

All are **boolean flag bits** in the socket's `so_options` field. The option number IS the bitmask value:
- `setsockopt(SO_0x2000, 1)` → readback = 0x2000
- Same behavior on all socket types (UNIX, TCP, RAW, IPv6 RAW)
- No complex parsing, no buffer handling, no kernel pointer exposure

**Not exploitable.**

---

## Finding 10: poll() is Fully Functional

**Probe:** 32c

`poll()` works with correct BSD semantics:
- `nfds=0` → rv=0 (immediate return)
- Invalid fd → POLLNVAL (0x0020)
- `fd=-1` → ignored (standard behavior)
- Closed peer → POLLIN|POLLHUP (0x0051)
- `read(closed peer)` → rv=0 (EOF)
- Mixed fd array → correct per-fd results

---

## Finding 11: TCP_INFO Contains No Kernel Pointers

**Probe:** 31b

The 236-byte TCP_INFO structure was fully dumped and scanned:
- Contains only protocol metadata: timestamps, RTT values, window sizes, congestion state
- Connected vs unconnected socket comparison shows expected field changes
- **No kernel addresses leaked** — all pointer-sized values are protocol counters or timestamps

---

## Finding 12: Memory Layout

**Probe:** 03

Key addresses observed:
- Signal handler (crash): `0x533118f4`
- Code segment is execute-only (cannot read)
- Heap is RW, stack is RW
- `MAP_FIXED` works for page-aligned addresses in userland range

---

## Finding 13: AIO is Completely Sandbox-Killed

**Probes:** 19, 19b, 19c, 19d, 19e, 19f, 19g

Every AIO syscall tested:
- `aio_read` — killed
- `aio_write` — killed
- `aio_return` — killed
- `aio_suspend` — killed
- `aio_cancel` — killed
- `aio_error` — returns but useless without the others

Seven progressively minimal probes confirmed this is a hard sandbox restriction, not a usage error.

---

## Finding 14: kqueue Allocates but kevent is Dead

**Probes:** 20, 21

- `kqueue()` → returns a valid fd
- `kevent()` → always returns -1 regardless of changelist content
- The fd is usable for close() but nothing else

---

## Finding 15: writev with IOV_MAX Boundary

**Probe:** 30b

- `writev` with 16 iovecs of 64 bytes each (1024 total) → rv=1024 ✓
- `writev` with 1024 iovecs of 1 byte each (1024 total) → rv=1024 ✓
- `writev` with 1025 iovecs → rejected (IOV_MAX=1024)

No buffer overflow at the IOV_MAX boundary. Kernel handles correctly.

---

## Finding 16: Port Bind Policy (probe 36, live)

- Ports **<1024 blocked** (rv=-1), ports **≥40000 blocked**
- Ports 1024–32767 work: 1024, 5000, 8080, 9027, 31337–31340 all bind (UDP+TCP)
- TCP 9026 fails (loader owns it); UDP 9026 binds (different protocol slot)
- INADDR_ANY binds fine; SO_REUSEADDR double-bind correctly rejected
- **This solves the 35/35b mystery:** nothing was wrong with bind on good ports; the earlier failure was port-selection-related

---

## Finding 17: ip_reass() Handles All Standard Cases Correctly (probe 39, live)

With a working listener on 31338, all fragment cases reassemble correctly:
- baseline 2-frag, out-of-order, overlap (-8B), tiny-first (8B), dup-final-overwrite, 9×8B chain — **all delivered with correct data**
- First-fragment-wins on overlap (BSD semantics preserved)
- proto=47 fragments correctly not delivered to UDP listener
- **No crash, no corruption.** Basic ip_reass attack surface is well-behaved; deeper fuzzing (timeout expiry, reassembly queue limits, 64+ fragment chains) still untested.

---

## Finding 18: ip_dooptions() Processes Options but Drops Routed Ones (probe 37, live)

- Well-formed RR/TS/NOP: sent and delivered
- Malformed option lengths (len=0, oversized, truncated): **rejected at send time** (rv=-1) — `ip_output()` validates before `ip_dooptions()` ever runs on loopback. The classic length-confusion cases never reach the parser this way.
- **LSRR, SSRR, TS-overflow-flag: send OK but NOT delivered** — kernel processes the option and drops/redirects the packet. Source routing is disabled, as expected, but this confirms option-processing code runs.
- To reach input-side `ip_dooptions()` with malformed lengths, packets must arrive from the **real network** (PC-side scapy), not loopback injection — output-path validation is the gatekeeper.

---

## Finding 19: Crash Record = ASLR Oracle (probes 41m/41o, live)

The crash handler (magic `0x13371337`) emits a ~280-byte binary record on SIGSEGV:
- `+0x08`: signal number (0x0b = SIGSEGV)
- `+0x28`: fault address (si_addr)
- `+0x20/+0x40/+0x58/+0x60/+0x80/+0xD0`: heap pointers (Lua state registers)
- `+0xB8/+0xF8/+0x100`: **code pointers into the main module**
- Code base shifted 0x2393xxxx → 0x2558xxxx between runs: **per-process ASLR, but the delta is consistent across all code pointers** — one crash leaks the module base.
- Heap base `0x3_10000000` region is stable across sessions; only the top frontier moves.

**Strategic value:** any future PC-control primitive (fake vtable etc.) needs gadget addresses. The crash record hands you the module base every time; gadgets can be resolved offline from a dumped copy of the same binary (Relapse can dump on ≤13.60).

---

## Finding 20: The 0x1A3A4EE0 "vtable" is a Session Artifact (probes 41m–41q, live)

- `0x1A3A4EE0` as a raw address is **unmapped** (SIGSEGV, si_addr confirmed 0x1A3A4E00)
- Full scans of the entire mapped heap `[0x310000000, 0x310DC0000)` plus 4 MB anchor-relative windows: **zero objects with dword 0x1A3A4EE0 exist** in fresh sessions
- The 41i/41k/41l "objects with vtable header" were artifacts of that session's heap spray (41j AFAF spray) — not naturally occurring loader objects
- **Do not chase this value without recreating the 41j spray conditions first**

---

## Finding 21: New Syscall Map (probes 38/42a/42b, live)

**Newly confirmed working:**
- `ktimer_create` (clock 0=REALTIME, 4=MONOTONIC), `ktimer_settime`, `ktimer_getoverrun` — **partially open POSIX timer surface**
- `getsockname` — works
- `accept4`, `preadv`, `pwritev`, `copy_file_range` — resolve and error correctly on bad fds (untested on real fds; no usable file fd exists since memfd is stubbed)

**Newly confirmed blocked/stubbed:**
- `ktimer_gettime`, `ktimer_delete` — blocked even on valid ids (inconsistent with settime being open — odd split)
- `getrandom` — blocked
- `ppoll` — blocked
- `cap_rights_limit/get` — blocked
- `memfd_create` — stub, returns fake fd=1
- itimerspec validation is CORRECT (nsec>1e9, negative, huge sec all rejected)
- Timer cap: 27 concurrent timers

**Newly confirmed DEADLY (instant process kill, no crash record):**
- `minherit` — kills on first call (this was the probe-29/30 killer)
- `msync` — kills on first call (the second probe-30 killer, isolated in 42b)

---

## Finding 22: Loader Session Model (live observations)

- pid increments across connections (451→458→472→493→500): the loader respawns a fresh process per TCP connection, **fresh ASLR each probe**
- Heap anchors shift per session (0x310878000, 0x310bdcfc0, 0x310e05520…) — all heap scanning must be **anchor-relative**, never hardcoded
- The mapped heap top ends in a guard page (fault at exactly page-aligned 0x310DC0000); scanning UP into the guard kills the process. Scan DOWN from a known-mapped address, or keep progress output flowing to survive the 30s socket timeout.
