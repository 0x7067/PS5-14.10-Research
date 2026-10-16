# PS5 Firmware 14.10 Kernel Attack Surface Research

Systematic kernel attack surface mapping and exploit primitive development on PlayStation 5 firmware **14.10**, conducted via a userland Lua loader at `10.0.0.96:9026`.

**Goal chain:** Userland code exec → Kernel R/W → Hypervisor bypass

## Current Status: Userland Arbitrary-Call Confirmed

All userland exploit primitives confirmed working. **The loader's live ROP chain is fully writable from the heap primitive** — both the function call target and all argument slots can be overwritten and restored without crashing the process.

**Critical assessment (read before celebrating):** controlling ROP-chain argument slots gives arbitrary *syscall invocation*, not kernel memory access. `sysctl` only returns the OIDs Sony chose to expose, and kernel objects (socket structs, uma zones) do not live in the userland heap (41x). "copyout/copyin gadgets" cannot be called from userland ROP — they are kernel functions. Closing the gap to kernel R/W still requires a kernel memory disclosure (leaky OID / info-leak bug) or a kernel corruption bug — which is what the network input path program (below) hunts.

**Open question with big consequences:** 41w's sysctl succeeded via `make_syscall()` while early probes declared sysctl "blocked" via `syscall.resolve()`. The sandbox filter may live in the resolve path, not the kernel. If so, every "blocked" verdict (threading, AIO, ioctl, dup) needs re-testing through the raw path — threading alone would reopen the entire race-condition bug class.

### Confirmed Primitives

| Primitive | Status | Source |
|-----------|--------|--------|
| Arbitrary syscall | Working | `make_syscall()` via Lua loader |
| Heap read (256+ pages) | Working | GPU mmap adjacency, no guard pages |
| Heap write | Working | Same GPU mmap primitive |
| ASLR bypass | Working | `dynlib_get_info` leaks all 39 module bases |
| Complete ROP gadget set | Working | Extracted from loader's own ROP chain |
| Stack pivot (`pop rsp; ret`) | Working | eboot+0x9A2 |
| Function call stub | Working | Loader's internal call mechanism |
| **ROP chain hijack** | **Confirmed** | **Chain + fn_addr writable from heap (probe 41z)** |
| Kernel info via sysctl | Working | FreeBSD r230171, securelevel=1024 |

### ROP Gadget Catalog (eboot-relative offsets)

These offsets are constant across runs; add the ASLR'd eboot base each session.

```
pop rdi; ret         eboot+0xC9DFE
pop rsi; ret         eboot+0xD77D
pop rdx; ret         eboot+0x3502D7
pop rax; ret         eboot+0x992
pop rcx; ret         eboot+0xE64
pop r8; ret          eboot+0x991
pop rsp; ret         eboot+0x9A2     (stack pivot)
ret                  eboot+0x42
jmp rax              eboot+0x84C
mov rax,[rax]; ret   eboot+0x1EEBB
mov [rdi],rax; ret   eboot+0x92C67
pop r13;r14;r15;ret  eboot+0xE1FC7
leave; ret           eboot+0x37FDE0
xchg rsp,rax         eboot+0x163874
```

Syscall stub: `libkernel+0xB57` (discovered via loader introspection in probe 41v).

### Kernel Build Info (from sysctl)

```
kern.ostype:      FreeBSD
kern.osrelease:   0.0-prototype
kern.version:     r230171/releases/14.10 Sep 28 2026 02:18:33
kern.securelevel: 1024 (PS5-specific)
hw.pagesize:      16384 (16 KB)
hw.ncpu:          16
```

## Environment

| Property | Value |
|----------|-------|
| Firmware | 14.10 |
| Kernel | FreeBSD r230171 (Sep 28 2026) |
| Entry point | Lua 5.1 loader on TCP port 9026 |
| Page size | 16 KB (0x4000) |
| CPU cores | 16 (Zen 2 8C/16T) |
| Syscall API | `make_syscall(num)` clones `syscall.pipe` |
| Memory API | `memory.alloc/read_*/write_*` for userland buffers |

## Key Constraints Discovered

- **W^X strictly enforced** — `mmap(RWX)` gives `RW` only; `mprotect(EXEC)` always fails
- **Execute-only memory (XOM)** on system libraries — libkernel text is XO, reading crashes the process; eboot text is RX (readable)
- **Threading fully blocked** — `fork`, `rfork`, `thr_new` all return -1
- **Signal mask is a no-op** — `sigprocmask` returns 0 but never modifies the mask
- **AIO completely sandbox-killed** — all `aio_*` syscalls terminate the process
- **minherit/msync are deadly** — instant process kill, no crash record
- **No kernel pointers in userland heap** — confirmed across 10,240 qword exhaustive scan
- **Per-connection ASLR** — fresh process per TCP connection, new address layout each probe

## Heap R/W Primitive Details

GPU mmap allocations (`mmap(0, size, 0x33, 0x1002, -1, 0)`) have **no guard pages**. Memory 256+ pages before the allocation is readable AND writable — this is adjacent heap data in the `0x3_1xxxxxxx` range.

- Read confirmed: can read heap object metadata, pointers, vtable references
- Write confirmed: `DEADBEEF` written and read back successfully
- Heap objects contain type descriptor pointers at `0x1_xxxxxxxx` (kernel-mapped, unreadable from userland)
- Heap objects contain self-referential linked list pointers (hash/bucket tables at `0x1426xxxxx`)

## Exploit Strategy

### Path to Kernel R/W

1. **Map heap object types** near GPU mmap boundary
2. **Find a controllable kernel object** (socket, kqueue fd, pipe) allocated adjacent to GPU memory
3. **Corrupt its internal buffer pointer** via heap write to point at a kernel address
4. **Read/write kernel memory** through the corrupted object's normal syscall interface (e.g., `recvmsg` on a socket with corrupted recv buffer)
5. **Use leaked kernel address + ROP** for privilege escalation

### CONFIRMED: Loader ROP Chain Hijack (Probe 41z)

The Lua loader builds a complete ROP chain in heap memory for every syscall invocation (discovered in probe 41v). **Probe 41z confirmed the chain is fully writable from the GPU mmap heap primitive:**

- Chain at `ropchain_base` is ~145 pages before GPU mmap — within the 256+ page R/W zone
- `fn_addr` (function call target pointer) is writable: `0x4141414142424242` written and read back
- 13 argument slots mapped to their register destinations (rdi, rsi, rdx, rcx, r8, rsp)
- Write/restore cycle verified — getpid() still works after all corruption/restore cycles

The chain layout:
1. Load each argument from a heap slot via `pop rax; mov rax,[rax]; pop rdi; mov [rdi],rax`
2. Write function address to call stub's `fn_addr`
3. `pop rsp; ret` pivots to call stub
4. Function executes, returns to longjmp recovery

**Exploitation**: overwrite the argument slot values before triggering a syscall to control what the kernel receives. Combined with the writable `fn_addr`, this gives arbitrary function call with fully controlled arguments — kernel R/W via `sysctl` or `copyout`/`copyin` gadgets.

## Probe Categories

### Phase 1: Identity & Layout (Probes 1–8)
Basic system identification, syscall availability sweep, memory layout mapping, file system recon.

### Phase 2: Kernel Object Stress (Probes 9–21)
IPv6 stack stress, UMTX operations, nwake oracle, device ioctls, direct memory access, AIO, kqueue.

### Phase 3: Signal & Code Execution (Probes 22–26f)
Signal handler installation, sigaltstack kernel write attempts, gadget scanning, W^X confirmation.

### Phase 4: IPC & Network Internals (Probes 27–31c)
Threading, fd passing (SCM_RIGHTS), IPv6 extension headers, mmap/fcntl deep dive, socket option fuzzing, PS5 custom socket options.

### Phase 5: Buffer & I/O Edge Cases (Probes 32–33f)
Buffer minimum stress testing, nonblocking I/O discovery (MSG_DONTWAIT), F_SETFL bypass analysis.

### Phase 6: Raw Packet Injection (Probes 34–39)
RAW socket + IP_HDRINCL confirmed working. Fragment reassembly testing. IP options parsing.

### Phase 7: Heap Exploitation (Probes 40–41z)
GPU mmap boundary discovery, heap adjacency exploitation, object identification, vtable analysis, ASLR bypass via dynlib_get_info, ROP gadget extraction, loader chain reverse engineering, kernel R/W infrastructure.

### Phase 8: Network Input Path — Live Results (Probes 36–40, 42a–42b)
Kernel parsers reachable via RAW socket injection and attacker-controlled TCP. Run live against the console on 2026-10-15/16.

| Probe | Result |
|-------|--------|
| 36 | **Port bind policy mapped:** <1024 and ≥40000 blocked; 1024–32767 open. Solves the 35/35b fragment-test blocker. |
| 39 | `ip_reass()` correct on all 7 standard cases (baseline, out-of-order, overlap, tiny-first, dup-final, 9-frag chain, non-UDP control). Basic frag attacks dead; queue-exhaustion/timeout fuzz still open. |
| 37 | Malformed IP option lengths are **rejected in `ip_output()`** before reaching `ip_dooptions()` — loopback can't deliver length-confusion packets. LSRR/SSRR/TS-overflow are processed and dropped. Input-side option fuzzing must come from the real network. |
| 40 | **TCP connect-back fuzz WORKS end-to-end.** PC impersonates a fake LAN host (`tools/run_session40.py`: ARP responder + raw packets from an unowned IP, so the Windows stack never RSTs). Full handshake + 26 malformed segments (SACK with impossible blocks, URG+max urgptr, seq overlap, all-flags, RST-with-data) delivered; console stable. Bigger variant space is the next step. |
| 42a | **ktimer surface partially open:** `ktimer_create` (clocks 0+4), `ktimer_settime`, `ktimer_getoverrun` work; `gettime`/`delete` blocked; validation correct; cap 27 timers. |
| 42b | `memfd_create` is a stub (fake fd=1). **`msync` = instant process kill** — with `minherit` (probe 38), both probe-29/30 killers are now identified. |

**Crash handler = ASLR oracle:** every SIGSEGV emits a ~280-byte record (magic `0x13371337`) leaking the fault address, heap registers, and the main module's code base for that process.

**41m–41q vtable chase closed:** `0x1A3A4EE0` is unmapped; zero matching objects exist in fresh sessions — the 41k-era "objects" were heap-spray artifacts. Dead end, do not revisit without recreating spray conditions.

## Key Probe Results

| Probe | Finding |
|-------|---------|
| 41c | GPU mmap has no guard pages — 256+ adjacent heap pages R/W |
| 41e | Heap write confirmed (DEADBEEF readback) |
| 41o | ASLR bypass: dynlib_get_info returns all 39 module bases |
| 41o | Zero kernel pointers in 10,240 qword heap scan |
| 41q | System lib text is XO; eboot text is RX |
| 41r | First 300KB gadget scan: pop_rax, pop_rsi, pop_rcx, jmp_rax found |
| 41s | Deep scan: pop_rdi confirmed at eboot+0xC9DFE, xchg_rsp at +0x163874 |
| 41t | pop_rdx confirmed at eboot+0x420E6D, leave;ret at +0x37FDE0 |
| 41u | Zero syscall instructions in entire eboot binary (4.6MB scanned) |
| 41v | Loader ROP chain dumped — complete gadget set + libkernel stub at +0xB57 |
| 41w | Kernel info: FreeBSD r230171, securelevel=1024, 16 cores, 16KB pages |
| 41x | Socket kernel objects are in kernel memory (uma_zalloc), not userland heap |
| 41y | Located ropchain buffer in GPU-adjacent heap zone (output truncated) |
| 41z | **ROPCHAIN HIJACK CONFIRMED** — chain + fn_addr fully writable, all arg slots mapped |

## Running Probes

```bash
# Send a probe to the PS5
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<probe_name>.lua

# Results are saved to results/<probe_name>_<timestamp>.txt

# TCP connect-back fuzz session (probe 40 + PC-side raw packet server,
# fake-IP ARP responder so the host OS doesn't RST the connection):
python tools/run_session40.py --ps5-ip 10.0.0.96 --fake-ip 10.0.0.250
```

The loader expects an 8-byte LE uint64 length prefix followed by raw Lua source on TCP port 9026.

**Long-running probe tips (learned live):** the loader spawns a fresh process per connection (fresh ASLR — derive all addresses from `memory.alloc` anchors, never hardcode); the mapped heap ends in a guard page, so scan DOWN from known-mapped memory; print progress every ≤30s or the socket recv timeout kills the session (this is what killed probe 41n).

### Critical Lua Constraints

1. **uint64 for addresses >32 bits**: use `uint64(string.format("0x%X%08X", hi, lo))` — passing a Lua double overflows
2. **pcall wrapping**: `pcall(function() return memory.read_qword(addr) end)` — NOT `pcall(memory.read_qword, addr)`
3. **Lua 5.1**: no `goto`/labels — use `repeat...until true` + `break`
4. **XO pages bypass pcall**: reading execute-only memory causes SIGSEGV that kills the process, pcall cannot catch it
5. **Fresh ASLR per connection**: all addresses must be re-derived each probe run

## Documentation

- [docs/PROBE_INDEX.md](docs/PROBE_INDEX.md) — Full probe-by-probe breakdown
- [docs/ATTACK_SURFACE.md](docs/ATTACK_SURFACE.md) — Complete syscall status map
- [docs/FINDINGS.md](docs/FINDINGS.md) — Detailed technical findings
- [docs/STRATEGY.md](docs/STRATEGY.md) — Exploit strategy assessment

## License

This research is for educational and authorized security research purposes only.
