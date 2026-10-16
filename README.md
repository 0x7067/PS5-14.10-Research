# PS5 Firmware 14.10 Kernel Attack Surface Research

Systematic kernel attack surface mapping and exploit primitive development on PlayStation 5 firmware **14.10**, conducted via a userland Lua loader at `10.0.0.96:9026`.

**Goal chain:** Userland code exec → Kernel R/W → Hypervisor bypass

## Current Status: Exploit Primitives Complete

All userland exploit primitives are confirmed working. The path to kernel R/W is open.

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

### Alternative: Loader ROP Chain Hijack

The Lua loader builds a complete ROP chain in heap memory for every syscall invocation (discovered in probe 41v). The chain layout:
1. Set all argument registers (rdi, rsi, rdx, rcx, r8)
2. Load function address from memory into call stub
3. `pop rsp; ret` pivots to call stub
4. Function executes, returns to longjmp recovery

By overwriting the call stub's function pointer or return address in the heap, we can redirect execution to arbitrary addresses — including kernel exploit payloads.

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

### Phase 7: Heap Exploitation (Probes 40–41w)
GPU mmap boundary discovery, heap adjacency exploitation, object identification, vtable analysis, ASLR bypass via dynlib_get_info, ROP gadget extraction, loader chain reverse engineering, kernel R/W infrastructure.

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

## Running Probes

```bash
# Send a probe to the PS5
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<probe_name>.lua

# Results are saved to results/<probe_name>_<timestamp>.txt
```

The loader expects an 8-byte LE uint64 length prefix followed by raw Lua source on TCP port 9026.

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
