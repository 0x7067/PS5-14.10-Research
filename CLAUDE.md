# PS5 14.10 Kernel Research — AI Guide

## What This Project Is

Systematic kernel exploit research on PlayStation 5 firmware 14.10. The goal is: **userland code exec → kernel R/W → hypervisor bypass**. We have userland code execution via a Lua 5.1 loader on TCP 9026. We need kernel memory access.

## Critical Context

### The Environment
- **Target:** PS5 at `10.0.0.96:9026`, firmware 14.10
- **Kernel:** FreeBSD r230171 (Sep 28 2026), 16KB pages
- **Entry:** Lua 5.1 scripts sent over TCP (8-byte LE length prefix + raw source)
- **Tool:** `python tools/send_probe.py --save probes/<path>.lua`
- **Per-connection ASLR:** Fresh process spawns for every TCP connection. All addresses must be re-derived each run.

### What We Have (Confirmed Working)
| Primitive | How |
|-----------|-----|
| Arbitrary syscall | `make_syscall(N)` — bypasses `syscall.resolve()` sandbox via C wrapper |
| Heap R/W (256+ pages) | GPU mmap adjacency, no guard pages |
| ASLR bypass (userland) | `dynlib_get_info(593)` leaks all 39 module bases |
| Full ROP gadget set | Extracted from eboot (RX, not XO) — but ROP chain is NOT used by make_syscall |
| Network packet injection | RAW socket + IP_HDRINCL, TCP connect-back with ARP responder |

### What's Blocked (Hard Walls)
- **No native code execution** — make_syscall() uses C wrapper, NOT ROP chain. fn_addr is never called. W^X "bypass" was false positive (probe 45c)
- **W^X enforced** — `mmap(RWX)` gives RW only; `mprotect(EXEC)` always fails; mtypeprotect may change perms but no jump path exists
- **Execute-only memory (XOM)** — system lib .text is XO (reading crashes); eboot is RX
- **No threading** — `fork`, `rfork`, `thr_new` all blocked (confirmed via both resolve() and make_syscall)
- **AIO sandbox-killed** — all `aio_*` terminate instantly (confirmed kernel-level, not resolve()-side)
- **No kernel pointers in userland** — all info leak paths exhaustively tested and dead
- **ROP chain is vestigial** — chain + fn_addr + slot0 are metadata only; make_syscall() bypasses them entirely (probe 45c)

### The Key Insight: `make_syscall()` Bypasses the Sandbox
The Lua loader's `syscall.resolve()` function has a filter that blocks many syscalls. But `make_syscall(N)` constructs a raw syscall object that goes straight to the kernel. **Sysctl (202) was reported "blocked" by resolve() but works perfectly via make_syscall().** This means every "blocked" verdict from earlier probes needs re-testing.

## How to Write Probes

### Probe Template
```lua
-- CRASH_CLASS: LOW | MODERATE | HIGH | RISKY
-- PROBE XX: one-line description
--
-- Context: what we know, what we're testing, why

print("=== PROBE XX: TITLE ===")
print("")

-- Standard helpers (ALWAYS include these)
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
```

### Lua 5.1 Constraints (MUST follow)
1. **uint64 for all addresses >32 bits:** `uint64(string.format("0x%X%08X", hi, lo))`
2. **pcall everything risky:** `pcall(function() return memory.read_qword(addr) end)`
3. **No `goto`/labels** — Lua 5.1 doesn't have them. Use `repeat...until true` + `break`
4. **XO pages kill past pcall** — reading execute-only memory terminates the process. Never read system lib .text sections. Eboot .text is RX and safe to read.
5. **Fresh ASLR every connection** — never hardcode addresses. Always re-derive from `dynlib_get_info` or `tostring(syscall.pipe)`.
6. **memory.alloc(N)** for heap buffers. Always zero them before use.
7. **Kernel pointer detection:** `h >= 0xFFFF8000` where `h, l = get_hi_lo(val)`. Values like `0xFFFFFFFF_00000000` and `0xFFFFFFFF_FFFFFFFF` are bitmasks/sentinels, NOT real kernel pointers.

### How make_syscall Works
```lua
local sc = make_syscall(202)  -- sysctl
local ret = sc(arg1, arg2, arg3, arg4, arg5, arg6)
-- Arguments are uint64 values
-- Returns: the syscall return value
```
The ROP chain loads `fn_addr` (the syscall stub), sets rdi/rsi/rdx/rcx/r8 from argument slots, calls the function, and returns the result. All of these slots are in the heap R/W zone.

### Getting Key Addresses
```lua
-- Module bases (ASLR bypass)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(handle), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)

-- ROP chain + fn_addr addresses
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")

-- GPU mmap (heap R/W primitive)
local sc_mmap = make_syscall(477)
local gpu = sc_mmap(uint64(0), uint64(512*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
```

### Sysctl Pattern
```lua
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 1)   -- KERN_PROC_PID
safe_wd(mib + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x800)
local ret = sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
    uint64(oldlenp), uint64(0), uint64(0))
```

## Repository Layout

```
probes/
  phase1_identity_layout/    # 01-08: system ID, syscalls, memory
  phase2_kernel_objects/     # 09-21: UMTX, nwake, dmem, AIO, kqueue
  phase3_signals_codexec/    # 22-26: signals, sigaltstack, W^X, XOM
  phase4_ipc_network/        # 27-31: threading, fd passing, sockets
  phase5_buffer_io/          # 32-33: buffer stress, MSG_DONTWAIT
  phase6_raw_packets/        # 34-39: RAW sockets, fragments, IP options
  phase7_heap_exploitation/  # 40-41: GPU mmap, heap R/W, ROP, ASLR bypass
  phase8_live_network/       # 40tcp, 42: TCP fuzz, ktimer, live testing
  phase9_kaslr_defeat/       # 42b-42j: KASLR attempts (mostly failed)
  phase10_untested_theories/ # 43a+: theory-driven probes (READY TO SEND)
results/                     # Output logs (same phase structure)
tools/                       # send_probe.py, run_session40.py, tcp_fuzz_server.py
docs/
  ATTACK_SURFACE.md          # Complete syscall status map
  FINDINGS.md                # Detailed technical findings
  PROBE_INDEX.md             # Every probe with status and key result
  STRATEGY.md                # Exploit strategy and dead ends
  UNTESTED_THEORIES.md       # 17 theories ranked by priority
```

## Known Dead Ends (Don't Repeat These)

- **sigaltstack kernel write** — copyout() validates destinations
- **mprotect(EXEC)** — always fails, hard W^X
- **XOM gadget scan** — reading XO pages crashes past pcall
- **Threading via resolve()** — fork/rfork/thr_new all -1
- **AIO** — sandbox-killed instantly
- **kqueue** — fd allocates but kevent returns -1
- **ioctl via resolve()** — all blocked (untested via make_syscall)
- **sysctl kernel pointer leaks** — all scanned pointers are sentinels (0xFFFFFFFF_*)
- **TCP_INFO** — 236 bytes, no kernel pointers
- **minherit/msync** — instant-kill syscalls
- **memfd_create** — stub, does nothing
- **/dev/dmem0** — opens but all operations fail (GPU partition only)
- **kenv** — sandbox kill
- **TCB (FS base)** — userland only (0x88xxxxxxxx)
- **libkernel data segment scan** — no kernel pointers
- **kldstat at syscall 306** — 306 is `kldfind` (crashed on bad arg). Real FreeBSD `kldstat` is 308; sweep 02 had 367. Probe 43a tests both.
- **sysarch command confusion** — 129 is `SET_FSBASE` (calling with 0 crashes userland). Real `GET_GSBASE` is 130.
- **/dev/dmem0 physical memory** — GPU aperture only; phys 0 = GPU HW reg `0x80000000_C0012800`, 4GB+ unmapped/zeros.
- **pipe(42) via make_syscall** — returns fds 0,0 (dead)
- **ROP chain hijack / fn_addr redirect** — make_syscall() bypasses ROP chain entirely via C wrapper. fn_addr never called. ud2/null/unmapped = no crash. Chain corruption = no effect (probe 45c)
- **W^X bypass via mtypeprotect + fn_addr** — false positive. mtypeprotect may change perms but fn_addr never calls the page. No code execution path exists (probes 44a, 45a-c)
- **Shellcode execution via fn_addr** — all return values = pid regardless of shellcode content. Code is never executed (probes 45a-c)
- **AF_ROUTE KASLR (Relapse technique)** — socket opens, zero kernel pointers. Info leak patched on 14.10.
- **AIO via make_syscall** — sandbox kill is kernel-level. aio_error instant-kills even raw.
- **kldstat/kldsym via make_syscall** — both sandbox-killed at kernel level.
- **kinfo_proc kernel pointers** — full 1096B dump: only sentinels, no real kernel pointers.
- **kern.proc.filedesc/vmmap** — blocked (ret=-1)
- **sysctl write paths** — all blocked (securelevel, coredump, maxproc)
- **sysarch GET_GSBASE** — returns 0, no kernel pointer
- **ioctl via make_syscall** — returns -1 for all tested codes
- **dup/dup2 via make_syscall** — returns -1
- **thr_new via make_syscall** — crashes process
- **kern.msgbuf** — returns only 8 bytes (filtered)
- **mincore KASLR oracle** — all kernel VA probes return -1
- **sockopt overflow** — kernel clamps copy length, not exploitable
- **/dev/hid ioctl** — Sony error 0x80740004 on all codes
- **Syscall 557** — returns formula-based metric (base+ver), base varies per connection. Not exploitable.
- **Syscall 620** — always returns 0, doesn't modify buffers. No-op.
- **CClosure C function pointer redirect** — CClosure +0 (C func ptr) is READ-ONLY. Upvalues (+16-48) writable but don't control dispatch. All metatable functions same. (probe 47b)

## Sending Probes

```bash
# Via Python (if installed):
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<name>.lua

# Via native PowerShell (no Python required):
.\tools\send_probe.ps1 probes\<phase>\<name>.lua -Save

# For TCP connect-back fuzzing:
python tools/run_session40.py --ps5-ip 10.0.0.96 --fake-ip 10.0.0.250
```

Results are saved to `results/<phase>/<name>_<timestamp>.txt`.

## Current Attack Priority (Updated 2026-10-16 — post-45c)

**★★★ CRITICAL UPDATE:** Probe 45c proved make_syscall() bypasses the ROP chain entirely. fn_addr, slot0, and the chain are vestigial. The W^X "bypass" was a false positive. We have NO native code execution and NO KASLR defeat.

**REMAINING PRIMITIVES:**
- Arbitrary syscall via `make_syscall(N)` (C-level wrapper, confirmed working)
- Heap R/W via GPU mmap (256+ pages)
- Userland ASLR bypass via `dynlib_get_info(593)`
- Network packet injection (RAW socket + IP_HDRINCL, TCP connect-back)

**NEXT PROBES TO WRITE:**
1. **TCP input-side attacks** — SACK processing, urgent pointer, MD5/AO, PAWS (network-side, bypasses syscall sandbox)
2. **IP options from real network** — scapy from PC with malformed options to PS5 LAN IP
3. **Sony syscall 557/620 deep investigation** — proper arg structures, output buffers
4. **Loader internals** — find the C-level syscall dispatch, check for writable function pointers
5. **SCTP / ip_reass deeper** — untested attack surface in network stack

## When Analyzing Results

1. **Kernel pointers** are in the `0xFFFF8xxx_xxxxxxxx` range. Values like `0xFFFFFFFF_00000000` are bitmasks, not pointers.
2. **ret=0** means success for most syscalls. **ret=-1** means failure. **ret=-999** means the pcall itself failed (crash or exception).
3. **Always cross-reference** against docs/FINDINGS.md and the dead ends list above before declaring something new.
4. **Update UNTESTED_THEORIES.md** when a theory is tested — mark it confirmed, dead, or partially tested.
5. **Update CHANGELOG.md** with each phase's findings.

## Git Conventions

- **Author:** ZigZagBoi1 <marwantech2004@gmail.com>
- **No AI attribution** in commits, PRs, or code.
- Commit messages should be short and descriptive of what changed.
