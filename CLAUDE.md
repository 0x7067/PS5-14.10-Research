# PS5 14.10 Kernel Research — AI Guide

## What This Project Is

Systematic kernel exploit research on PlayStation 5 firmware 14.10. The goal is: **userland code exec → kernel R/W → hypervisor bypass**. We have userland code execution via a Lua 5.1 loader on TCP 9026. We need kernel memory access.

## Evidence Corrections
See [docs/EVIDENCE_CORRECTIONS.md](docs/EVIDENCE_CORRECTIONS.md) — scopes current claims and probe evidence.

### The Environment
- **Target:** PS5 at YOUR_PS5_IP:9026, firmware 14.10
- **Kernel:** FreeBSD r230171 (Sep 28 2026), 16KB pages
- **Entry:** Lua 5.1 scripts sent over TCP (8-byte LE length prefix + raw source)
- **Tool:** `python tools/send_probe.py --save probes/<path>.lua` (writes a JSON run record; `tools/run_probe_batch.py` provides bounded sequential execution)
- **Per-connection ASLR:** Fresh process spawns for every TCP connection. All addresses must be re-derived each run.

### What We Have (Confirmed Working)
| Primitive | How |
|-----------|-----|
| Tested raw syscall invocation | make_syscall(N) bypasses the Lua syscall.resolve() filter for tested numbers; kernel-side restrictions still apply |
| Heap R/W (256+ pages) | GPU mmap adjacency, no guard pages |
| Userland module-base discovery | dynlib_get_info(593) returned base information for 39 userland modules; kernel ASLR is separate |
| eboot gadget catalog | Readable candidate bytes; 56e records nil gadget-test returns, but no working general ROP chain is established |
| Network packet injection | RAW socket + IP_HDRINCL, TCP connect-back with ARP responder |
| sys 649 module member query | Returns userland addresses for member types 1-4, 7, 8 across module handles (no kernel pointers). Probe 54k, 2026-10-18 |
| CClosure function redirect | Selected existing Lua C targets produced target-like outputs and restore checks (56c/56f); arbitrary target/ABI and ROP support remain unverified |
| native.fcall_with_rax | Arbitrary userland function calls: getpid=0x22a, socket=0x16, close=0x0 confirmed (probe 129b) |
| C11 threading (Thrd_create) | 5+ concurrent threads with join; Atomic_fetch_add_8 as thread entry verified (probes 126g/126h) |
| UMTX_OP functional (op 5/21) | UMTX_OP_WAIT blocks correctly on value match; NWAKE_PRIVATE returns 0; MUTEX_LOCK writes owner TID (probes 56i2, 152k) |
| Device inventory (34/76 nodes) | 34 of 76 `/dev` nodes open from game process (`gc`, `dce`, `ajm`, `dmem0`-`2`, `camera`, `usb`, `hid`, `bt`, `rng`, `gic`, `notification*`, HMD sets); ioctl reaches drivers, they reject commands. 32-bit dirent layout. Probes 259a-268a, PR #74 ng643, 2026-10-21 |

### What's Blocked (Hard Walls)
- **fn_addr/ROP execution is not demonstrated** — 45c undermines that model; CClosure redirects are separate userland evidence
- **W^X enforced** — hypervisor blocks execute bit on all mmap/mprotect paths. sys 588/548 return 0 but PTE unchanged
- **XOM** — system lib .text is execute-only (reading crashes past pcall); eboot .text is RX
- **Threading** — `thr_create(430)` works with correct gates/CS/SS. See `docs/THREADING_ALIVE_14_10.md`
- **Thread ucontext** — read (634) works, write (635) returns -1. No register rewrite of existing threads
- **mmap_dmem (628)** — refuses every descriptor/prot/flag combination (330a/331a)
- **Authid gates hold** — 535/536/563-566 check `cred+0x58`; bit 62 gates 618/646/671 and is unwritable (332a/333a)
- **A kill does not prove the slot is absent** — a handler that faults on bad args dies the same way. See `docs/SYSCALL_ABSENT_VS_LETHAL.md`
- **Sysent ends at 676** — 677-707 all kill; real-args probes (275a) needed before accepting past-the-end. See `docs/SYSENT_PRESENCE_14_10.md`
- **No kernel pointers found** — AF_ROUTE, kldstat, kinfo_proc, GPU pool, all scanned paths: zero kernel pointers. No KASLR defeat identified
- **ROP-shaped metadata role is unknown** — do not treat fn_addr/chain fields as a function-call primitive

### Tested raw syscall behavior
The Lua loader's resolver filter blocks some syscall names. Selected calls still returned results through make_syscall(); this bypasses the Lua-side filter only for those tested calls, and kernel-side restrictions remain. The full dispatch implementation is unknown.

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
Historical hypothesis only: the heap contains writable ROP-shaped metadata and argument slots. Probe 45c recorded tested calls continuing after selected mutations, so this does not establish that the loader calls fn_addr or executes the chain.

### Getting Key Addresses
```lua
-- Userland module-base discovery; this does not defeat kernel ASLR
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(handle), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)

-- Historical metadata addresses; not established as execution controls
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

`probes/phase{N}_{name}/` — Lua probes by phase (1-13+). `results/` — output logs (same structure). `tools/` — send_probe.py, run_probe_batch.py. `docs/` — ATTACK_SURFACE.md (syscall map), FINDINGS.md, PROBE_INDEX.md, STRATEGY.md, UNTESTED_THEORIES.md, DEAD_ENDS.md, EVIDENCE_CORRECTIONS.md.

## Known Dead Ends
**MANDATORY**: read [docs/DEAD_ENDS.md](docs/DEAD_ENDS.md) before writing any probe. 110+ tested paths documented there.

## Sending Probes

```bash
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<name>.lua
```
Results → `results/<phase>/<name>_<timestamp>.txt`. PowerShell: `.\tools\send_probe.ps1 <probe> -Save`. TCP fuzz: `tools/run_session40.py`.

## Current Attack Priority

**Key context:** No KASLR defeat found. W^X hard-enforced by hypervisor. CClosure redirect works for selected Lua C targets (56c/56f) but arbitrary/ABI unverified. See `docs/EVIDENCE_CORRECTIONS.md` for full evidence scoping.

**NEXT STEPS:**
1. **★ Run probe 58a — msync(65) device-pager UAF (CVE-2026-49418)** — syscall number corrected from nosys 226 to real 65 (PR #70, DEM9N101). If msync(MS_INVALIDATE) returns 0 on GPU-mmap pages, the device-pager vulnerability path is reachable. **Highest priority test.**
2. **Threaded UMTX PI-mutex races (op 5/6/22 on 454)** — UMTX_OP_WAIT/WAKE/MUTEX are functional (56i2, 152k). Thread budget is ≤8 children (PR #71). Use corrected parking pattern (`jmp $` gadget) to race MUTEX_LOCK/UNLOCK for refcount or state corruption.
3. **56d ROP via CClosure** — redirect +0x20 to eboot gadgets (ret, pop rdi;ret, etc.) to build a gadget chain. Redirect rawequal/rawget to gadget addresses, call them, observe register/stack effects.
4. **Sysent 679-734 survey** — unexplored Sony syscall range beyond the lethal 677/678
5. **Targeted device ioctl research** — 34 drivers reachable; `gc`, `dce`, `gic`, `camera`, `notification*` have kernel-facing code. Need Sony ioctl command codes from 13.60 Ghidra analysis, not blind sweeps. (PR #74 ng643)
6. **Run JSC corpus (p172)** — 518 regression test cases targeting WebKit bugs fixed after Safari 17.0 branch. Guide browser engine is pre-17.0. Even one crash is a lead. (PR #75 ng643)
7. **Remaining gaps** — syscalls 530–532/537 (PR #72 gap), probe 243a (thread slot reclaim, written not run), UMTX op 19 non-deterministic write repeat

## When Analyzing Results

1. **Kernel pointers** are in the `0xFFFF8xxx_xxxxxxxx` range. Values like `0xFFFFFFFF_00000000` are bitmasks, not pointers.
2. **ret=0** means success for most syscalls. **ret=-1** means failure. **ret=-999** means the pcall itself failed (crash or exception).
3. **Always cross-reference** against docs/FINDINGS.md and the dead ends list above before declaring something new.
4. **Update UNTESTED_THEORIES.md** when a theory is tested — mark it confirmed, dead, or partially tested.
5. **Update CHANGELOG.md** with each phase's findings.

## Git Conventions

- **Author:** commit as the contributor doing the work (Rithik Janarthanan
  <janarthananrithik@gmail.com>), never as the repository owner
- **No AI attribution** in commits, PRs, or code.
- Commit messages should be short and descriptive of what changed.
