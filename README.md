# PS5 Firmware 14.10 Kernel Attack Surface Research

Systematic kernel attack surface mapping on PlayStation 5 firmware **14.10**, conducted via a userland Lua loader at `10.0.0.96:9026`.

**Goal chain:** Userland code exec → Kernel R/W → Hypervisor bypass (Byepervisor)

## Environment

| Property | Value |
|----------|-------|
| Firmware | 14.10 |
| Entry point | Lua 5.1 loader on TCP port 9026 |
| PID | 355–360 (varies by session) |
| Syscall API | `syscall.resolve()` batch registration, `syscall.<name>()` calls |
| Memory API | `memory.alloc/read_*/write_*` for userland buffers |

## Key Constraints Discovered

- **W^X strictly enforced** — `mmap(RWX)` gives `RW` only; `mprotect(EXEC)` always fails
- **Execute-only memory (XOM)** — cannot read from code pages (no gadget scanning)
- **Threading fully blocked** — `fork`, `rfork`, `thr_new` all return -1 (no race conditions)
- **Signal mask is a no-op** — `sigprocmask` returns 0 but never modifies the mask
- **AIO completely blocked** — all `aio_*` syscalls killed by sandbox
- **sysctl/ioctl/dup/fstat** — all blocked

## Summary of All Probes

See [docs/PROBE_INDEX.md](docs/PROBE_INDEX.md) for the full probe-by-probe breakdown.
See [docs/ATTACK_SURFACE.md](docs/ATTACK_SURFACE.md) for the complete syscall status map.
See [docs/FINDINGS.md](docs/FINDINGS.md) for the detailed technical findings.
See [docs/STRATEGY.md](docs/STRATEGY.md) for the current exploit strategy assessment.

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

### Phase 6: Raw Packet Injection (Probes 34–35b)
RAW socket + IP_HDRINCL confirmed working. Crafted UDP packets reach kernel `ip_input()`. Fragment reassembly testing (ongoing).

## Critical Lua Loader Constraints

These will crash the loader silently if violated:

1. **`make_syscall()` pattern does NOT work** — must use `syscall.resolve()` batch registration
2. **NULL/zero arguments crash many syscalls** — always provide valid buffers
3. **Lua 5.1 — no `goto`/labels**
4. **`sendto` (133) and `recvfrom` (29) crash `syscall.resolve()`** — use `sendmsg`/`recvmsg` instead
5. **`SOCK_NONBLOCK` (0x20000000) in socketpair type crashes the loader**
6. **`shm_open` crashes the loader**

## Running Probes

```bash
python tools/send_probe.py probes/<probe_name>.lua
```

The loader expects an 8-byte LE uint64 length prefix followed by raw Lua source.

## License

This research is for educational and authorized security research purposes only.
