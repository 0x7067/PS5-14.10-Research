# Complete Attack Surface Map — PS5 14.10

## Syscall Status

### Fully Working
| Syscall | Number | Notes |
|---------|--------|-------|
| `read` | 3 | Works on socket fds |
| `write` | 4 | Works on socket fds |
| `close` | 6 | Standard fd close |
| `getpid` | 20 | Returns process PID |
| `recvmsg` | 27 | Full functionality with MSG_DONTWAIT |
| `sendmsg` | 28 | Full functionality with MSG_DONTWAIT |
| `socket` | 97 | AF_INET, AF_INET6, AF_UNIX; STREAM, DGRAM, RAW |
| `connect` | 98 | TCP and raw socket connect |
| `bind` | 104 | Works on loopback (port restrictions may apply) |
| `setsockopt` | 105 | Limited options writable (see below) |
| `listen` | 106 | TCP listen works |
| `getsockopt` | 118 | Most options readable |
| `readv` | 120 | Up to IOV_MAX=1024 iovecs |
| `writev` | 121 | Up to IOV_MAX=1024 iovecs, 1025 rejected |
| `socketpair` | 135 | AF_UNIX SOCK_STREAM |
| `shutdown` | 134 | Standard shutdown |
| `poll` | 209 | Correct POLLIN/POLLHUP/POLLNVAL semantics |
| `mmap` | 477 | RW only (no EXEC). MAP_FIXED works. |
| `munmap` | 73 | Standard |
| `madvise` | 75 | Most advisories work (not MADV_PROTECT) |
| `mlock` | 203 | Works |
| `sigaction` | 416 | Can set SIG_IGN/SIG_DFL, install handlers |
| `fcntl` | 92 | F_GETFL works; F_SETFL cosmetic only |

### Partially Working / Limited
| Syscall | Notes |
|---------|-------|
| `setsockopt` | Only: TCP_NODELAY, TCP_KEEPINIT, SO_SNDBUF, SO_RCVBUF, SO_RCVLOWAT, SO_LINGER, SO_TIMESTAMP, IP_TTL, IP_MINTTL, IP_HDRINCL, PS5 custom flags |
| `mmap` | RW only — PROT_EXEC always stripped. MAP_FIXED works for page-aligned remapping. |
| `fcntl F_SETFL` | Returns -1 but updates visible flags. **Kernel does NOT honor the flags** (O_NONBLOCK has no effect). Each call REPLACES flags (not OR). |
| `sigaltstack` | Can set alternate stack, but signal delivery to it triggers copyout() validation → EFAULT → process killed |
| `kqueue` | Allocates fd, but `kevent()` always returns -1 |

### Completely Blocked (return -1 or killed)
| Syscall | Number | Notes |
|---------|--------|-------|
| `fork` | 2 | Blocked |
| `rfork` | 251 | Blocked |
| `thr_new` | 455 | Blocked |
| `dup` | 41 | Blocked |
| `dup2` | 90 | Blocked |
| `fstat` | 189 | Blocked |
| `pipe` | 42 | Blocked |
| `pipe2` | 542 | Blocked |
| `ioctl` | 54 | Blocked |
| `sysctl` | 202 | Blocked |
| `mprotect` | 74 | PROT_EXEC always denied |
| `aio_read` | 255 | Sandbox-killed |
| `aio_write` | 256 | Sandbox-killed |
| `aio_return` | 314 | Sandbox-killed |
| `aio_suspend` | 315 | Sandbox-killed |
| `aio_cancel` | 316 | Sandbox-killed |
| `aio_error` | 317 | Returns but does nothing useful |
| `shm_open` | 482 | Crashes loader |
| `sendto` | 133 | Crashes syscall.resolve() |
| `recvfrom` | 29 | Crashes syscall.resolve() |
| `fcntl F_SETOWN` | — | Truly blocked (F_GETOWN stays -1) |
| `sigprocmask` | 340 | No-op: returns 0 but never modifies mask |
| `kevent` | 363 | Always -1 |

### Untested (Potential Targets)
| Syscall | Number | Notes |
|---------|--------|-------|
| `ktimer_create` | 235 | POSIX timers — kernel objects with complex lifecycle |
| `ktimer_settime` | 236 | Timer arming |
| `ktimer_gettime` | 238 | Timer readback |
| `accept` / `accept4` | 30 / 541 | TCP accept path (listen works) |
| `preadv` | 289 | Vectored I/O with offset |
| `pwritev` | 290 | Vectored I/O with offset |
| `copy_file_range` | 580 | File-to-file kernel copy |
| `cap_rights_limit` | 533 | Capsicum capabilities |
| `sctp_*` | various | SCTP protocol |
| `msync` | 226 | Untested — probe 30 crashed before reaching it |
| `minherit` | 250 | Never tested |

## Socket Options Accessible

### SOL_SOCKET (level 0xFFFF) — 23 options
```
0x0001 SO_DEBUG          0x0002 SO_ACCEPTCONN     0x0004 SO_REUSEADDR
0x0008 SO_KEEPALIVE      0x0010 SO_DONTROUTE      0x0020 SO_BROADCAST
0x0080 SO_LINGER         0x0100 SO_OOBINLINE      0x0200 SO_REUSEPORT
0x0400 SO_TIMESTAMP      0x0800 SO_NOSIGPIPE
0x1001 SO_SNDBUF         0x1002 SO_RCVBUF         0x1003 SO_SNDLOWAT
0x1004 SO_RCVLOWAT       0x1005 SO_SNDTIMEO       0x1006 SO_RCVTIMEO
0x1007 SO_ERROR          0x1008 SO_TYPE
0x1011 SO_SETFIB         0x1012 SO_USER_COOKIE    0x1013 SO_TS_CLOCK
```

### PS5 Custom Socket Options (Sony-extended)
```
0x2000   — boolean flag bit in so_options
0x10000  — boolean flag bit
0x20000  — boolean flag bit
0x40000  — boolean flag bit
0x100000 — boolean flag bit
```
All are simple on/off toggles. set(any_nonzero) → readback = option_number. Same behavior on all socket types. **Not exploitable.**

### TCP Level (level 6)
- `TCP_NODELAY` (1) — writable
- `TCP_KEEPINIT` (128) — writable
- `TCP_INFO` (32) — 236 bytes readable, all protocol metadata, no kernel pointers
- `TCP_CONGESTION` (64) — "newreno"

### IP Level (level 0)
- `IP_TTL` (4) — writable (accepts 256, -1)
- `IP_MINTTL` (66) — writable
- `IP_HDRINCL` (2) — writable on RAW sockets (value reads back as 8 = INP_HDRINCL flag)
