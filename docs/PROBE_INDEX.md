# Probe Index — PS5 14.10

Every probe sent to the PS5, with status and key result.

| # | Name | Status | Key Finding |
|---|------|--------|-------------|
| 01 | `identity` | OK | fw=14.10, pid=355, Lua 5.1 confirmed |
| 02 | `syscall_sweep` | OK | Mapped ~40 working syscalls out of 600+ |
| 03 | `vmmap_layout` | OK | Process memory layout, heap/stack/code ranges |
| 04 | `kernel_surface` | OK | Syscall availability matrix for kernel objects |
| 05 | `file_recon` | OK | Filesystem access: most paths blocked |
| 06 | `bug_hunt` | OK | Initial targeted bug search |
| 07 | `ipv6_leak` | OK | IPv6 socket options, extension header attempts |
| 08 | `read_offsets` | OK | Memory read primitives, offset mapping |
| 09 | `ipv6_stress` | OK | IPv6 stack stress testing |
| 10 | `umtx_stress` | OK | UMTX userland mutex kernel operations |
| 11 | `umtx_race` | PARTIAL | Race condition attempts (no threading = no races) |
| 12 | `nwake_robust` | OK | nwake syscall behavior mapping |
| 13 | `nwake_oracle` | OK | nwake as kernel state oracle |
| 14 | `device_ioctl` | OK | Device ioctl — all blocked by sandbox |
| 15 | `dmem_deep` | OK | Direct memory device deep dive |
| 16 | `dmem_mmap` | CRASH | dmem mmap attempts — crashed |
| 17 | `dmem_kptr` | OK | Searched for kernel pointers in dmem |
| 18 | `dmem_phys` | OK | Physical memory mapping attempts |
| 19 | `aio_stress` | CRASH | AIO stress — all AIO syscalls sandbox-killed |
| 19b | `aio_safe` | OK | Confirmed AIO completely blocked |
| 19c–g | `aio_*` | VARIOUS | Progressive AIO isolation (all dead) |
| 20 | `kqueue_stress` | OK | kqueue fd allocates, kevent blocked |
| 21 | `kqueue_deep` | OK | Deep kqueue — confirmed kevent always -1 |
| 22 | `signal_stress` | OK | Signal handler installation works, SIG_IGN/SIG_DFL ok |
| 23 | `sigalt_exploit` | KILLED | sigaltstack + signal delivery → EFAULT, process killed |
| 24 | `sigalt_kwrite` | KILLED | Kernel write via sigaltstack — copyout() validates dest |
| 25 | `sigalt_safe` | OK | Safe sigaltstack — confirmed completely dead |
| 25b | `sigalt_ign` | OK | SIG_IGN behavior with altstack |
| 25c | `sigprocmask` | OK | **sigprocmask is a no-op** — returns 0, does nothing |
| 26 | `gadget_scan` | CRASH | Code page read → SIGBUS (XOM) |
| 26b | `ret_gadget` | CRASH | RET gadget search — XOM blocks all reads |
| 26c | `wxor_gadget` | OK | Confirmed W^X: mprotect(EXEC) always fails |
| 26d | `find_ret` | CRASH | Another code read attempt — XOM |
| 26e | `code_read` | OK | **Execute-only memory confirmed** — cannot read code pages |
| 26f | `kstack_crash` | CRASH | Kernel stack probe via crash handler |
| 27 | `thread_and_fd` | OK | **Threading fully blocked** — fork/rfork/thr_new all -1. dup/dup2 blocked. fstat blocked. |
| 28 | `ipv6_scmrights` | OK | SCM_RIGHTS works, IPv6 ext headers blocked on send |
| 29 | `rthdr_mmap` | CRASH | IPv6 routing header + mmap — crash (msync or shm_open) |
| 30 | `mmap_fcntl_deep` | CRASH | mmap+fcntl deep — crashed on msync or minherit |
| 30b | `fcntl_scm` | OK | **writev works** (IOV_MAX=1024), **SCM_RIGHTS validated** (5/5 correct), F_SETFL returns -1 but changes flags, pipe2 blocked |
| 30c | `fcntl_bypass` | OK | **F_SETFL is cosmetic only** — flags appear set but kernel ignores them. F_SETOWN truly blocked. poll() works. kqueue fd allocates but kevent -1. |
| 31 | `sockopt_fuzz` | OK | TCP_INFO 236 bytes (no pointers), TCP_CONGESTION="newreno", IP_TTL accepts 256/-1, SO_SNDBUF/RCVBUF accept 1 |
| 31b | `tcpinfo_dump` | OK | Full TCP_INFO hex dump — all protocol metadata, **no kernel pointer leaks**. 23 SOL_SOCKET options accessible. IP_HDRINCL=8 is INP_HDRINCL flag. |
| 31c | `ps5opts_fuzz` | OK | **PS5 custom socket options** (0x2000–0x100000) are boolean flag bits in so_options. Not exploitable. |
| 32 | `bufstress` | HANG | SNDBUF=1 write blocked (F_SETFL nonblock is fake) |
| 32b | `bufstress` | HANG | Same issue — F_SETFL doesn't actually work |
| 32c | `safe_stress` | OK | SETFIB/USER_COOKIE/TS_CLOCK readable but sets blocked. **poll() works perfectly.** SO_TIMESTAMP accepted but no cmsg on UNIX. |
| 32d | `minimal` | RESET | Loader bad state after crashes |
| 32e | `ping` | OK | Minimal ping — loader alive |
| 33a | `sndbuf_step1` | OK | SNDBUF=1 + single write(1) = success (rv=1) |
| 33b | `sndbuf_step2` | HANG | Second write on full SNDBUF=1 buffer blocks (nonblock fake) |
| 33c | `nonblock_test` | HANG | O_NONBLOCK confirmed fake — read blocks on empty socket |
| 33d | `sock_nonblock` | CRASH | SOCK_NONBLOCK (0x20000000) crashes socketpair |
| 33e | `dontwait` | CRASH | **sendto(133)/recvfrom(29) crash syscall.resolve()** |
| 33f | `dontwait_safe` | OK | **MSG_DONTWAIT (0x80) is the real nonblocking mechanism.** recv(empty)=EAGAIN, send works, SNDBUF=1 partial writes correct, 100x rapid cycling clean. |
| 34 | `raw_hdrincl` | OK | **RAW socket + IP_HDRINCL WORKS.** Crafted UDP packet reached listener through kernel ip_input(). TCP SYN dropped (bad checksum). bind/connect on raw socket work. |
| 35 | `frag_fuzz` | FAIL | All 10 fragment tests: no data arrived. Root cause: **listener bind failed** (not fragment-related). |
| 35b | `frag_isolate` | FAIL | Confirmed: bind() returning -1 is the root cause. Even unfragmented UDP fails when bind fails. Need to investigate port restrictions. |
