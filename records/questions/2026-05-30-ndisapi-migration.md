# WinDivert → ndisapi Migration Questions

**Date**: 2026-05-30

## Questions
| # | Question | Answer |
|---|---|---|
| Q1 | What is Proxifyre — do we have source code? | `github.com/wiresock/proxifyre` — full C++ source available. |
| Q2 | Which ndisapi: static lib or DLL? C or C++? | `ndisapi.dll` via its `extern "C"` C API (`github.com/wiresock/ndisapi`). Pure C preserved; no C++ wrapper needed. `Common.h` provides C-compatible structs. |
| Q3 | Loopback/relay path: MSTCP revert model or socket-splice? | **MSTCP revert model** (Proxifyre model). Rewrite outgoing packets → `SendPacketsToMstcpUnsorted` for client→proxy; catch proxy→client responses on adapter send path → rewrite → `SendPacketsToMstcpUnsorted`. Proven in Proxifyre, minimal relay changes. |
| Q4 | Which adapters to filter? Configurable? | **All adapters unconditionally.** No configuration. |
| Q5 | IPv6 support? | **Stay IPv4-only.** IPv6 packets pass through uninspected (same as current). |
| Q6 | I/O threading model: pipeline or simple workers? | **Simple N-worker model** (mirror current). Each worker does batch read→process→send inline. Pipeline model's overlap benefit is below measurement noise for header-rewrite workloads; saves significant complexity. |
| Q7 | WinDivert types: abstraction layer or direct replacement? | **Direct replacement** with ndisapi types. `PWINDIVERT_IPHDR` → `iphdr_ptr`, etc. No typedef aliases — one source of truth. |

## Stories

1. As a user, I want WSL and Hyper-V traffic to be proxied, so that all my system's network traffic is transparently routed through the SOCKS5 proxy. ← Q1, Q4

2. As a developer, I want the packet interception engine to use ndisapi.dll's C API, so that the project stays pure C and the build system remains Mingw-compatible. ← Q2

3. As a developer, I want proxied packets to reach local relay listeners via the OS TCP/IP stack (MSTCP revert), so that the existing TCP/UDP relay subsystems remain unchanged in logic. ← Q3, Q5

4. As a developer, I want the I/O model to use simple multi-worker batch processing, so that packet throughput is maximized without unnecessary pipeline queue complexity. ← Q6

5. As a developer, I want WinDivert-specific types replaced directly with ndisapi types throughout the codebase, so that there is a single source of truth and no mapping indirection for debugging. ← Q7
