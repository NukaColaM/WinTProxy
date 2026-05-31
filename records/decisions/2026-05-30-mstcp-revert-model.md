# MSTCP revert model for local relay delivery

**Date**: 2026-05-30

## Context

WinTProxy redirects proxied TCP/UDP traffic to local relay listeners. With WinDivert, this was done by rewriting the packet destination to `127.0.0.1:relay_port`, setting `addr->Loopback=1`, and re-injecting. With ndisapi, loopback traffic never traverses the NDIS stack, so a different mechanism is needed. Two options existed: (A) the MSTCP revert model used by Proxifyre, or (B) extracting payloads and forwarding via userspace sockets.

## Decision

**Use the MSTCP revert model (Option A).** Outgoing client packets are rewritten and sent to the OS TCP/IP stack via `SendPacketsToMstcpUnsorted`, making them appear as locally-delivered packets to the relay listeners. Proxy→client return traffic is caught on the adapter send path and rewritten back.

## Why not alternatives

- **Socket-splice model (Option B)** — rejected because:
  - For TCP, it would require a full userspace TCP stack (lwIP or similar) to handle sequence numbers, ACKs, windowing, and retransmission independently from the kernel. This is thousands of lines of code and would be slower than kernel TCP.
  - For UDP, the performance difference is negligible, but the complexity increase is significant.
  - Option A is validated by Proxifyre in production use.
