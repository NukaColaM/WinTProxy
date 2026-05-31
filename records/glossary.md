# Glossary

## Concepts
| Term | Definition |
|---|---|
| WinDivert | A Windows Filtering Platform (WFP) callout library for packet interception at the IP layer (WINDIVERT_LAYER_NETWORK). Being replaced. |
| ndisapi / WinpkFilter | A Windows NDIS-based packet filtering driver and user-mode API (`ndisapi.dll`) that intercepts packets at the Ethernet layer. Replaces WinDivert. |
| Proxifyre | Reference implementation by Wiresock that uses ndisapi for transparent SOCKS5 proxying. Source: `github.com/wiresock/proxifyre` |
| MSTCP revert model | Packet redirection technique: rewrite an outgoing packet's addresses, then send it to `SendPacketsToMstcpUnsorted` (up the OS TCP/IP stack) instead of to the adapter, making it appear as a locally-delivered packet. Named for the ndisapi `revert` action type. |
| INTERMEDIATE_BUFFER | ndisapi's packet container struct holding an Ethernet frame (`m_IBuffer`) plus metadata: `m_hAdapter` (interface handle), `m_dwDeviceFlags` (ON_SEND/ON_RECEIVE direction), `m_Length`. |
| ON_SEND / ON_RECEIVE | ndisapi direction flags: `PACKET_FLAG_ON_SEND` means the packet is being transmitted by the OS (outbound). `PACKET_FLAG_ON_RECEIVE` means it was received from the network (inbound). |
| MSTCP | Microsoft TCP/IP stack. `SendPacketsToMstcpUnsorted` injects packets upward into the OS network stack as if they arrived from a network interface. |
| Conntrack | WinTProxy's connection tracking subsystem: a fixed-size hash table with SRW locks mapping (src_ip, src_port, dst_ip, dst_port, protocol) → relay state and original tuple for return-path restoration. Unchanged by the migration. |
| Relay (TCP/UDP) | WinTProxy's local loopback listeners that accept proxied connections, perform SOCKS5 handshakes, and relay bytes between the client and the SOCKS5 proxy. Implementation logic is unchanged; only the packet delivery mechanism changes. |
