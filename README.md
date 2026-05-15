# WinTProxy

Transparent SOCKS5 proxy for Windows. WinTProxy intercepts IPv4 TCP and UDP traffic with [WinDivert](https://github.com/basil00/WinDivert), plans each packet through explicit DNS, bypass, policy, proxy, return-path, and action-execution stages, then applies a proxy/direct verdict.

## Features

- Explicit verdict/action traffic engine with centralized pass, drop, rewrite/send, DNS-forward, and UDP-relay actions.
- Traffic-stage JSON config: `capture`, `dns`, `bypass`, `policy`, `proxy`, and `logging`.
- Ordered first-match proxy/direct policy rules by process name, IP range, port, and protocol.
- TCP forwarding through SOCKS5 CONNECT.
- UDP forwarding through SOCKS5 UDP ASSOCIATE.
- DNS hijacking for both UDP and TCP DNS before normal policy decisions.
- Fixed-size hot-path tables for connection tracking, DNS NAT, process lookup, and relay state.

## Quick Start

Cross-compile with MinGW from WSL2 or Linux:

```bash
sudo apt install gcc-mingw-w64-x86-64
cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-toolchain.cmake
cmake --build build
```

Place `WinDivert.dll` and `WinDivert64.sys` next to `WinTProxy.exe`, then run from an elevated Windows shell:

```powershell
WinTProxy.exe --config config.example.json
```

## Usage

```text
WinTProxy.exe [options]

Options:
  --config <path>     Path to JSON config file
  --log <path>        Override logging.file from config
  -v, --verbose       Override logging.level (repeat for more: -vv, -vvv, -vvvv)
  --version           Show version
  -h, --help          Show help
```

Traffic behavior belongs in the config file. CLI flags are intentionally limited to bootstrap/logging/help/version.

## Configuration

WinTProxy now uses a traffic-stage schema. Policy decisions are `proxy` or `direct` only; the previous policy-level `block` action has been removed from the traffic model.

See [config.example.json](config.example.json) for an annotated example.

## Documentation

- [Guide](guide.md) — build, configuration, and architecture
- [config.example.json](config.example.json) — annotated traffic-stage config

## License

Third-party components:

- [WinDivert](https://github.com/basil00/WinDivert) - LGPL-3.0
- [cJSON](https://github.com/DaveGamble/cJSON) - MIT
