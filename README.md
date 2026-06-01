# WinTProxy

Transparent SOCKS5 proxy for Windows. WinTProxy intercepts IPv4 TCP and UDP
traffic with [WinpkFilter](https://github.com/wiresock/ndisapi), plans each
packet through explicit DNS, bypass, policy, proxy, return-path, and
execution stages, then applies a proxy/direct verdict.

## What It Does

- SOCKS5 TCP CONNECT and UDP ASSOCIATE forwarding
- DNS hijacking before normal policy decisions
- Ordered proxy/direct policy rules
- Fixed-size hot-path state for conntrack, DNS NAT, process lookup, and relays
- Explicit plan/execute flow with centralized send routing

## Quick Start

```bash
sudo apt install gcc-mingw-w64-x86-64
cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-toolchain.cmake
cmake --build build
```

Install WinpkFilter, place `ndisapi.dll` next to `WinTProxy.exe`, then run:

```powershell
WinTProxy.exe --config config.example.json
```

## Docs

- [Guide](guide.md)
- [Build](docs/build.md)
- [Run](docs/run.md)
- [Configuration](docs/config.md)
- [Architecture](docs/architecture.md)
- [config.example.json](config.example.json)

## License

Third-party components:

- [WinpkFilter / ndisapi](https://github.com/wiresock/ndisapi) — driver and user-mode DLL
- [cJSON](https://github.com/DaveGamble/cJSON) - MIT
