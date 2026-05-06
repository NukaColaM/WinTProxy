# WinTProxy

Transparent SOCKS5 proxy for Windows. WinTProxy intercepts IPv4 TCP and UDP traffic with [WinDivert](https://github.com/basil00/WinDivert), classifies packets by process and destination, and applies ordered proxy/direct/block rules.

## Features

- Rule-based transparent proxying by process name, IP range, port, and protocol.
- TCP forwarding through SOCKS5 CONNECT.
- UDP forwarding through SOCKS5 UDP ASSOCIATE.
- Optional DNS hijacking to a configured IPv4 resolver.
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
WinTProxy.exe --config examples\basic.json
```

## Usage

```text
WinTProxy.exe [options]

Options:
  --config <path>     Path to JSON config file
  --proxy <addr:port> SOCKS5 proxy address (default: 127.0.0.1:7890)
  --dns <addr:port>   Enable DNS hijacking (redirect to addr:port)
  --log <path>        Write logs to file (in addition to stderr)
  -v, --verbose       Increase verbosity (repeat for more: -vv, -vvv, -vvvv)
  --version           Show version
  -h, --help          Show help
```

Command-line options override config file values.

## Documentation

- [Build and runtime requirements](docs/build-and-runtime.md)
- [Configuration reference](docs/configuration.md)
- [Architecture notes](docs/architecture.md)

Example configurations live in [examples](examples):

- [basic.json](examples/basic.json): practical browser proxying with direct local/private destinations.
- [proxy-all.json](examples/proxy-all.json): proxy every non-private destination.
- [dns-hijack.json](examples/dns-hijack.json): proxy traffic and redirect DNS to a local resolver.

## License

Third-party components:

- [WinDivert](https://github.com/basil00/WinDivert) - LGPL-3.0
- [cJSON](https://github.com/DaveGamble/cJSON) - MIT
