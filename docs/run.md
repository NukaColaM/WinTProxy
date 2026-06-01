# Run

## Runtime Requirements

- Windows 10 or later, 64-bit.
- [WinpkFilter / ndisapi](https://github.com/wiresock/ndisapi/releases) runtime DLL next to `WinTProxy.exe`:
  - `ndisapi.dll`
- WinpkFilter driver installed. Use the release installer so driver signing and service setup are handled for you.
- A SOCKS5 proxy reachable by IPv4 address.

## Usage

```powershell
WinTProxy.exe --config config.example.json
WinTProxy.exe --config config.example.json -vv
WinTProxy.exe --config config.example.json --log wintproxy.log
```

```text
WinTProxy.exe [options]

Options:
  --config <path>     Path to JSON config file
  --log <path>        Override logging.file from config
  -v, --verbose       Override logging.level (-v=info, -vv=debug, -vvv=trace; -vvvv also clamps to trace)
  --version           Show version
  -h, --help          Show help
```

Traffic behavior lives in JSON. CLI flags only cover bootstrap, logging, help, and version. The former traffic override flags were removed so runtime behavior has one source of truth.

## Startup Order

WinTProxy initializes stateful subsystems before interception starts:

```text
Winsock -> Config -> Conntrack -> Process lookup -> DNS hijack -> TCP relay -> UDP relay -> ndisapi engine
```

Shutdown reverses ownership-sensitive services so relay traffic is closed before packet interception is stopped.
