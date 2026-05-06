# Build and Runtime

## Build

Install the MinGW cross-compiler and configure CMake with the supplied toolchain:

```bash
sudo apt install gcc-mingw-w64-x86-64
cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-toolchain.cmake
cmake --build build
```

For a release build:

```bash
cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-toolchain.cmake
cmake --build build-release
```

## Runtime Requirements

- Windows 10 or later, 64-bit.
- Administrator privileges.
- [WinDivert](https://github.com/basil00/WinDivert/releases) 2.x runtime files next to `WinTProxy.exe`:
  - `WinDivert.dll`
  - `WinDivert64.sys`
- A SOCKS5 proxy reachable by IPv4 address.

## Running

```powershell
WinTProxy.exe --config examples\basic.json
WinTProxy.exe --proxy 127.0.0.1:7890 --dns 127.0.0.1:1053 -vv
```

## Notes

- Configuration addresses must be IPv4 literals. Hostnames are not resolved from config fields.
- The application intercepts IPv4 only.
- SOCKS5 authentication is not supported.
- All proxied traffic uses a single SOCKS5 server.
