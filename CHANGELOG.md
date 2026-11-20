# Changelog

## 0.1.0 - 2026-11-20

Initial public NomadX release.

- Zig 0.17.1 Windows x64 agent for Mythic
- HTTP C2 with AES-256-CBC/HMAC-SHA256 and zero-key mode
- EXE, DLL, and donut shellcode delivery
- File management, registry, services, tokens, privileges, and process discovery
- BOF/COFF loader with hash-only Beacon API resolution
- Bundled BOF objects use the project `nx_` prefix
- `execute_pe` in-memory DLL loading
- Fiber, callback, module stomp, module overload, threadless, KCT, Pool Party,
  and Early Cascade injection
- SOCKS5 relay and reverse port forwarding
- `ekko`, `ekko_heap`, `rc4_text`, and `rtl_data` sleep masks
- Direct/indirect syscall stubs with self-test and fallback
- Build-time guardrails, pacing, allocation strategy, sacrificial process, and
  injection selection
- VERSIONINFO metadata, PE checksum, and timestamp normalization
- Encrypted embedded config and hashed lazy Win32/NT import resolution
- Async Mythic build path with pre-warmed Zig cache
