# Architecture

NomadX is split into a small Mythic payload-type container and a native Windows
agent.

## Mythic side

```text
Mythic UI / GraphQL
        |
        v
nomadx payload container (Python)
  - builder.py: stamps config, runs zig build, packages artifacts
  - command modules: task parameter validation and response processing
  - BOF modules: command wrappers around shipped COFF objects
        |
        v
HTTP C2 profile
```

`builder.py` copies `build.zig` and `src/`, stamps `src/agent_config.enc`, runs
the Zig build with the selected injection switches and optional VERSIONINFO
resource, normalizes the PE, and returns `nomadx.exe`, `nomadx.dll`, or donut
shellcode.

## Agent side

```text
wWinMain / DllMain / NomadEntry
        |
        v
guardrails -> config decrypt -> HTTP endpoint
        |
        v
check-in -> sleep -> get_tasking -> dispatch -> post_response
        |
        +-- commands (files, tokens, recon, proxy, execution)
        +-- COFF loader
        +-- injection engine
        +-- execute_pe
        +-- sleep mask
```

The EXE and DLL share the same beacon loop. DLL builds export:

- `NomadEntry`
- `DllRegisterServer`
- `DllUnregisterServer`
- `DllMain`

The shellcode build wraps the DLL with the custom donut converter and uses
`NomadEntry` so the module remains mapped while the beacon is running.

## Crypto and config

- Embedded config: encrypted blob in `src/agent_config.enc`
- Wire crypto: AES-256-CBC with HMAC-SHA256, matching Mythic's envelope
- Zero-key mode: plaintext UUID-prefixed payload for local testing
- AES key material is not stored as plaintext in the built payload

## API resolution and syscalls

The PE import table contains only KERNEL32 and UCRT. `src/api.zig` resolves
other APIs lazily:

1. walk the module export table
2. hash each export name
3. match a 32-bit module/function hash
4. cache the resolved pointer

`src/syscalls.zig` builds direct or indirect Nt* stubs in private executable
memory:

- direct: `mov r10, rcx; mov eax, SSN; syscall; ret`
- indirect: same, but jumps to an ntdll `syscall; ret` gadget
- startup self-test: allocate, write, protect, free
- fallback: normal ntdll/Win32 calls if the self-test fails

## Sleep masks

`src/sleep.zig` implements:

- `ekko` / `rc4_text`: whole-image RC4 with thread quiescing
- `ekko_heap`: whole-image plus non-default heap-block RC4
- `rtl_data`: `RtlEncryptMemory` on data sections

The mask is selected at build time and embedded in the encrypted config.

## COFF loader

`src/coff.zig` is a native-x64 COFF loader. Beacon BOF APIs are resolved by hash
rather than by plaintext name. External BOF imports are resolved through the
normal loader path, including `__imp_lib$func` symbols and common BOF libraries.

## Hardening boundaries

NomadX reduces obvious static indicators, but it is not a packer and does not
claim to be undetectable. Runtime behavior, memory scanning, ETW/AMSI, and EDR
telemetry can still observe the agent. See the operational notes in the main
README.
