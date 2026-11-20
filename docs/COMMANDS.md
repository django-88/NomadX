# NomadX command reference

NomadX registers 67 Mythic commands. Most are thin command modules around the
agent dispatcher; BOF-backed commands ship their COFF objects in
`nomadx/bof_files/`.

## Discovery and host information

| Command | Purpose |
| --- | --- |
| `pwd` | Current working directory |
| `ls` | Directory listing |
| `cat` | Read a file |
| `cd` | Change directory |
| `ps` | Process listing |
| `pslist-handles` | Process handle information via BOF |
| `whoami` | Current user and integrity level |
| `whoami_bof` | Whoami BOF |
| `ipconfig` | Network configuration BOF |
| `arp` | ARP table BOF |
| `routeprint` | Routing table BOF |
| `dnscache` | DNS cache BOF |
| `env` | Environment variables BOF |
| `locale` | Locale information BOF |
| `uptime` | System uptime BOF |
| `windowlist` | Top-level windows BOF |
| `wmi-query` | WMI query BOF |
| `net-localgroup` | Local group enumeration BOF |
| `net-user` | Local user enumeration BOF |
| `net-session` | Session enumeration BOF |
| `nslookup` | DNS lookup BOF |
| `ldapsearch` | LDAP query BOF |
| `sysmon-check` | Sysmon presence/configuration check BOF |

## File management

| Command | Purpose |
| --- | --- |
| `cp` | Copy a file |
| `mv` | Move a file |
| `rm` | Delete a file |
| `mkdir` | Create a directory |
| `download` | Download a file from the target to Mythic |
| `upload` | Upload a Mythic file to the target |

## Execution and BOF/COFF

| Command | Purpose |
| --- | --- |
| `shell` | Run a command through `cmd.exe /c` |
| `register_file` | Register a file/COFF in the agent cache |
| `register_coff` | Register a COFF object in the agent cache |
| `execute_coff` | Execute an inline or cached COFF object |
| `execute_pe` | Load an in-memory x64 DLL, call `DllMain`, and optionally an export |
| `screenshot` | Screenshot BOF |
| `clipdump` | Clipboard dump BOF |
| `reg-query` | Registry query BOF |
| `reg-set` | Registry set BOF |
| `reg-delete` | Registry delete BOF |
| `sc-create` | Service create BOF |
| `sc-query` | Service query BOF |
| `sc-start` | Service start BOF |
| `sc-stop` | Service stop BOF |
| `sc-delete` | Service delete BOF |
| `sc-enum` | Service enumeration BOF |
| `sc-qc` | Service config query BOF |
| `sc-qdescription` | Service description query BOF |
| `selfdel` | Self-delete BOF |
| `shutdown` | Shutdown/restart BOF |
| `exit` | Stop the beacon |

## Injection

| Command | Purpose |
| --- | --- |
| `inject` | Generic injection; uses the selected or build-default technique |
| `inject_fiber` | Fiber-based execution |
| `inject_callback` | Callback-based execution (`calendar`, `desktops`, `winstations`, `geoid`) |
| `inject_threadless` | Threadless `NtClose` hook injection |
| `inject_kct` | KernelCallbackTable hijack |
| `inject_poolparty` | Windows thread-pool timer injection |
| `inject_earlycascade` | Early Cascade injection |
| `inject_module_overload` | Module overloading via a sacrificial DLL image |

`inject` accepts a base64 shellcode, an optional PID, an optional technique, and
(for module overload/stomp) an optional DLL path.

## Tokens and privileges

| Command | Purpose |
| --- | --- |
| `getprivs` | List/enable token privileges |
| `steal_token` | Duplicate and impersonate a token from a PID |
| `rev2self` | Revert to the original token |
| `make_token` | Create a token with `LogonUserW` |
| `token_store` | List, use, or remove stored tokens |
| `blockdlls` | Apply Microsoft-signed-only DLL policy |

## Proxy

| Command | Purpose |
| --- | --- |
| `socks` | SOCKS5 relay through Mythic dynamic ports |
| `rportfwd` | Reverse port forward |

## Agent control

| Command | Purpose |
| --- | --- |
| `sleep` | Update callback interval and jitter |
| `exit` | Stop the agent |
| `shutdown` | Shut down or restart the host (BOF) |
