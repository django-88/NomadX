#!/usr/bin/env python3
"""Minimal Mythic-compatible C2 server for NomadX smoke tests.

It speaks the Nomad/Mythic envelope, queues the basic command set, logs each
response, and prints a pass/fail summary. Use it when you want to validate the
Windows payload without standing up a full Mythic instance.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import pathlib
import sys
import threading
import uuid as uuidlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from gen_config import normalize_key

try:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


KNOWN_KEY = bytes([0x42]) * 32
KNOWN_VECTOR = (
    "MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwERERERERERERERER"
    "EREREQya1hlqwTaFNEePPy630JndAcEgMmZmc6a5QkIysLbMxceeYArz3mxRp3vhu"
    "vbxKlWf1YE7CXC3G8QtW37/Lpmah7Qp8Upkxzw/9sibw3WH"
)
ZERO_VECTOR = (
    "MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAweyJhY3Rpb24iOiJn"
    "ZXRfdGFza2luZyIsInRhc2tpbmdfc2l6ZSI6LTF9"
)


class Envelope:
    def __init__(self, key: bytes):
        self.key = key
        self.zero = not any(key)
        if not self.zero and not HAVE_CRYPTO:
            raise SystemExit("AES smoke tests need: pip install cryptography")

    def decode(self, b64: str) -> tuple[str, dict]:
        raw = base64.b64decode(b64)
        if len(raw) < 36:
            raise ValueError("envelope too short")
        agent_uuid = raw[:36].decode("ascii")
        if self.zero:
            plain = raw[36:]
        else:
            if len(raw) < 36 + 16 + 32 + 16:
                raise ValueError("encrypted envelope too short")
            iv = raw[36:52]
            ciphertext = raw[52:-32]
            received_mac = raw[-32:]
            expected_mac = hmac.new(self.key, raw[36:-32], hashlib.sha256).digest()
            if not hmac.compare_digest(received_mac, expected_mac):
                raise ValueError("HMAC verification failed")
            decryptor = Cipher(algorithms.AES(self.key), modes.CBC(iv)).decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            if not padded:
                raise ValueError("empty plaintext")
            pad_value = padded[-1]
            if pad_value < 1 or pad_value > 16 or padded[-pad_value:] != bytes([pad_value]) * pad_value:
                raise ValueError("invalid PKCS7 padding")
            plain = padded[:-pad_value]
        return agent_uuid, json.loads(plain.decode("utf-8"))

    def encode(self, agent_uuid: str, message: dict) -> str:
        plain = json.dumps(message, separators=(",", ":")).encode("utf-8")
        if self.zero:
            payload = agent_uuid.encode("ascii") + plain
        else:
            iv = os.urandom(16)
            pad_value = 16 - (len(plain) % 16)
            padded = plain + bytes([pad_value]) * pad_value
            encryptor = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
            ciphertext = encryptor.update(padded) + encryptor.finalize()
            mac = hmac.new(self.key, iv + ciphertext, hashlib.sha256).digest()
            payload = agent_uuid.encode("ascii") + iv + ciphertext + mac
        return base64.b64encode(payload).decode("ascii")


def make_task(command: str, parameters: str = "") -> dict:
    return {
        "id": str(uuidlib.uuid4()),
        "command": command,
        "parameters": parameters,
    }


def default_tasks() -> list[dict]:
    return [
        make_task("pwd"),
        make_task("whoami"),
        make_task("shell", json.dumps({"command": "echo nomad-smoke"})),
        make_task("ls", json.dumps({"path": "C:\\"})),
        make_task("cat", json.dumps({"path": "C:\\Windows\\System32\\drivers\\etc\\hosts"})),
        make_task("cd", json.dumps({"path": "C:\\Windows"})),
        make_task("pwd"),
        make_task("ps"),
        make_task("sleep", json.dumps({"interval": 1, "jitter": 0})),
        make_task("exit"),
    ]


class SmokeServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, address, handler, uri: str, envelope: Envelope, tasks: list[dict], expected_uuid: str | None):
        super().__init__(address, handler)
        self.uri = uri
        self.envelope = envelope
        self.tasks = tasks
        self.expected_uuid = expected_uuid
        self.sent_tasking = False
        self.task_by_id = {task["id"]: task for task in tasks}
        self.responses: dict[str, str] = {}
        self.evaluated = False
        self.lock = threading.Lock()

    def next_tasks(self) -> list[dict]:
        with self.lock:
            if self.sent_tasking:
                return []
            self.sent_tasking = True
            return self.tasks

    def handle_responses(self, agent_uuid: str, responses: list[dict]) -> None:
        with self.lock:
            for response in responses:
                task_id = response.get("task_id", "")
                task = self.task_by_id.get(task_id)
                command = task["command"] if task else "<unknown>"
                output = response.get("user_output", "")
                status = response.get("status", "")
                self.responses[task_id] = output
                print(f"[<] {command} status={status} completed={response.get('completed')}:")
                if output:
                    for line in str(output).rstrip("\n").splitlines():
                        print(f"    {line}")
                else:
                    print("    <empty>")
            if not self.evaluated and all(task_id in self.responses for task_id in self.task_by_id):
                self.evaluated = True
                self.evaluate(agent_uuid)

    def evaluate(self, agent_uuid: str) -> None:
        by_command: dict[str, list[str]] = {}
        for task_id, output in self.responses.items():
            command = self.task_by_id[task_id]["command"]
            by_command.setdefault(command, []).append(str(output))

        def first(command: str) -> str:
            values = by_command.get(command, [])
            return values[0] if values else ""

        checks = {
            "check-in UUID": agent_uuid == (self.expected_uuid or agent_uuid),
            "pwd": "\\" in first("pwd"),
            "whoami": "\\" in first("whoami"),
            "shell": "nomad-smoke" in first("shell"),
            "ls": any(name in first("ls") for name in ("Windows", "Program Files", "Users")),
            "cat": bool(first("cat")) and "Failed" not in first("cat"),
            "cd": "Changed to" in first("cd"),
            "pwd after cd": "Windows" in (by_command.get("pwd") or ["", ""])[-1],
            "ps": bool(first("ps")) and "Snapshot failed" not in first("ps"),
            "sleep": "Sleep updated" in first("sleep"),
            "exit": "Agent exiting" in first("exit"),
        }

        print("\n[=] smoke summary")
        for name, passed in checks.items():
            print(f"    {'PASS' if passed else 'FAIL'}  {name}")
        overall = all(checks.values())
        print(f"[=] {'SMOKE TEST PASSED' if overall else 'SMOKE TEST FAILED'}\n")
        threading.Timer(1.0, self.shutdown).start()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: SmokeServer

    def log_message(self, fmt: str, *args) -> None:
        pass

    def do_POST(self) -> None:
        if self.path != self.server.uri:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("ascii")
            agent_uuid, message = self.server.envelope.decode(body)
        except Exception as exc:
            print(f"[!] decode failed: {exc}")
            self.send_error(400, "bad envelope")
            return

        action = message.get("action", "")
        if action == "checkin":
            print("\n[+] check-in")
            for key in ("uuid", "host", "user", "domain", "pid", "integrity_level", "os", "architecture", "ips"):
                if key in message:
                    print(f"    {key}: {message[key]}")
            reply = {"status": "success", "id": agent_uuid}
        elif action == "get_tasking":
            tasks = self.server.next_tasks()
            print(f"[>] get_tasking -> {len(tasks)} task(s)")
            reply = {"tasks": tasks}
        elif action == "post_response":
            print("[<] post_response")
            self.server.handle_responses(agent_uuid, message.get("responses", []))
            reply = {"status": "success"}
        else:
            print(f"[!] unknown action: {action}")
            reply = {"status": "error"}

        data = self.server.envelope.encode(agent_uuid, reply).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True


def self_test() -> int:
    zero = Envelope(b"\x00" * 32)
    agent_uuid, message = zero.decode(ZERO_VECTOR)
    assert agent_uuid == "00000000-0000-0000-0000-000000000000"
    assert message == {"action": "get_tasking", "tasking_size": -1}
    reply = zero.encode(agent_uuid, {"status": "success"})
    _, decoded = zero.decode(reply)
    assert decoded == {"status": "success"}

    encrypted = Envelope(KNOWN_KEY)
    agent_uuid, message = encrypted.decode(KNOWN_VECTOR)
    assert agent_uuid == "00000000-0000-0000-0000-000000000000"
    assert message == {"action": "get_tasking", "tasking_size": -1}
    reply = encrypted.encode(agent_uuid, {"status": "success", "id": agent_uuid})
    _, decoded = encrypted.decode(reply)
    assert decoded == {"status": "success", "id": agent_uuid}
    print("self-test ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--uri", default="/api/v1.4/agent_message")
    parser.add_argument("--key", default="", help="Base64 or 64 hex chars; empty = zero key")
    parser.add_argument("--uuid", default=None, help="Expected payload UUID (optional)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    key = normalize_key(args.key)
    envelope = Envelope(key)
    tasks = default_tasks()
    server = SmokeServer((args.bind, args.port), Handler, args.uri, envelope, tasks, args.uuid)
    mode = "plaintext" if envelope.zero else "AES-256-CBC/HMAC"
    print(f"[*] listening on http://{args.bind}:{args.port}{args.uri} ({mode})")
    print("[*] waiting for check-in; press Ctrl-C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
