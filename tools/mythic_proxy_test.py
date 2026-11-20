#!/usr/bin/env python3
"""Live Mythic SOCKS5/rportfwd regression test for NomadX."""

from __future__ import annotations

import argparse
import http.server
import pathlib
import subprocess
import sys
import threading

_TOOLS = pathlib.Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from mythic_file_test import create_task, gql, task_output, wait_task


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"nomadx proxy test\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def run(url, token, display_id, command, params, verify_tls, log):
    task_id = create_task(url, token, display_id, command, params, verify_tls)
    task = wait_task(url, token, task_id, verify_tls, timeout=90)
    output = task_output(url, token, task_id, verify_tls)
    print(f"[+] {command:10s} task={task_id} status={task['status']} output={len(output)} bytes")
    log.write(f"\n===== {command} =====\n{output}\n")
    return output


def curl(url, socks_port=None, timeout=20):
    command = ["curl", "-sS", "-m", str(timeout)]
    if socks_port is not None:
        command += ["--socks5-hostname", f"127.0.0.1:{socks_port}"]
    command.append(url)
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 5)
    return result.returncode, result.stdout, result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:7443/graphql/")
    parser.add_argument("--token-file", default="/tmp/mythic_token")
    parser.add_argument("--callback-display-id", type=int, required=True)
    parser.add_argument("--http-port", type=int, default=8091)
    parser.add_argument("--socks-port", type=int, default=7000, help="Must be in Mythic's dynamic port range")
    parser.add_argument("--rpfwd-port", type=int, default=4444)
    parser.add_argument("--remote-ip", required=True, help="Linux host IP reachable from the target")
    parser.add_argument("--target-ip", required=True, help="Target VM IP reachable from this host")
    parser.add_argument("--firewall", action="store_true", help="Add/remove a Windows firewall rule for rpfwd")
    parser.add_argument("--log", default="/tmp/nomadx_proxy_test.log")
    parser.add_argument("--verify-tls", action="store_true")
    args = parser.parse_args()

    token = open(args.token_file, encoding="utf-8").read().strip()
    if not token:
        raise SystemExit(f"empty token file: {args.token_file}")

    query = '''
    query($display_id: Int!) {
      callback(where: {display_id: {_eq: $display_id}}) {
        display_id host user payload { payloadtype { name } }
      }
    }
    '''
    rows = gql(args.url, token, query, {"display_id": args.callback_display_id}, args.verify_tls)["data"]["callback"]
    if not rows:
        raise SystemExit(f"callback {args.callback_display_id} not found")
    callback = rows[0]
    if callback["payload"]["payloadtype"]["name"] != "nomadx":
        raise SystemExit("callback is not nomadx")
    print(f"[*] callback {callback['display_id']} host={callback['host']} user={callback['user']}")

    server = http.server.ThreadingHTTPServer(("0.0.0.0", args.http_port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    test_url = f"http://{args.remote_ip}:{args.http_port}/"
    print(f"[*] test HTTP service on {test_url}")

    checks = {}
    started_socks = False
    started_rpfwd = False
    firewall_added = False
    try:
        with open(args.log, "w", encoding="utf-8") as log:
            def call(command, params=None):
                return run(args.url, token, callback["display_id"], command, params or {}, args.verify_tls, log)

            call("socks", {"port": args.socks_port, "action": "start"})
            started_socks = True
            code, body, error = curl(test_url, socks_port=args.socks_port)
            checks["SOCKS relay"] = code == 0 and "nomadx proxy test" in body
            print(f"[+] SOCKS curl rc={code} body={body.strip()!r} err={error.strip()!r}")

            if args.firewall:
                call("shell", {"command": f'netsh advfirewall firewall delete rule name="nomadx_rpfwd_{args.rpfwd_port}" >nul 2>&1 & netsh advfirewall firewall add rule name="nomadx_rpfwd_{args.rpfwd_port}" dir=in action=allow protocol=TCP localport={args.rpfwd_port}'})
                firewall_added = True

            call(
                "rportfwd",
                {
                    "action": "start",
                    "port": args.rpfwd_port,
                    "remote_ip": args.remote_ip,
                    "remote_port": args.http_port,
                },
            )
            started_rpfwd = True
            code, body, error = curl(f"http://{args.target_ip}:{args.rpfwd_port}/")
            checks["rportfwd relay"] = code == 0 and "nomadx proxy test" in body
            print(f"[+] rportfwd curl rc={code} body={body.strip()!r} err={error.strip()!r}")
    finally:
        with open(args.log, "a", encoding="utf-8") as log:
            if started_rpfwd:
                run(
                    args.url,
                    token,
                    callback["display_id"],
                    "rportfwd",
                    {
                        "action": "stop",
                        "port": args.rpfwd_port,
                        "remote_ip": args.remote_ip,
                        "remote_port": args.http_port,
                    },
                    args.verify_tls,
                    log,
                )
            if firewall_added:
                run(
                    args.url,
                    token,
                    callback["display_id"],
                    "shell",
                    {"command": f'netsh advfirewall firewall delete rule name="nomadx_rpfwd_{args.rpfwd_port}"'},
                    args.verify_tls,
                    log,
                )
            if started_socks:
                run(
                    args.url,
                    token,
                    callback["display_id"],
                    "socks",
                    {"port": args.socks_port, "action": "stop"},
                    args.verify_tls,
                    log,
                )
        server.shutdown()
        server.server_close()

    print("\n[=] proxy summary")
    for name, passed in checks.items():
        print(f"    {'PASS' if passed else 'FAIL'}  {name}")
    overall = all(checks.values())
    print(f"[=] {'PROXY TEST PASSED' if overall else 'PROXY TEST FAILED'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
