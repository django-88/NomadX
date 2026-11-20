#!/usr/bin/env python3
"""Live Mythic BOF/COFF regression test for NomadX."""

from __future__ import annotations

import argparse
import pathlib
import sys

_TOOLS = pathlib.Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from mythic_file_test import create_task, gql, task_output, wait_task


def run(url, token, display_id, command, params, verify_tls, log):
    task_id = create_task(url, token, display_id, command, params, verify_tls)
    task = wait_task(url, token, task_id, verify_tls, timeout=120)
    output = task_output(url, token, task_id, verify_tls)
    print(f"[+] {command:14s} task={task_id} status={task['status']} output={len(output)} bytes")
    log.write(f"\n===== {command} =====\n{output}\n")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:7443/graphql/")
    parser.add_argument("--token-file", default="/tmp/mythic_token")
    parser.add_argument("--callback-display-id", type=int, required=True)
    parser.add_argument("--log", default="/tmp/nomadx_bof_test.log")
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

    checks = {}
    with open(args.log, "w", encoding="utf-8") as log:
        def call(command, params=None):
            return run(args.url, token, callback["display_id"], command, params or {}, args.verify_tls, log)

        whoami = call("whoami_bof")
        checks["whoami_bof"] = "UserName" in whoami or "SID" in whoami or "\\" in whoami

        arp = call("arp")
        checks["arp"] = "Internet Address" in arp or "Interface" in arp or "Inteface" in arp

        nslookup = call("nslookup", {"hostname": "localhost", "server": "", "type": "A"})
        checks["nslookup args"] = "127.0.0.1" in nslookup or "localhost" in nslookup

        env = call("env")
        checks["env"] = env.strip() != "" and ("=" in env or "PATH" in env.upper())

    print("\n[=] BOF/COFF summary")
    for name, passed in checks.items():
        print(f"    {'PASS' if passed else 'FAIL'}  {name}")
    overall = all(checks.values())
    print(f"[=] {'BOF/COFF TEST PASSED' if overall else 'BOF/COFF TEST FAILED'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
