#!/usr/bin/env python3
"""Run the NomadX command suite against a live Mythic callback."""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import time
import urllib.request


def gql(url: str, token: str, query: str, variables: dict | None = None, verify_tls: bool = False) -> dict:
    payload = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
        },
    )
    context = None if verify_tls else ssl._create_unverified_context()
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        return json.load(response)


def find_callback(url: str, token: str, display_id: int, verify_tls: bool) -> dict:
    query = """
    query($display_id: Int!) {
      callback(where: {display_id: {_eq: $display_id}}) {
        id
        display_id
        host
        user
        active
        payload { payloadtype { name } }
      }
    }
    """
    callbacks = gql(url, token, query, {"display_id": display_id}, verify_tls)["data"]["callback"]
    if not callbacks:
        raise SystemExit(f"callback display_id {display_id} not found")
    return callbacks[0]


def create_task(url: str, token: str, display_id: int, command: str, params: dict, verify_tls: bool) -> int:
    query = """
    mutation($callback_id: Int, $command: String!, $params: String!) {
      createTask(callback_id: $callback_id, command: $command, params: $params) {
        status
        id
        error
      }
    }
    """
    result = gql(
        url,
        token,
        query,
        {"callback_id": display_id, "command": command, "params": json.dumps(params)},
        verify_tls,
    )["data"]["createTask"]
    if result["status"] != "success":
        raise RuntimeError(f"{command} task creation failed: {result['error']}")
    return result["id"]


def wait_for_task(url: str, token: str, task_id: int, verify_tls: bool, timeout: float = 30.0) -> dict:
    query = """
    query($id: Int!) {
      task_by_pk(id: $id) {
        id
        display_id
        command_name
        status
        completed
      }
    }
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        task = gql(url, token, query, {"id": task_id}, verify_tls)["data"]["task_by_pk"]
        if task and task["completed"]:
            return task
        time.sleep(1)
    raise TimeoutError(f"task {task_id} did not complete within {timeout}s")


def task_output(url: str, token: str, task_id: int, verify_tls: bool) -> str:
    query = """
    query($task_id: Int!) {
      response(where: {task_id: {_eq: $task_id}}, order_by: {id: asc}) {
        response: response_text
        is_error
      }
    }
    """
    rows = gql(url, token, query, {"task_id": task_id}, verify_tls)["data"]["response"]
    chunks: list[str] = []
    for row in rows:
        try:
            chunks.append(base64.b64decode(row["response"]).decode("utf-8", errors="replace"))
        except Exception:
            chunks.append(row["response"])
    return "".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:7443/graphql/")
    parser.add_argument("--token-file", default="/tmp/mythic_token")
    parser.add_argument("--callback-display-id", type=int, required=True)
    parser.add_argument("--log", default="/tmp/nomadx_live_output.log")
    parser.add_argument("--keep-alive", action="store_true", help="Do not send the exit task")
    parser.add_argument("--verify-tls", action="store_true")
    args = parser.parse_args()

    token = open(args.token_file, encoding="utf-8").read().strip()
    if not token:
        raise SystemExit(f"empty token file: {args.token_file}")

    callback = find_callback(args.url, token, args.callback_display_id, args.verify_tls)
    if callback["payload"]["payloadtype"]["name"] != "nomadx":
        raise SystemExit(
            f"callback {args.callback_display_id} is {callback['payload']['payloadtype']['name']}, not nomadx"
        )
    print(f"[*] callback {callback['display_id']} host={callback['host']} user={callback['user']}")

    sequence = [
        ("pwd", {}),
        ("whoami", {}),
        ("shell", {"command": "echo nomadx-mythic"}),
        ("ls", {"path": "C:\\"}),
        ("cat", {"path": "C:\\Windows\\System32\\drivers\\etc\\hosts"}),
        ("cd", {"path": "C:\\Windows"}),
        ("pwd", {}),
        ("ps", {}),
        ("sleep", {"interval": 1, "jitter": 0}),
    ]
    if not args.keep_alive:
        sequence.append(("exit", {}))

    outputs: dict[str, list[str]] = {}
    with open(args.log, "w", encoding="utf-8") as log:
        for command, params in sequence:
            task_id = create_task(
                args.url, token, callback["display_id"], command, params, args.verify_tls
            )
            task = wait_for_task(args.url, token, task_id, args.verify_tls)
            output = task_output(args.url, token, task_id, args.verify_tls)
            outputs.setdefault(command, []).append(output)
            print(f"[+] {command:6s} task={task_id} status={task['status']} output={len(output)} bytes")
            log.write(f"\n===== {command} =====\n{output}\n")

    pwd_outputs = outputs["pwd"]
    checks = {
        "pwd": "\\" in pwd_outputs[0],
        "whoami": "\\" in outputs["whoami"][0],
        "shell": "nomadx-mythic" in outputs["shell"][0],
        "ls": any(name in outputs["ls"][0] for name in ("Windows", "Program Files", "Users")),
        "cat": "localhost" in outputs["cat"][0] or "127.0.0.1" in outputs["cat"][0],
        "cd": "Changed to" in outputs["cd"][0],
        "pwd after cd": len(pwd_outputs) >= 2 and "Windows" in pwd_outputs[-1],
        "ps": bool(outputs["ps"][0]),
        "sleep": "Sleep updated" in outputs["sleep"][0],
    }
    if not args.keep_alive:
        checks["exit"] = "Agent exiting" in outputs["exit"][0]

    print("\n[=] live Mythic summary")
    for name, passed in checks.items():
        print(f"    {'PASS' if passed else 'FAIL'}  {name}")
    overall = all(checks.values())
    print(f"[=] {'LIVE MYTHIC TEST PASSED' if overall else 'LIVE MYTHIC TEST FAILED'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
