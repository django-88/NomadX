#!/usr/bin/env python3
"""Live Mythic file-management regression test for NomadX."""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import time
import urllib.request


def gql(url: str, token: str, query: str, variables: dict | None = None, verify_tls: bool = False) -> dict:
    payload = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    )
    context = None if verify_tls else ssl._create_unverified_context()
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        return json.load(response)


def callback_info(url, token, display_id, verify_tls):
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
    rows = gql(url, token, query, {"display_id": display_id}, verify_tls)["data"]["callback"]
    if not rows:
        raise SystemExit(f"callback {display_id} not found")
    return rows[0]


def create_task(url, token, display_id, command, params, verify_tls):
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
        raise RuntimeError(f"{command}: {result['error']}")
    return result["id"]


def wait_task(url, token, task_id, verify_tls, timeout=60):
    query = """
    query($id: Int!) {
      task_by_pk(id: $id) { id display_id command_name status completed }
    }
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        task = gql(url, token, query, {"id": task_id}, verify_tls)["data"]["task_by_pk"]
        if task and task["completed"]:
            return task
        time.sleep(1)
    raise TimeoutError(f"task {task_id} did not complete")


def task_output(url, token, task_id, verify_tls):
    query = """
    query($task_id: Int!) {
      response(where: {task_id: {_eq: $task_id}}, order_by: {id: asc}) {
        response: response_text
      }
    }
    """
    rows = gql(url, token, query, {"task_id": task_id}, verify_tls)["data"]["response"]
    chunks = []
    for row in rows:
        try:
            chunks.append(base64.b64decode(row["response"]).decode("utf-8", errors="replace"))
        except Exception:
            chunks.append(row["response"])
    return "".join(chunks)


def run(url, token, display_id, command, params, verify_tls, log):
    task_id = create_task(url, token, display_id, command, params, verify_tls)
    task = wait_task(url, token, task_id, verify_tls)
    output = task_output(url, token, task_id, verify_tls)
    print(f"[+] {command:8s} task={task_id} status={task['status']} output={len(output)} bytes")
    log.write(f"\n===== {command} =====\n{output}\n")
    return task_id, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:7443/graphql/")
    parser.add_argument("--token-file", default="/tmp/mythic_token")
    parser.add_argument("--callback-display-id", type=int, required=True)
    parser.add_argument("--base-path", default=r"C:\Users\Public\nomadx_fs")
    parser.add_argument("--log", default="/tmp/nomadx_file_test.log")
    parser.add_argument("--exit", action="store_true", help="Send exit at the end")
    parser.add_argument("--no-cleanup", action="store_true", help="Leave test files on the target")
    parser.add_argument("--multi-chunk-size", type=int, default=0, help="Also test a file of this many bytes")
    parser.add_argument("--verify-tls", action="store_true")
    args = parser.parse_args()

    token = open(args.token_file, encoding="utf-8").read().strip()
    if not token:
        raise SystemExit(f"empty token file: {args.token_file}")

    callback = callback_info(args.url, token, args.callback_display_id, args.verify_tls)
    if callback["payload"]["payloadtype"]["name"] != "nomadx":
        raise SystemExit(f"callback is not nomadx: {callback['payload']['payloadtype']['name']}")
    print(f"[*] callback {callback['display_id']} host={callback['host']} user={callback['user']}")

    base = args.base_path.rstrip("\\/")
    source_path = base + r"\source.txt"
    copy_path = base + r"\copy.txt"
    moved_path = base + r"\moved.txt"
    roundtrip_path = base + r"\roundtrip.txt"

    checks = {}
    with open(args.log, "w", encoding="utf-8") as log:
        def call(command, params):
            return run(args.url, token, callback["display_id"], command, params, args.verify_tls, log)

        _, mkdir_out = call("mkdir", {"path": base})
        checks["mkdir"] = "Created" in mkdir_out or "mkdir failed" in mkdir_out

        call("shell", {"command": f'echo alpha > "{source_path}"'})
        _, source = call("cat", {"path": source_path})
        checks["source file"] = "alpha" in source

        _, cp_out = call("cp", {"source": source_path, "destination": copy_path})
        checks["cp"] = "Copied" in cp_out
        _, copy_data = call("cat", {"path": copy_path})
        checks["cat copy"] = "alpha" in copy_data

        _, mv_out = call("mv", {"source": copy_path, "destination": moved_path})
        checks["mv"] = "Moved" in mv_out
        _, moved_data = call("cat", {"path": moved_path})
        checks["cat moved"] = "alpha" in moved_data

        _, rm_out = call("rm", {"path": source_path})
        checks["rm"] = "Deleted" in rm_out
        _, listing = call("ls", {"path": base})
        checks["ls"] = "moved.txt" in listing and "source.txt" not in listing

        download_task, download_out = call("download", {"path": moved_path})
        checks["download"] = "Downloaded" in download_out
        time.sleep(1)
        query = """
        query($task_id: Int!) {
          filemeta(where: {task_id: {_eq: $task_id}, is_download_from_agent: {_eq: true}}, order_by: {id: desc}, limit: 1) {
            id
            agent_file_id
            filename_text
            size
            complete
            chunks_received
            total_chunks
          }
        }
        """
        files = gql(args.url, token, query, {"task_id": download_task}, args.verify_tls)["data"]["filemeta"]
        checks["download filemeta"] = bool(files) and files[0]["complete"] and files[0]["size"] > 0
        if files:
            file = files[0]
            print(
                f"[+] filemeta id={file['id']} agent_file_id={file['agent_file_id']} "
                f"size={file['size']} chunks={file['chunks_received']}/{file['total_chunks']}"
            )
            _, upload_out = call(
                "upload",
                {"file": file["agent_file_id"], "remote_path": roundtrip_path},
            )
            checks["upload"] = "Uploaded" in upload_out
            _, roundtrip = call("cat", {"path": roundtrip_path})
            checks["round-trip content"] = "alpha" in roundtrip
        else:
            checks["upload"] = False
            checks["round-trip content"] = False

        if args.multi_chunk_size > 0:
            size = args.multi_chunk_size
            large_path = base + r"\big.bin"
            large_rt = base + r"\big_rt.bin"
            create_cmd = (
                f'powershell -NoProfile -Command "$p=\'{large_path}\'; '
                f'$b=New-Object byte[] {size}; [IO.File]::WriteAllBytes($p,$b)"'
            )
            call("shell", {"command": create_cmd})
            large_task, large_out = call("download", {"path": large_path})
            checks["multi-chunk download output"] = "Downloaded" in large_out
            time.sleep(1)
            query = """
            query($task_id: Int!) {
              filemeta(where: {task_id: {_eq: $task_id}, is_download_from_agent: {_eq: true}}, order_by: {id: desc}, limit: 1) {
                agent_file_id
                size
                complete
                chunks_received
                total_chunks
              }
            }
            """
            large_files = gql(args.url, token, query, {"task_id": large_task}, args.verify_tls)["data"]["filemeta"]
            expected_chunks = (size + 511999) // 512000
            if large_files:
                large = large_files[0]
                print(
                    f"[+] large filemeta size={large['size']} chunks={large['chunks_received']}/{large['total_chunks']}"
                )
                checks["multi-chunk download filemeta"] = (
                    large["size"] == size
                    and large["complete"]
                    and large["chunks_received"] == expected_chunks
                    and large["total_chunks"] == expected_chunks
                )
                _, large_upload = call(
                    "upload",
                    {"file": large["agent_file_id"], "remote_path": large_rt},
                )
                checks["multi-chunk upload"] = f"Uploaded {size} bytes" in large_upload
                _, size_check = call(
                    "shell",
                    {"command": f'powershell -NoProfile -Command "(Get-Item \'{large_rt}\').Length"'},
                )
                checks["multi-chunk round-trip size"] = str(size) in size_check
            else:
                checks["multi-chunk download filemeta"] = False
                checks["multi-chunk upload"] = False
                checks["multi-chunk round-trip size"] = False
            if not args.no_cleanup:
                call("rm", {"path": large_path})
                call("rm", {"path": large_rt})

        if not args.no_cleanup:
            call("rm", {"path": moved_path})
            call("rm", {"path": roundtrip_path})

        if args.exit:
            _, exit_out = call("exit", {})
            checks["exit"] = "Agent exiting" in exit_out

    print("\n[=] file-management summary")
    for name, passed in checks.items():
        print(f"    {'PASS' if passed else 'FAIL'}  {name}")
    overall = all(checks.values())
    print(f"[=] {'FILE MANAGEMENT TEST PASSED' if overall else 'FILE MANAGEMENT TEST FAILED'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
