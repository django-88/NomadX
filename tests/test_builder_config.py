import base64
import importlib.util
import json
import pathlib

BUILDER_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "nomadx"
    / "mythic"
    / "agent_functions"
    / "builder.py"
)


def load_builder():
    spec = importlib.util.spec_from_file_location("nomadx_builder_test", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_config(module, key=""):
    return json.loads(
        module.generate_agent_config_json(
            uuid="11111111-1111-1111-1111-111111111111",
            aes_key=key,
            callback_host="https://192.0.2.10",
            callback_port=443,
            callback_interval=10,
            callback_jitter=23,
            get_uri="/api/v1.4/agent_message",
            post_uri="/api/v1.4/agent_message",
            user_agent="test-agent",
            kill_date_int=0,
            verify_tls=False,
            proxy_host="",
            proxy_port=0,
        )
    )


def test_zero_key_is_embedded_as_hex():
    config = build_config(load_builder())
    assert config["aes_key_hex"] == "00" * 32
    assert config["tls_verify"] is False
    assert config["callback_port"] == 443


def test_base64_key_is_decoded():
    raw = bytes(range(32))
    config = build_config(load_builder(), base64.b64encode(raw).decode())
    assert config["aes_key_hex"] == raw.hex()


def test_hex_key_is_preserved():
    raw = bytes(range(32))
    config = build_config(load_builder(), raw.hex())
    assert config["aes_key_hex"] == raw.hex()


def test_option_defaults_match_cpp_builder():
    module = load_builder()
    config = build_config(module)
    assert config["alloc_strategy"] == "memory_hole"
    assert config["sacrificial_process"] == ""
    assert config["pre_sleep_seconds"] == 0
    assert config["injection_step_delay_ms"] == 0
    assert config["require_domain_joined"] is False
    assert config["enable_anti_sandbox"] is True
    assert config["enable_computational_delay"] is True
    assert config["enable_anti_emulation"] is True
    assert config["enable_anti_debug"] is False
    assert config["use_direct_syscalls"] is True
    assert config["syscall_mode"] == "indirect"
    assert config["default_injection_technique"] == "none"


def test_string_booleans_are_parsed():
    module = load_builder()
    config = json.loads(
        module.generate_agent_config_json(
            uuid="11111111-1111-1111-1111-111111111111",
            aes_key="",
            callback_host="https://192.0.2.10",
            callback_port=443,
            callback_interval=10,
            callback_jitter=23,
            get_uri="/api/v1.4/agent_message",
            post_uri="/api/v1.4/agent_message",
            user_agent="test-agent",
            kill_date_int=0,
            verify_tls="false",
            proxy_host="",
            proxy_port=0,
            require_domain_joined="true",
            enable_anti_sandbox="false",
            enable_computational_delay="false",
            enable_anti_emulation="false",
            enable_anti_debug="true",
            use_direct_syscalls="false",
        )
    )
    assert config["tls_verify"] is False
    assert config["require_domain_joined"] is True
    assert config["enable_anti_sandbox"] is False
    assert config["enable_computational_delay"] is False
    assert config["enable_anti_emulation"] is False
    assert config["enable_anti_debug"] is True
    assert config["use_direct_syscalls"] is False


def test_config_encryption_roundtrip():
    module = load_builder()
    text = '{"uuid":"11111111-1111-1111-1111-111111111111"}'
    encrypted = module.encrypt_agent_config(text)
    key = module.NX_CONFIG_KEY
    decrypted = bytes(
        byte ^ key[index % len(key)] ^ ((index * 37 + 11) & 0xFF)
        for index, byte in enumerate(encrypted)
    ).decode("utf-8")
    assert decrypted == text
    assert b"uuid" not in encrypted
