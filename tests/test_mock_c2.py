import importlib.util
import pathlib

MOCK_C2_PATH = (
    pathlib.Path(__file__).resolve().parents[1] / "tools" / "mock_c2.py"
)


def load_mock_c2():
    spec = importlib.util.spec_from_file_location("nomad_mock_c2_test", MOCK_C2_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_envelope_wire_vectors():
    assert load_mock_c2().self_test() == 0
