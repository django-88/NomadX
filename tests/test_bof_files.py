import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOF_DIR = ROOT / "nomadx" / "bof_files"


def bof_references():
    refs = set()
    for path in (ROOT / "nomadx" / "mythic" / "agent_functions").glob("*.py"):
        refs.update(re.findall(r'"([^"]+\.x64\.o)"', path.read_text()))
    return refs


def test_referenced_bof_objects_exist():
    refs = bof_references()
    assert refs, "no BOF references found"
    missing = sorted(name for name in refs if not (BOF_DIR / name).is_file())
    assert not missing, f"missing BOF objects: {missing}"


def test_bof_objects_use_project_prefix():
    names = sorted(path.name for path in BOF_DIR.glob("*.x64.o"))
    assert names
    assert all(name.startswith("nx_") for name in names), names
