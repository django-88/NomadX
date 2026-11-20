# Contributing

Thanks for considering a contribution. NomadX is a red-team tool; keep all
contributions within authorized, defensive, or research use.

## Development

```bash
zig build
zig build test
python3 -m pytest -q
```

Use Zig 0.17.1. Run `zig fmt` on changed Zig files before opening a pull
request.

For the Mythic payload type:

```bash
export MYTHIC_DIR=/path/to/Mythic
./tools/deploy_mythic.sh
```

Live test suites are in `tools/mythic_*_test.py`; see `SMOKE_TEST.md`.

## Guidelines

- Keep compatibility names unchanged: `NomadEntry`, `DllMain`,
  `DllRegisterServer`, `DllUnregisterServer`, `Beacon*`, Win32/NT names, and
  Mythic command/JSON names.
- Use the existing `nx_` / `Nx` / `NX_` internal naming convention.
- Do not commit live credentials, callback URLs, AES keys, payload binaries,
  crash dumps, or test reports.
- Keep the checked-in `src/agent_config.json` and `src/agent_config.enc` as
  sanitized placeholders only.
- Bundled BOF objects use the `nx_` prefix. If you rename one, update its
  command module and keep `tests/test_bof_files.py` passing.
- Add or update tests for behavior changes.
- Keep the original C++ tree outside this repository; it is not part of this
  project.

## Pull requests

Describe the change, the affected command/build option, and the test coverage.
If the change affects detection characteristics, include a short note in the
PR description. Do not include unauthorized target data.
