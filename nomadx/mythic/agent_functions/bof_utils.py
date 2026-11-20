import struct
import pathlib
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

BOF_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "bof_files"


async def load_bof_from_disk(filename: str) -> bytes:
    """Load a BOF .o file from the bof_files directory."""
    path = BOF_DIR / filename
    if not path.exists():
        raise Exception(f"BOF file not found: {path}")
    return path.read_bytes()


async def bof_tasking(
    task: PTTaskMessageAllData,
    bof_filename: str,
    function_name: str = "go",
    coff_arguments: list = None,
    binary_output: bool = False,
) -> PTTaskCreateTaskingMessageResponse:
    """Build a tasking response that sends inline BOF data to execute_coff."""
    bof_bytes = await load_bof_from_disk(bof_filename)
    bof_hex = bof_bytes.hex()

    # coff_name keeps execute_coff's create_go_tasking from searching with
    # Filename=None when the task is redirected to execute_coff.
    task.args.add_arg("coff_name", bof_filename)
    task.args.add_arg("bof_data", bof_hex, type=ParameterType.String)
    task.args.add_arg("function_name", function_name, type=ParameterType.String)
    if binary_output:
        # The agent base64-encodes the raw BOF output so it survives JSON.
        task.args.add_arg("binary_output", "1")

    packed_args = b''
    packed_size = 0
    if coff_arguments:
        for arg_type, value in coff_arguments:
            if arg_type == "int16":
                packed_args += struct.pack("<h", int(value))
                packed_size += 2
            elif arg_type == "int32":
                packed_args += struct.pack("<i", int(value))
                packed_size += 4
            elif arg_type == "string":
                s = (str(value) + '\x00').encode("utf-8")
                packed_args += struct.pack(f"<L{len(s)}s", len(s), s)
                packed_size += 4 + len(s)
            elif arg_type == "wchar":
                s = (str(value) + '\x00').encode("utf-16_le")
                packed_args += struct.pack(f"<L{len(s)}s", len(s), s)
                packed_size += 4 + len(s)

    final_packed = struct.pack("<L", packed_size) + packed_args
    # Explicit type: coff_arguments is declared as a TypedArray in
    # execute_coff, and without this the container tries to parse the hex blob
    # as "type:value" pairs and drops it.
    task.args.add_arg("coff_arguments", final_packed.hex(),
                      type=ParameterType.String)

    return PTTaskCreateTaskingMessageResponse(
        TaskID=task.Task.ID,
        CommandName="execute_coff",
        TokenID=task.Task.TokenID,
    )
