from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class PslistHandlesArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                display_name="PID",
                description="Optional process ID (0 = all processes)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    self.add_arg("pid", int(self.command_line.strip()))
                except ValueError:
                    raise Exception("pslist-handles takes an optional numeric PID")


class PslistHandlesCommand(CommandBase):
    cmd = "pslist-handles"
    needs_admin = False
    help_cmd = "pslist-handles"
    description = "List processes with handle information (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = PslistHandlesArguments
    attackmapping = ["T1057"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        pid = task.args.get_arg("pid")
        if pid is None:
            pid = 0
        return await bof_tasking(
            task, "nx_pslist_handles.x64.o",
            coff_arguments=[("int32", int(pid))],
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
