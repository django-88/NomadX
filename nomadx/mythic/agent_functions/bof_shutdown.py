from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class ShutdownArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Target hostname (empty for local)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="reboot",
                type=ParameterType.Boolean,
                description="Reboot instead of shutdown",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("hostname", self.command_line.strip())


class ShutdownCommand(CommandBase):
    cmd = "shutdown"
    needs_admin = True
    help_cmd = "shutdown [hostname]"
    description = "Shutdown or reboot a system (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = ShutdownArguments
    attackmapping = ["T1529"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname") or ""
        reboot = task.args.get_arg("reboot") or False
        args = []
        if hostname:
            args.append(("string", hostname))
        args.append(("int32", 1 if reboot else 0))
        response = await bof_tasking(task, "nx_shutdown.x64.o", coff_arguments=args if args else None)
        response.DisplayParams = f"{'reboot' if reboot else 'shutdown'} {hostname or 'localhost'}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
