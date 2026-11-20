from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class InjectKctArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="shellcode",
                type=ParameterType.String,
                description="Base64-encoded shellcode to inject",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                display_name="PID",
                description="Target PID (0 = spawn the technique default)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class InjectKctCommand(CommandBase):
    cmd = "inject_kct"
    needs_admin = False
    help_cmd = 'inject_kct {"shellcode": "<b64>"}'
    description = "KernelCallbackTable hijack - spawns cttune.exe via CreateProcessW, overwrites __fnCOPYDATA in PEB->KernelCallbackTable with shellcode address, triggers via WM_COPYDATA message."
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1574.013"]
    argument_class = InjectKctArguments

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
