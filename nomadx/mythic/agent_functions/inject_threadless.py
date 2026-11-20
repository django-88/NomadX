from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class InjectThreadlessArguments(TaskArguments):
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


class InjectThreadlessCommand(CommandBase):
    cmd = "inject_threadless"
    needs_admin = False
    help_cmd = 'inject_threadless {"shellcode": "<b64>"}'
    description = "Threadless injection via self-restoring NtClose hook. No thread creation - hooks NtClose export in remote process, shellcode triggers on next NtClose call. Hook auto-restores before execution."
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1055.012"]
    argument_class = InjectThreadlessArguments

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
