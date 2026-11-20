from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class InjectFiberArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="shellcode",
                type=ParameterType.String,
                description="Base64-encoded shellcode to execute",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("shellcode", self.command_line)


class InjectFiberCommand(CommandBase):
    cmd = "inject_fiber"
    needs_admin = False
    help_cmd = "inject_fiber <base64_shellcode>"
    description = "Execute shellcode in-process via Windows Fiber API (CreateFiberEx). Local execution only - no remote process, no thread creation."
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1055.013"]
    argument_class = InjectFiberArguments

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
