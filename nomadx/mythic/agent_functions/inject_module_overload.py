from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class InjectModuleOverloadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
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
                description="Target PID (0 = the agent itself)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="dll",
                type=ParameterType.String,
                display_name="DLL",
                description="Optional DLL to map (default: auto-pick amsi/dbghelp/version/winhttp/cryptsp)",
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


class InjectModuleOverloadCommand(CommandBase):
    cmd = "inject_module_overload"
    needs_admin = False
    help_cmd = "inject_module_overload -Shellcode [base64] [-PID 0] [-DLL path]"
    description = (
        "Module overloading: maps a legitimate DLL file as an image section "
        "(NtCreateSection SEC_IMAGE + NtMapViewOfSection) and executes the "
        "shellcode from the mapped .text, so it lives in file-backed image "
        "memory instead of a private executable allocation."
    )
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1055.012"]
    argument_class = InjectModuleOverloadArguments

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
