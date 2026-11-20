from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class MakeTokenArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                default_value="",
                description="Domain (empty = local '.')",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Username",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=3)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split(" ", 1)
            if len(parts) != 2:
                raise Exception("Usage: make_token <domain\\user> <password>")
            user = parts[0]
            if "\\" in user:
                domain, username = user.split("\\", 1)
                self.add_arg("domain", domain)
                self.add_arg("username", username)
            else:
                self.add_arg("username", user)
            self.add_arg("password", parts[1])


class MakeTokenCommand(CommandBase):
    cmd = "make_token"
    needs_admin = False
    help_cmd = "make_token -Domain [domain] -Username [user] -Password [password]"
    description = "Create a new logon session with LogonUserW and impersonate it."
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1134.001"]
    argument_class = MakeTokenArguments

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        domain = taskData.args.get_arg("domain") or "."
        user = taskData.args.get_arg("username") or "?"
        response.DisplayParams = f"{domain}\\{user}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
