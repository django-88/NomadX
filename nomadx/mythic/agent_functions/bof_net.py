from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class NetLocalGroupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="group_name",
                type=ParameterType.String,
                description="Local group name (empty to list all groups)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Remote hostname (empty for local)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                self.add_arg("group_name", parts[0])
                if len(parts) > 1:
                    self.add_arg("hostname", parts[1])


class NetLocalGroupCommand(CommandBase):
    cmd = "net-localgroup"
    needs_admin = False
    help_cmd = "net-localgroup [group_name] [hostname]"
    description = "List local groups or members of a group (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = NetLocalGroupArguments
    attackmapping = ["T1069.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        group = task.args.get_arg("group_name") or ""
        hostname = task.args.get_arg("hostname") or ""
        args = [("string", hostname), ("string", group)]
        response = await bof_tasking(task, "nx_netlocalgroup.x64.o", coff_arguments=args)
        if group:
            response.DisplayParams = f"{group}" + (f" on {hostname}" if hostname else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


class NetSessionArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Target hostname",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("hostname", self.command_line.strip())


class NetSessionCommand(CommandBase):
    cmd = "net-session"
    needs_admin = False
    help_cmd = "net-session <hostname>"
    description = "Enumerate sessions on a remote host (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = NetSessionArguments
    attackmapping = ["T1049"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname")
        args = [("string", hostname)]
        response = await bof_tasking(task, "nx_get-netsession.x64.o", coff_arguments=args)
        response.DisplayParams = hostname
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


class NetUserArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Username to query (empty to list all)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Remote hostname (empty for local)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                self.add_arg("username", parts[0])
                if len(parts) > 1:
                    self.add_arg("hostname", parts[1])


class NetUserCommand(CommandBase):
    cmd = "net-user"
    needs_admin = False
    help_cmd = "net-user [username] [hostname]"
    description = "List users or query user details (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = NetUserArguments
    attackmapping = ["T1087.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        username = task.args.get_arg("username") or ""
        hostname = task.args.get_arg("hostname") or ""
        args = [("string", hostname), ("string", username)]
        response = await bof_tasking(task, "nx_netuser.x64.o", coff_arguments=args)
        if username:
            response.DisplayParams = f"{username}" + (f" on {hostname}" if hostname else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
