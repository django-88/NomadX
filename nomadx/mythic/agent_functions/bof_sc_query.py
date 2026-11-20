from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class ScQueryArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Service name to query",
                parameter_group_info=[ParameterGroupInfo(required=True)],
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
                self.add_arg("service_name", parts[0])
                if len(parts) > 1:
                    self.add_arg("hostname", parts[1])


class ScQueryCommand(CommandBase):
    cmd = "sc-query"
    needs_admin = False
    help_cmd = "sc-query <service_name> [hostname]"
    description = "Query a service's status (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = ScQueryArguments
    attackmapping = ["T1007"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname") or ""
        service = task.args.get_arg("service_name")
        args = [("string", hostname), ("string", service)]
        response = await bof_tasking(task, "nx_sc_query.x64.o", coff_arguments=args)
        response.DisplayParams = f"{service}" + (f" on {hostname}" if hostname else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


class ScEnumArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
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
                self.add_arg("hostname", self.command_line.strip())


class ScEnumCommand(CommandBase):
    cmd = "sc-enum"
    needs_admin = False
    help_cmd = "sc-enum [hostname]"
    description = "Enumerate all services (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = ScEnumArguments
    attackmapping = ["T1007"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname") or ""
        args = [("string", hostname)] if hostname else None
        return await bof_tasking(task, "nx_sc_enum.x64.o", coff_arguments=args)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


class ScStopArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Service name to stop",
                parameter_group_info=[ParameterGroupInfo(required=True)],
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
                self.add_arg("service_name", parts[0])
                if len(parts) > 1:
                    self.add_arg("hostname", parts[1])


class ScStopCommand(CommandBase):
    cmd = "sc-stop"
    needs_admin = False
    help_cmd = "sc-stop <service_name> [hostname]"
    description = "Stop a service (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = ScStopArguments
    attackmapping = ["T1489"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname") or ""
        service = task.args.get_arg("service_name")
        args = [("string", hostname), ("string", service)]
        response = await bof_tasking(task, "nx_sc_stop.x64.o", coff_arguments=args)
        response.DisplayParams = f"{service}" + (f" on {hostname}" if hostname else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


class ScStartArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Service name to start",
                parameter_group_info=[ParameterGroupInfo(required=True)],
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
                self.add_arg("service_name", parts[0])
                if len(parts) > 1:
                    self.add_arg("hostname", parts[1])


class ScStartCommand(CommandBase):
    cmd = "sc-start"
    needs_admin = False
    help_cmd = "sc-start <service_name> [hostname]"
    description = "Start a service (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = ScStartArguments
    attackmapping = ["T1569.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname") or ""
        service = task.args.get_arg("service_name")
        args = [("string", hostname), ("string", service)]
        response = await bof_tasking(task, "nx_sc_start.x64.o", coff_arguments=args)
        response.DisplayParams = f"{service}" + (f" on {hostname}" if hostname else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
