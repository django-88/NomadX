from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class ScCreateArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Service name",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="binary_path",
                type=ParameterType.String,
                description="Path to the service binary",
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


class ScCreateCommand(CommandBase):
    cmd = "sc-create"
    needs_admin = True
    help_cmd = "sc-create"
    description = "Create a new service (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = ScCreateArguments
    attackmapping = ["T1543.003"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname") or ""
        service = task.args.get_arg("service_name")
        binary = task.args.get_arg("binary_path")
        args = [("string", hostname), ("string", service), ("string", binary)]
        response = await bof_tasking(task, "nx_sc_create.x64.o", coff_arguments=args)
        response.DisplayParams = f"{service}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


class ScDeleteArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Service name to delete",
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


class ScDeleteCommand(CommandBase):
    cmd = "sc-delete"
    needs_admin = True
    help_cmd = "sc-delete <service_name> [hostname]"
    description = "Delete a service (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = ScDeleteArguments
    attackmapping = ["T1489"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname") or ""
        service = task.args.get_arg("service_name")
        args = [("string", hostname), ("string", service)]
        response = await bof_tasking(task, "nx_sc_delete.x64.o", coff_arguments=args)
        response.DisplayParams = f"{service}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


class ScQcArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Service name",
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


class ScQcCommand(CommandBase):
    cmd = "sc-qc"
    needs_admin = False
    help_cmd = "sc-qc <service_name> [hostname]"
    description = "Query service configuration (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = ScQcArguments
    attackmapping = ["T1007"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname") or ""
        service = task.args.get_arg("service_name")
        args = [("string", hostname), ("string", service)]
        response = await bof_tasking(task, "nx_sc_qc.x64.o", coff_arguments=args)
        response.DisplayParams = f"{service}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


class ScQdescriptionArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Service name",
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


class ScQdescriptionCommand(CommandBase):
    cmd = "sc-qdescription"
    needs_admin = False
    help_cmd = "sc-qdescription <service_name> [hostname]"
    description = "Query service description (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = ScQdescriptionArguments
    attackmapping = ["T1007"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname") or ""
        service = task.args.get_arg("service_name")
        args = [("string", hostname), ("string", service)]
        response = await bof_tasking(task, "nx_sc_qdescription.x64.o", coff_arguments=args)
        response.DisplayParams = f"{service}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
