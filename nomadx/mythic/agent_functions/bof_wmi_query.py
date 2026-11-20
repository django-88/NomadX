from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class WmiQueryArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="query",
                type=ParameterType.String,
                description="WMI query (e.g. SELECT * FROM Win32_Process)",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Remote hostname (empty for local)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="namespace",
                type=ParameterType.String,
                description="WMI namespace",
                default_value="root\\cimv2",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("query", self.command_line.strip())


class WmiQueryCommand(CommandBase):
    cmd = "wmi-query"
    needs_admin = False
    help_cmd = "wmi-query <WQL query> [hostname]"
    description = "Execute a WMI query (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = WmiQueryArguments
    attackmapping = ["T1047"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        query = task.args.get_arg("query")
        hostname = task.args.get_arg("hostname") or ""
        namespace = task.args.get_arg("namespace") or "root\\cimv2"
        args = [("string", hostname), ("string", namespace), ("string", query)]
        response = await bof_tasking(task, "nx_wmi_query.x64.o", coff_arguments=args)
        response.DisplayParams = query
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
