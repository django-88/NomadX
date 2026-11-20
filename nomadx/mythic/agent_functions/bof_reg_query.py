from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class RegQueryArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hive",
                type=ParameterType.ChooseOne,
                choices=["HKCR", "HKCU", "HKLM", "HKU"],
                description="Registry hive",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Registry key path",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="key",
                type=ParameterType.String,
                description="Value name (empty for all values)",
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
                if len(parts) >= 2:
                    self.add_arg("hive", parts[0].upper())
                    self.add_arg("path", parts[1])
                if len(parts) >= 3:
                    self.add_arg("key", parts[2])


class RegQueryCommand(CommandBase):
    cmd = "reg-query"
    needs_admin = False
    help_cmd = "reg-query <hive> <path> [value_name]"
    description = "Query registry keys and values (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = RegQueryArguments
    attackmapping = ["T1012"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hive = task.args.get_arg("hive")
        path = task.args.get_arg("path")
        key = task.args.get_arg("key") or ""
        hostname = task.args.get_arg("hostname") or ""
        hive_map = {"HKCR": 0, "HKCU": 1, "HKLM": 2, "HKU": 3}
        args = [
            ("string", hostname),
            ("int32", hive_map.get(hive, 2)),
            ("string", path),
            ("string", key),
            ("int32", 0),
        ]
        response = await bof_tasking(task, "nx_reg_query.x64.o", coff_arguments=args)
        display = f"{hive}\\{path}"
        if key:
            display += f" -> {key}"
        response.DisplayParams = display
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
