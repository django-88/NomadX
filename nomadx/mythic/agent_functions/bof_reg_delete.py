from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class RegDeleteArguments(TaskArguments):
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
                description="Value name to delete",
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


class RegDeleteCommand(CommandBase):
    cmd = "reg-delete"
    needs_admin = False
    help_cmd = "reg-delete"
    description = "Delete a registry value (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = RegDeleteArguments
    attackmapping = ["T1112"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hive = task.args.get_arg("hive")
        path = task.args.get_arg("path")
        key = task.args.get_arg("key")
        hostname = task.args.get_arg("hostname") or ""
        hive_map = {"HKCR": 0, "HKCU": 1, "HKLM": 2, "HKU": 3}
        args = [
            ("string", hostname),
            ("int32", hive_map.get(hive, 2)),
            ("string", path),
            ("string", key),
        ]
        response = await bof_tasking(task, "nx_reg_delete.x64.o", coff_arguments=args)
        response.DisplayParams = f"{hive}\\{path} -> {key}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
