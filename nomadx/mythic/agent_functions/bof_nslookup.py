from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class NslookupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                type=ParameterType.String,
                description="Hostname to resolve",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="server",
                type=ParameterType.String,
                description="DNS server to query (empty for default)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="type",
                type=ParameterType.ChooseOne,
                choices=["A", "AAAA", "ANY", "CNAME", "MX", "NS", "SRV", "TXT"],
                default_value="A",
                description="DNS record type",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.strip().split()
                self.add_arg("hostname", parts[0])
                if len(parts) > 1:
                    self.add_arg("server", parts[1])


class NslookupCommand(CommandBase):
    cmd = "nslookup"
    needs_admin = False
    help_cmd = "nslookup <hostname> [dns_server]"
    description = "DNS lookup for a hostname (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = NslookupArguments
    attackmapping = ["T1018"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hostname = task.args.get_arg("hostname")
        server = task.args.get_arg("server") or ""
        record_type = task.args.get_arg("type") or "A"
        type_map = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}
        args = [
            ("string", hostname),
            ("string", server),
            ("int16", type_map.get(record_type, 1)),
        ]
        response = await bof_tasking(task, "nx_nslookup.x64.o", coff_arguments=args)
        response.DisplayParams = f"{hostname} ({record_type})"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
