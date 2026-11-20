from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class LdapSearchArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="filter",
                type=ParameterType.String,
                description="LDAP filter (e.g. (objectClass=user))",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="attributes",
                type=ParameterType.String,
                description="Comma-separated attributes to return",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("filter", self.command_line.strip())


class LdapSearchCommand(CommandBase):
    cmd = "ldapsearch"
    needs_admin = False
    help_cmd = "ldapsearch <filter> [attributes]"
    description = "LDAP search query (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = LdapSearchArguments
    attackmapping = ["T1087.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        ldap_filter = task.args.get_arg("filter")
        attrs = task.args.get_arg("attributes") or ""
        args = [("string", ldap_filter), ("string", attrs)]
        response = await bof_tasking(task, "nx_ldapsearch.x64.o", coff_arguments=args)
        response.DisplayParams = ldap_filter
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
