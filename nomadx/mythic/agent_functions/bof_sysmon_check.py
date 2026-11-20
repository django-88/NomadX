from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class SysmonCheckArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class SysmonCheckCommand(CommandBase):
    cmd = "sysmon-check"
    needs_admin = False
    help_cmd = "sysmon-check"
    description = "Check if Sysmon is running and enumerate its configuration (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = SysmonCheckArguments
    attackmapping = ["T1518.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return await bof_tasking(task, "nx_enumsysmon.x64.o")

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
