from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class RouteprintArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class RouteprintCommand(CommandBase):
    cmd = "routeprint"
    needs_admin = False
    help_cmd = "routeprint"
    description = "Print the routing table (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = RouteprintArguments
    attackmapping = ["T1016"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return await bof_tasking(task, "nx_routeprint.x64.o")

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
