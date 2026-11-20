from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="File",
                display_name="File",
                type=ParameterType.File,
                description="File from the Mythic file store to upload to the target.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="remote_path",
                cli_name="Path",
                display_name="Remote Path",
                type=ParameterType.String,
                description="Destination path on the target. A directory or trailing slash appends the original filename.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload (modal popup)"
    description = "Upload a file from the Mythic file store to the target host."
    version = 1
    supported_ui_features = ["file_browser:upload"]
    author = "NomadAgent"
    argument_class = UploadArguments
    attackmapping = ["T1105"]

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        file_id = taskData.args.get_arg("file")
        if not file_id:
            raise Exception("No file selected")

        file_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                AgentFileID=file_id,
            )
        )
        if not file_resp.Success or len(file_resp.Files) == 0:
            raise Exception(f"Failed to find uploaded file: {file_resp.Error}")

        file_name = file_resp.Files[0].Filename
        remote_path = taskData.args.get_arg("remote_path") or file_name
        remote_path = remote_path.strip()
        if len(remote_path) >= 2 and remote_path[0] == remote_path[-1] and remote_path[0] in ("'", '"'):
            remote_path = remote_path[1:-1]
        taskData.args.add_arg("file_id", file_id)
        taskData.args.add_arg("file_name", file_name)
        taskData.args.add_arg("remote_path", remote_path)
        response.DisplayParams = f"{file_name} -> {remote_path}"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
