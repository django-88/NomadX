from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class RegisterFileArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="File",
                display_name="File",
                type=ParameterType.File,
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=1,
                    required=True,
                    group_name="Default"
                )]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob.")
        self.load_args_from_json_string(self.command_line)


class RegisterFileCommand(CommandBase):
    cmd = "register_file"
    needs_admin = False
    help_cmd = "register_file (modal popup)"
    description = "Register a file to later use in the agent (e.g. BOF/COFF files)."
    version = 1
    author = "@peter.tamas"
    argument_class = RegisterFileArguments
    attackmapping = ["T1547"]
    attributes = CommandAttributes(
        builtin=True,
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=taskData.Task.ID,
            AgentFileID=taskData.args.get_arg("file")
        ))
        if file_resp.Success and len(file_resp.Files) > 0:
            original_file_name = file_resp.Files[0].Filename
        else:
            raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(
                taskData.args.get_arg("file")))

        taskData.args.add_arg("file_name", original_file_name,
                              parameter_group_info=[ParameterGroupInfo(group_name="Default")])
        taskData.args.add_arg("file_id", taskData.args.get_arg("file"),
                              parameter_group_info=[ParameterGroupInfo(group_name="Default")])
        content_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=taskData.args.get_arg("file")
        ))
        if content_resp.Success and content_resp.Content:
            taskData.args.add_arg("file_data", content_resp.Content.hex(),
                                  type=ParameterType.String)
        response.DisplayParams = original_file_name

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
