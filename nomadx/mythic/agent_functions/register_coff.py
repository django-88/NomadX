from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from nomadx.mythic.agent_functions.register_file import RegisterFileCommand, RegisterFileArguments


class RegisterCoffArguments(RegisterFileArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)


class RegisterCoffCommand(CommandBase):
    cmd = "register_coff"
    needs_admin = False
    help_cmd = "register_coff (modal popup)"
    description = "Import a COFF/BOF file into the agent cache for later execution."
    version = 1
    author = "@peter.tamas"
    argument_class = RegisterCoffArguments
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
            AgentFileId=taskData.args.get_arg("file")
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

        # Send the bytes inline so registration does not depend on a second
        # agent-initiated WinINet download (which can fail with 12150 behind
        # EDR/proxies).  The agent accepts file_data as a cache-only path.
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
