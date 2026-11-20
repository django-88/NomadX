from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecutePeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pe_name",
                cli_name="PE",
                display_name="PE",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="Cached PE DLL to load",
                parameter_group_info=[ParameterGroupInfo(
                    required=True, group_name="Default", ui_position=1)],
            ),
            CommandParameter(
                name="pe_file",
                display_name="New PE",
                type=ParameterType.File,
                description="Upload a new PE DLL to load.",
                parameter_group_info=[ParameterGroupInfo(
                    required=True, group_name="New", ui_position=1)],
            ),
            CommandParameter(
                name="export",
                cli_name="Export",
                display_name="Export",
                type=ParameterType.String,
                default_value="",
                description="Optional exported function to call after DllMain. Empty = DllMain only.",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=2),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=2),
                ],
            ),
            CommandParameter(
                name="arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                default_value="",
                description="Arguments for the exported function.",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=3),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=3),
                ],
            ),
        ]

    async def get_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        response = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback,
            LimitByCallback=False,
            Filename="",
        ))
        if file_resp.Success:
            names = []
            for f in file_resp.Files:
                if f.Filename.endswith(".dll") and f.Filename not in names:
                    names.append(f.Filename)
            response.Success = True
            response.Choices = names
            return response
        response.Error = file_resp.Error
        return response

    async def parse_arguments(self):
        if self.command_line and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON. Usage: execute_pe -PE <file.dll> [-Export <name>] [-Arguments <args>]")


class ExecutePeCommand(CommandBase):
    cmd = "execute_pe"
    needs_admin = False
    help_cmd = "execute_pe -PE [file.dll] [-Export name] [-Arguments args]"
    description = "Load a PE DLL in memory through module overloading and call its entry point."
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1620"]
    argument_class = ExecutePeArguments
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows],
        builtin=False,
        load_only=False,
        suggested_command=False,
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        group = taskData.args.get_parameter_group_name()

        if group == "New":
            file_id = taskData.args.get_arg("pe_file")
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID, AgentFileID=file_id))
            if not file_resp.Success or len(file_resp.Files) == 0:
                raise Exception("Failed to find uploaded PE file")
            taskData.args.add_arg("file_id", file_resp.Files[0].AgentFileId)
            taskData.args.add_arg("file_name", file_resp.Files[0].Filename)
            taskData.args.remove_arg("pe_file")
        else:
            name = taskData.args.get_arg("pe_name")
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID, Filename=name))
            if not file_resp.Success or len(file_resp.Files) == 0:
                raise Exception(f"Failed to find PE file: {name}")
            taskData.args.add_arg("file_id", file_resp.Files[0].AgentFileId)
            taskData.args.add_arg("file_name", file_resp.Files[0].Filename)

        response.DisplayParams = taskData.args.get_arg("file_name") or taskData.args.get_arg("pe_name")
        export_name = taskData.args.get_arg("export")
        if export_name:
            response.DisplayParams += f" export={export_name}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
