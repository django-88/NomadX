import binascii
import struct
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecuteCoffArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="coff_name",
                cli_name="Coff",
                display_name="Coff",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="COFF to execute (e.g. whoami.x64.o)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    )
                ]),
            CommandParameter(
                name="bof_file",
                display_name="New BOF",
                type=ParameterType.File,
                description="Upload a new BOF to execute.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="New",
                        ui_position=1,
                    )
                ]
            ),
            CommandParameter(
                name="function_name",
                cli_name="Function",
                display_name="Function",
                type=ParameterType.String,
                default_value="go",
                description="Entry function name in the BOF.",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=2),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=2),
                ]),
            CommandParameter(
                name="timeout",
                cli_name="Timeout",
                display_name="Timeout",
                type=ParameterType.Number,
                default_value=30,
                description="Thread timeout in seconds.",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=3),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=3),
                ]),
            CommandParameter(
                name="coff_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.TypedArray,
                default_value=[],
                choices=["int16", "int32", "string", "wchar", "base64"],
                description="Arguments: int16:123, int32:456, string:hello, wchar:hello, base64:abc==",
                typedarray_parse_function=self.get_arguments,
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=4),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=4),
                ]),
        ]

    async def get_arguments(self, arguments: PTRPCTypedArrayParseFunctionMessage) -> PTRPCTypedArrayParseFunctionMessageResponse:
        argumentSplitArray = []
        for argValue in arguments.InputArray:
            for spaceSplitArg in argValue.split(" "):
                argumentSplitArray.append(spaceSplitArg)

        coff_arguments = []
        for argument in argumentSplitArray:
            argType, value = argument.split(":", 1)
            value = value.strip("'").strip('"')
            if argType in ("int16", "-s", "s"):
                coff_arguments.append(["int16", int(value)])
            elif argType in ("int32", "-i", "i"):
                coff_arguments.append(["int32", int(value)])
            elif argType in ("string", "-z", "z"):
                coff_arguments.append(["string", value])
            elif argType in ("wchar", "-Z", "Z"):
                coff_arguments.append(["wchar", value])
            elif argType in ("base64", "-b", "b"):
                coff_arguments.append(["base64", value])
            elif argType == "":
                pass
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(
                    Success=False,
                    Error=f"Unknown argument type: {argType}")

        return PTRPCTypedArrayParseFunctionMessageResponse(Success=True, TypedArray=coff_arguments)

    async def get_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        fileResponse = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback,
            LimitByCallback=False,
            Filename="",
        ))
        if file_resp.Success:
            file_names = []
            for f in file_resp.Files:
                if f.Filename not in file_names and f.Filename.endswith(".o"):
                    file_names.append(f.Filename)
            fileResponse.Success = True
            fileResponse.Choices = file_names
            return fileResponse
        else:
            fileResponse.Error = file_resp.Error
            return fileResponse

    async def parse_arguments(self):
        if self.command_line and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON. Usage: {}".format(ExecuteCoffCommand.help_cmd))


class ExecuteCoffCommand(CommandBase):
    cmd = "execute_coff"
    needs_admin = False
    help_cmd = "execute_coff -Coff [file.o] -Function [go] -Timeout [30] [-Arguments ...]"
    description = "Execute a COFF/BOF file in memory."
    version = 1
    author = "@peter.tamas"
    argument_class = ExecuteCoffArguments
    attackmapping = ["T1559"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows],
        builtin=False,
        load_only=False,
        suggested_command=False,
        dependencies=["register_file"],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        # Forge adds bof_file/coff_arguments without the same group metadata as
        # the native command, so parameter-group resolution can be ambiguous.
        # Do not let that abort tasking; the argument values are authoritative.
        try:
            originalGroupNameIsDefault = taskData.args.get_parameter_group_name() == "Default"
        except Exception:
            originalGroupNameIsDefault = False

        # Forge and the "New" upload group both pass a file ID in bof_file.
        # Do not branch on the parameter group: Forge adds the argument
        # without group metadata, so it can arrive while the group still says
        # "Default".  Treat a present bof_file as authoritative.
        bof_file_id = taskData.args.get_arg("bof_file")
        if bof_file_id:
            fileSearchResp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                AgentFileId=bof_file_id
            ))
            if not fileSearchResp.Success:
                raise Exception(f"Failed to find uploaded file: {fileSearchResp.Error}")
            if len(fileSearchResp.Files) == 0:
                raise Exception("Failed to find matching file.")

            taskData.args.add_arg("coff_name", fileSearchResp.Files[0].Filename)

            # Prefer inline BOF bytes: this avoids a second WinINet round trip
            # (and the 12150/EDR failure mode) and works for Forge, which only
            # passes an AgentFileId.  Keep bof_id as a fallback for very large
            # BOFs or if Mythic returns no content.
            content_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                AgentFileId=bof_file_id
            ))
            if content_resp.Success and content_resp.Content:
                taskData.args.add_arg("bof_data", content_resp.Content.hex(),
                                      type=ParameterType.String)
            else:
                taskData.args.add_arg("bof_id", bof_file_id)
            taskData.args.remove_arg("bof_file")
        else:
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=taskData.args.get_arg("coff_name")
            ))
            if file_resp.Success and len(file_resp.Files) > 0:
                found_id = file_resp.Files[0].AgentFileId
                content_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                    AgentFileId=found_id
                ))
                if content_resp.Success and content_resp.Content:
                    taskData.args.add_arg("bof_data", content_resp.Content.hex(),
                                          type=ParameterType.String)
                else:
                    taskData.args.add_arg("bof_id", found_id)
            else:
                raise Exception("Failed to find file: {}".format(
                    taskData.args.get_arg("coff_name")))

        timeout = taskData.args.get_arg("timeout")
        if timeout is None:
            taskData.args.set_arg("timeout", 30)

        taskargs = taskData.args.get_arg("coff_arguments")

        # bof_tasking() (used by every bof_* wrapper) already packs the
        # arguments itself and passes them as a hex string.  Only re-pack when
        # the operator supplied a real typed-array.
        prepacked = isinstance(taskargs, str)
        if prepacked:
            finalPackedArgs = taskargs if taskargs else "00000000"
            taskargs = []

        argsString = ""
        packedArgsBuffer = b''
        packedArgsSize = 0

        for argEntry in taskargs:
            if not argEntry:
                continue
            if argEntry[0] in ('s', 'int16'):
                argsString += f"-Arguments {argEntry[0]}:{argEntry[1]} "
                packedArgsBuffer += struct.pack("<h", int(argEntry[1]))
                packedArgsSize += struct.calcsize("<h")
            elif argEntry[0] in ('i', 'int32'):
                argsString += f"-Arguments {argEntry[0]}:{argEntry[1]} "
                packedArgsBuffer += struct.pack("<i", int(argEntry[1]))
                packedArgsSize += struct.calcsize("<i")
            elif argEntry[0] in ('z', 'string'):
                argsString += f"-Arguments {argEntry[0]}:\"{argEntry[1]}\" "
                stringVal = (argEntry[1] + '\x00').encode("utf-8")
                packedFormat = f"<L{len(stringVal)}s"
                packedArgsBuffer += struct.pack(packedFormat, len(stringVal), stringVal)
                packedArgsSize += struct.calcsize(packedFormat)
            elif argEntry[0] in ('Z', 'wchar'):
                argsString += f"-Arguments {argEntry[0]}:\"{argEntry[1]}\" "
                stringVal = (argEntry[1] + '\x00').encode("utf-16_le")
                packedFormat = f"<L{len(stringVal)}s"
                packedArgsBuffer += struct.pack(packedFormat, len(stringVal), stringVal)
                packedArgsSize += struct.calcsize(packedFormat)
            else:
                argsString += f"-Arguments {argEntry[0]}:\"{argEntry[1]}\" "
                import base64
                stringVal = base64.b64decode(argEntry[1])
                packedFormat = f"<L{len(stringVal)}s"
                packedArgsBuffer += struct.pack(packedFormat, len(stringVal), stringVal)
                packedArgsSize += struct.calcsize(packedFormat)

        if not prepacked:
            finalPackedArgs = binascii.hexlify(
                struct.pack("<L", packedArgsSize) + packedArgsBuffer
            ).decode('utf-8')

        taskData.args.remove_arg("coff_arguments")
        taskData.args.add_arg("coff_arguments", finalPackedArgs, type=ParameterType.String,
                              parameter_group_info=[
                                  ParameterGroupInfo(required=False, group_name="Default", ui_position=4),
                                  ParameterGroupInfo(required=False, group_name="New", ui_position=4),
                              ])

        if originalGroupNameIsDefault:
            if taskargs:
                response.DisplayParams = "-Coff {} -Function {} -Timeout {} {}".format(
                    taskData.args.get_arg("coff_name"),
                    taskData.args.get_arg("function_name"),
                    taskData.args.get_arg("timeout"),
                    argsString
                )
            else:
                response.DisplayParams = "-Coff {} -Function {} -Timeout {}".format(
                    taskData.args.get_arg("coff_name"),
                    taskData.args.get_arg("function_name"),
                    taskData.args.get_arg("timeout"),
                )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
