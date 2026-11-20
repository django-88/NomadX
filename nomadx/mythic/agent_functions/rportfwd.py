from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RportfwdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="Action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                default_value="start",
                description="Start or stop the reverse port forward listener.",
                parameter_group_info=[ParameterGroupInfo(ui_position=0, required=False)],
            ),
            CommandParameter(
                name="port",
                cli_name="Port",
                display_name="Port",
                type=ParameterType.Number,
                description="Port the agent listens on (target host).",
                parameter_group_info=[ParameterGroupInfo(ui_position=1, required=True)],
            ),
            CommandParameter(
                name="remote_ip",
                cli_name="RemoteIP",
                display_name="Remote IP",
                type=ParameterType.String,
                description="IP Mythic dials for this forward (the service you want to reach).",
                parameter_group_info=[ParameterGroupInfo(ui_position=2, required=True)],
            ),
            CommandParameter(
                name="remote_port",
                cli_name="RemotePort",
                display_name="Remote Port",
                type=ParameterType.Number,
                description="Port Mythic dials for this forward.",
                parameter_group_info=[ParameterGroupInfo(ui_position=3, required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must be passed a port on the command line.")
        try:
            self.load_args_from_json_string(self.command_line)
        except Exception:
            parts = self.command_line.strip().split()
            if len(parts) < 3:
                raise Exception("Expected: rportfwd [port] [remote_ip] [remote_port]")
            self.add_arg("port", int(parts[0]))
            self.add_arg("remote_ip", parts[1])
            self.add_arg("remote_port", int(parts[2]))
            self.add_arg("action", "start")


class RportfwdCommand(CommandBase):
    cmd = "rportfwd"
    needs_admin = False
    help_cmd = "rportfwd -Action {start|stop} -Port [port] -RemoteIP [ip] -RemotePort [port]"
    description = (
        "Listen on a port on the target and relay connections through Mythic "
        "to remote_ip:remote_port."
    )
    version = 1
    author = "NomadAgent"
    attackmapping = ["T1090"]
    argument_class = RportfwdArguments

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        action = taskData.args.get_arg("action")
        port = taskData.args.get_arg("port")
        remote_ip = taskData.args.get_arg("remote_ip")
        remote_port = taskData.args.get_arg("remote_port")
        response.DisplayParams = f"{action} {port} {remote_ip}:{remote_port}"

        if action == "start":
            resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
                TaskID=taskData.Task.ID,
                PortType="rpfwd",
                LocalPort=port,
                RemoteIP=remote_ip,
                RemotePort=remote_port,
            ))
            if not resp.Success:
                raise Exception(f"Failed to start rpfwd proxy: {resp.Error}")
        else:
            resp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                TaskID=taskData.Task.ID,
                PortType="rpfwd",
                Port=port,
            ))
            if not resp.Success:
                raise Exception(f"Failed to stop rpfwd proxy: {resp.Error}")

        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
