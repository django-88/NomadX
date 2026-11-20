from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SleepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="interval",
                type=ParameterType.Number,
                description="Sleep interval in seconds",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="jitter",
                type=ParameterType.Number,
                description="Jitter percentage (0-100)",
                default_value=23,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                self.add_arg("interval", int(parts[0]))
                if len(parts) > 1:
                    self.add_arg("jitter", int(parts[1]))


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep <interval> [jitter]"
    description = "Update the agent's sleep interval and jitter percentage"
    version = 1
    author = "NomadAgent"
    attackmapping = []
    argument_class = SleepArguments

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        interval = taskData.args.get_arg("interval")
        jitter = taskData.args.get_arg("jitter")
        response.DisplayParams = f"interval={interval}s jitter={jitter}%"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        sleep_info = response if isinstance(response, str) and response else None
        if sleep_info is None:
            interval = task.args.get_arg("interval")
            jitter = task.args.get_arg("jitter")
            sleep_info = f"{interval}s with {jitter}% jitter"
        await SendMythicRPCCallbackUpdate(
            MythicRPCCallbackUpdateMessage(
                TaskID=task.Task.ID,
                SleepInfo=sleep_info,
            )
        )
        return resp
