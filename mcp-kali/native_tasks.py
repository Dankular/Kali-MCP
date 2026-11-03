"""MCP 2025-11-25 task bridge for the pinned SDK; backed by durable job storage.

Portable kali_submit/job_* tools remain available for clients without Tasks.
This does not advertise the separate draft io.modelcontextprotocol/tasks extension.
"""
from datetime import datetime, timezone
import json

import anyio
from mcp import types
from mcp.shared.exceptions import McpError
import runtime


def task_data(job):
    return dict(taskId=job["id"], status="working" if job["state"] in ("queued", "running") else job["state"],
                statusMessage=job["error"] or job["progress"],
                createdAt=datetime.fromtimestamp(job["created"], timezone.utc),
                lastUpdatedAt=datetime.fromtimestamp(job["updated"], timezone.utc),
                ttl=int((job["expires"]-job["created"])*1000), pollInterval=1000)


async def lookup(token, include_result=False):
    try:
        return await anyio.to_thread.run_sync(runtime.job_status, token, include_result)
    except ValueError as exc:
        raise McpError(types.ErrorData(code=types.INVALID_PARAMS, message=str(exc))) from exc


def install(mcp, submit):
    low = mcp._mcp_server
    original_call = low.request_handlers[types.CallToolRequest]
    original_list = low.request_handlers[types.ListToolsRequest]

    async def list_tools(request):
        response = await original_list(request)
        for tool in response.root.tools:
            if tool.name == "kali_run":
                tool.execution = types.ToolExecution(taskSupport="optional")
        return response

    async def call_tool(request):
        if request.params.task is None:
            return await original_call(request)
        if request.params.name != "kali_run":
            raise McpError(types.ErrorData(code=types.INVALID_PARAMS, message="Task augmentation is supported for kali_run only"))
        try:
            # Validate against the exact same schema used by ordinary kali_run.
            tool = mcp._tool_manager.get_tool("kali_run")
            arguments = tool.fn_metadata.arg_model.model_validate(request.params.arguments or {}).model_dump()
            job = await anyio.to_thread.run_sync(lambda: submit(**arguments))
        except (ValueError, TypeError) as exc:
            raise McpError(types.ErrorData(code=types.INVALID_PARAMS, message=str(exc))) from exc
        return types.ServerResult(types.CreateTaskResult(task=types.Task(**task_data(job))))

    low.request_handlers[types.CallToolRequest] = call_tool
    low.request_handlers[types.ListToolsRequest] = list_tools

    @low.experimental.get_task()
    async def get_task(request: types.GetTaskRequest):
        return types.GetTaskResult(**task_data(await lookup(request.params.taskId)))

    @low.experimental.cancel_task()
    async def cancel_task(request: types.CancelTaskRequest):
        await lookup(request.params.taskId)
        await anyio.to_thread.run_sync(runtime.cancel_job, request.params.taskId)
        # The 2025 protocol expects a terminal cancelled state before acknowledgement.
        with anyio.fail_after(90):
            while True:
                job = await lookup(request.params.taskId)
                if job["state"] in runtime.TERMINAL:
                    return types.CancelTaskResult(**task_data(job))
                await anyio.sleep(0.2)

    @low.experimental.get_task_result()
    async def result(request: types.GetTaskPayloadRequest):
        while True:
            job = await lookup(request.params.taskId, True)
            if job["state"] in runtime.TERMINAL:
                failed = job["state"] != "completed"
                data = job["result"] if not failed else {"error": job["error"] or job["state"]}
                response = types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(data))],
                                                structuredContent=data, isError=failed)
                return types.GetTaskPayloadResult(**response.model_dump(by_alias=True))
            await anyio.sleep(0.3)
