"""Public Streamable HTTP transport for the existing MCP tools."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
import fnmatch
import json
import anyio
import runtime
import provider
import checks

from starlette.responses import JSONResponse, Response
import uvicorn
from server import mcp, kali_run


def allowed(request):
    settings = mcp.settings.transport_security
    host = request.headers.get("host", "")
    origin = request.headers.get("origin")
    return any(fnmatch.fnmatchcase(host, pattern) for pattern in settings.allowed_hosts) and (
        origin is None or any(fnmatch.fnmatchcase(origin, pattern) for pattern in settings.allowed_origins))


@mcp.custom_route("/artifacts/{artifact_id}", methods=["GET"])
async def download(request):
    if not allowed(request):
        return Response(status_code=403)
    try:
        info, data = await anyio.to_thread.run_sync(runtime.read_artifact, request.path_params["artifact_id"])
    except ValueError:
        return Response(status_code=404)
    # A fixed filename avoids reflecting untrusted tool-generated names into headers.
    return Response(data, media_type="application/octet-stream", headers={
        "Content-Disposition": 'attachment; filename="artifact.bin"',
        "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer", "X-Artifact-SHA256": info["sha256"]})


@mcp.custom_route("/healthz", methods=["GET"])
async def readiness(request):
    if not allowed(request):
        return Response(status_code=403)
    info = await anyio.to_thread.run_sync(checks.health)
    return JSONResponse({"status": info["status"], "queue": info["queue"], "image_id": info["image_id"]},
                        status_code=200 if info["status"] == "ready" else 503)

class RequestBodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        length = headers.get(b"content-length", b"0")
        try:
            oversized = int(length) > 131072
        except ValueError:
            oversized = True
        if oversized:
            return await JSONResponse({"error": "request_too_large"}, status_code=413)(scope, receive, send)
        # Bound streamed bodies too, before starting any tool execution.
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 131072:
                return await JSONResponse({"error": "request_too_large"}, status_code=413)(scope, receive, send)
            if not message.get("more_body", False):
                break
        delivered = False

        async def buffered_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, buffered_receive, send)


def create_app():
    app = mcp.streamable_http_app()
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        stop, threads = await anyio.to_thread.run_sync(
            runtime.start_workers, {"run": kali_run.__wrapped__, "selftest": checks.run_suite}, provider.reap_orphans)
        try:
            async with original_lifespan(application):
                yield
        finally:
            stop.set()
            # Existing background work finishes before process shutdown, within the service stop budget.
            def join():
                import time
                deadline = time.monotonic() + 620
                for thread in threads:
                    thread.join(max(0, deadline - time.monotonic()))
            await anyio.to_thread.run_sync(join)

    app.router.lifespan_context = lifespan
    return RequestBodyLimit(app)


if __name__ == "__main__":
    app = create_app()
    uvicorn.run(app, host=os.environ.get("MCP_KALI_HTTP_HOST", "0.0.0.0"),
                port=int(os.environ.get("MCP_KALI_HTTP_PORT", "9443")),
                ssl_certfile=os.environ["MCP_KALI_TLS_CERT"],
                ssl_keyfile=os.environ["MCP_KALI_TLS_KEY"],
                timeout_graceful_shutdown=650, limit_concurrency=64,
                proxy_headers=False, log_level="info")
