import os
import json
import tempfile
import yaml
import ssl
import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import serialization
from spiffe import WorkloadApiClient
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from hypercorn.config import Config
from hypercorn.asyncio import serve

# --- 1. RBAC CONFIGURATION ---
RBAC_RULES = yaml.safe_load("""
spiffe://blog.local/agent_reader:
  - read_sqlite
spiffe://blog.local/agent_admin:
  - read_sqlite
  - drop_table
""")

# --- 2. MCP INITIALIZATION ---
mcp_server = Server("TrustMCP")
transport = SseServerTransport("/messages/")

@mcp_server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return [
        Tool(
            name="read_sqlite",
            description="Reads data from SQLite database.",
            inputSchema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
        ),
        Tool(
            name="drop_table",
            description="Drops a table from SQLite database.",
            inputSchema={"type": "object", "properties": {"table_name": {"type": "string"}}, "required": ["table_name"]}
        )
    ]

@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "read_sqlite":
        print(f"[TOOL EXECUTION] Running read_sqlite with query: {arguments.get('query')}", flush=True)
        return [TextContent(type="text", text=f"Data successfully read for query: {arguments.get('query')}")]
    elif name == "drop_table":
        print(f"[TOOL EXECUTION] Running drop_table on: {arguments.get('table_name')}", flush=True)
        return [TextContent(type="text", text=f"Table {arguments.get('table_name')} dropped successfully.")]
    raise ValueError(f"Unknown tool: {name}")

app = FastAPI(title="TrustMCP Zero Trust Server")

# --- 3. MCP ENDPOINTS & RBAC INTERCEPTOR ---

@app.get("/sse")
async def handle_sse(request: Request):
    print("[SERVER] New SSE Connection established.", flush=True)
    async with transport.connect_sse(request.scope, request.receive, request._send) as streams:
        await mcp_server.run(streams[0], streams[1], mcp_server.create_initialization_options())

async def rbac_messages_app(scope, receive, send):
    if scope["type"] != "http":
        return await transport.handle_post_message(scope, receive, send)

    body = b""
    more_body = True
    messages = []

    while more_body:
        message = await receive()
        messages.append(message)
        body += message.get("body", b"")
        more_body = message.get("more_body", False)

    spiffe_id = "spiffe://blog.local/agent_reader"

    try:
        payload = json.loads(body)
        if payload.get("method") == "tools/call":
            tool_name = payload.get("params", {}).get("name")
            allowed_tools = RBAC_RULES.get(spiffe_id, [])

            if tool_name not in allowed_tools:
                print(f"[RBAC BLOCK] Access denied: {spiffe_id} attempted to use '{tool_name}'", flush=True)
                res = JSONResponse(content={
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": f"RBAC Denied: {spiffe_id} is not allowed to execute {tool_name}"},
                    "id": payload.get("id")
                }, status_code=200)
                return await res(scope, receive, send)
            else:
                print(f"[RBAC ALLOW] Access granted: {spiffe_id} called '{tool_name}'", flush=True)
    except Exception as e:
        pass

    async def new_receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    scope["path"] = "/messages/"
    await transport.handle_post_message(scope, new_receive, send)

app.mount("/messages/", rbac_messages_app)

# --- 4. SERVER STARTUP WITH DYNAMIC SVID ---
async def start_server():
    print("Fetching identity from SPIRE...", flush=True)
    with WorkloadApiClient() as client:
        svid = client.fetch_x509_svid()
        print(f"Successfully fetched server identity: {svid.spiffe_id}", flush=True)

        with tempfile.NamedTemporaryFile(delete=False) as cert_file, \
             tempfile.NamedTemporaryFile(delete=False) as key_file, \
             tempfile.NamedTemporaryFile(delete=False) as ca_file:

            cert_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in svid.cert_chain)
            key_pem = svid.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            bundles = client.fetch_x509_bundles()
            ca_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for bundle in bundles.bundles for c in bundle.x509_authorities)

            cert_file.write(cert_pem)
            key_file.write(key_pem)
            ca_file.write(ca_pem)

    config = Config()
    config.bind = ["0.0.0.0:8000"]
    config.certfile = cert_file.name
    config.keyfile = key_file.name
    config.ca_certs = ca_file.name
    config.verify_mode = ssl.CERT_REQUIRED

    print("Starting TrustMCP Server on port 8000 with strict mTLS...", flush=True)
    await serve(app, config)

if __name__ == "__main__":
    asyncio.run(start_server())