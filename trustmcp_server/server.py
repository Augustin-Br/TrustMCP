import os
import json
import tempfile
import yaml
import ssl
import asyncio
import sqlite3
from fastapi import FastAPI
from cryptography.hazmat.primitives import serialization
from spiffe import WorkloadApiClient
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from hypercorn.config import Config
from hypercorn.asyncio import serve

DB_PATH = "/tmp/demo.db" 
POLICY_PATH = "rbac_policy.yaml"

def init_db():
    print("[DB] Initializing SQLite database...", flush=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO users (username, role) VALUES (?, ?)",
            [("alice", "admin"), ("bob", "reader"), ("charlie", "editor")]
        )
        conn.commit()
        print("[DB] Inserted dummy users (alice, bob, charlie).", flush=True)
    conn.close()

def load_rbac_rules():
    if not os.path.exists(POLICY_PATH):
        raise FileNotFoundError(f"Policy file {POLICY_PATH} missing.")
    with open(POLICY_PATH, "r") as f:
        return yaml.safe_load(f) or {}

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
        query = arguments.get('query')
        print(f"[TOOL EXECUTION] Running read_sqlite with query: {query}", flush=True)
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(query)
            columns = [description[0] for description in cursor.description] if cursor.description else []
            rows = cursor.fetchall()
            conn.close()
            result = {"columns": columns, "rows": rows}
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type="text", text=f"SQL Error: {str(e)}")]

    elif name == "drop_table":
        table_name = arguments.get('table_name')
        print(f"[TOOL EXECUTION] Running drop_table on: {table_name}", flush=True)
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
            conn.commit()
            conn.close()
            return [TextContent(type="text", text=f"Table '{table_name}' dropped successfully.")]
        except Exception as e:
            return [TextContent(type="text", text=f"SQL Error: {str(e)}")]
            
    raise ValueError(f"Unknown tool: {name}")

fastapi_app = FastAPI(title="TrustMCP Zero Trust Server")

# --- 3. MASTER ASGI MIDDLEWARE (NO FASTAPI INTERFERENCE) ---
async def app(scope, receive, send):
    if scope["type"] != "http":
        return await fastapi_app(scope, receive, send)

    path = scope.get("path", "")

    # Route 1 : L'ouverture du Tunnel SSE
    if path == "/sse":
        print("[SERVER] New SSE Connection established.", flush=True)
        async with transport.connect_sse(scope, receive, send) as streams:
            await mcp_server.run(streams[0], streams[1], mcp_server.create_initialization_options())
        return

    # Route 2 : La réception des requêtes d'outils
    elif path == "/messages/":
        body = b""
        more_body = True
        messages = []

        while more_body:
            message = await receive()
            messages.append(message)
            body += message.get("body", b"")
            more_body = message.get("more_body", False)

        spiffe_id = "spiffe://blog.local/agent_reader"
        
        payload = None
        try:
            payload = json.loads(body)
        except Exception:
            pass

        if payload and payload.get("method") == "tools/call":
            tool_name = payload.get("params", {}).get("name")
            
            try:
                rbac_rules = load_rbac_rules()
                allowed_tools = rbac_rules.get(spiffe_id) or []
            except Exception as e:
                print(f"[RBAC ERROR] Failed to load {POLICY_PATH}: {e}. FAILING CLOSED.", flush=True)
                allowed_tools = []

            if tool_name not in allowed_tools:
                print(f"[RBAC BLOCK] Access denied: {spiffe_id} attempted to use '{tool_name}'", flush=True)
                # JEDI MIND TRICK : On force une demande invalide
                payload["params"]["name"] = f"UNAUTHORIZED_ACCESS_TO_{tool_name}"
                body = json.dumps(payload).encode("utf-8")
                messages = [{"type": "http.request", "body": body, "more_body": False}]
            else:
                print(f"[RBAC ALLOW] Access granted: {spiffe_id} called '{tool_name}'", flush=True)

        async def new_receive():
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        return await transport.handle_post_message(scope, new_receive, send)

    # Route par défaut (Laisse FastAPI gérer le reste s'il y a d'autres endpoints)
    return await fastapi_app(scope, receive, send)

# --- 4. SERVER STARTUP WITH DYNAMIC SVID ---
async def start_server():
    init_db()
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
    await serve(app, config) # On lance l'application maître !

if __name__ == "__main__":
    asyncio.run(start_server())