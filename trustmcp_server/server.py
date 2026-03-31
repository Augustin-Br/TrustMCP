import os
import json
import tempfile
import yaml
import ssl
import asyncio
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import serialization
from spiffe import WorkloadApiClient
from mcp.server import Server
from mcp.server.fastapi import SseServerTransport
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
transport = SseServerTransport("/messages")

@mcp_server.tool()
async def read_sqlite(query: str) -> str:
    print(f"[TOOL EXECUTION] Running read_sqlite with query: {query}")
    return f"Data successfully read for query: {query}"

@mcp_server.tool()
async def drop_table(table_name: str) -> str:
    print(f"[TOOL EXECUTION] Running drop_table on: {table_name}")
    return f"Table {table_name} dropped successfully."

app = FastAPI(title="TrustMCP Zero Trust Server")

# --- 3. RBAC MIDDLEWARE (Interception) ---
@app.middleware("http")
async def rbac_middleware(request: Request, call_next):
    # MCP tool requests are sent via POST to /messages
    if request.url.path == "/messages" and request.method == "POST":
        # Retrieve client certificate via Hypercorn TLS extension
        tls_info = request.scope.get("extensions", {}).get("tls", {})
        client_cert = tls_info.get("client_cert")
        
        if not client_cert:
            print("[RBAC BLOCK] Missing mTLS certificate.")
            return HTTPException(status_code=403, detail="Missing mTLS certificate")
        
        # In production, extract the SAN (SPIFFE URI) from the loaded cryptography certificate.
        # For this PoC, we mock the extraction assuming it's the reader agent.
        spiffe_id = "spiffe://blog.local/agent_reader"
        
        # Read the JSON-RPC body to identify the requested tool
        body = await request.body()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return await call_next(request)
            
        if payload.get("method") == "tools/call":
            tool_name = payload.get("params", {}).get("name")
            allowed_tools = RBAC_RULES.get(spiffe_id, [])
            
            if tool_name not in allowed_tools:
                print(f"[RBAC BLOCK] Access denied: {spiffe_id} attempted to use '{tool_name}'")
                # Return a formatted JSON-RPC error expected by MCP
                return JSONResponse(content={
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": f"RBAC Denied: {spiffe_id} is not allowed to execute {tool_name}"},
                    "id": payload.get("id")
                }, status_code=200) 
            else:
                print(f"[RBAC ALLOW] Access granted: {spiffe_id} called '{tool_name}'")
                
    response = await call_next(request)
    return response

# --- 4. MCP ENDPOINTS ---
@app.get("/sse")
async def handle_sse(request: Request):
    return await transport.handle_sse(request)

@app.post("/messages")
async def handle_messages(request: Request):
    return await transport.handle_post_message(request)

# --- 5. SERVER STARTUP WITH DYNAMIC SVID ---
async def start_server():
    print("Fetching identity from SPIRE...")
    # Fetch SVID from SPIRE Workload API
    with WorkloadApiClient() as client:
        svid = client.fetch_x509_svid()
        print(f"Successfully fetched server identity: {svid.spiffe_id}")
        
        # Create temporary files for Hypercorn SSL context
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
    
    print("Starting TrustMCP Server on port 8000 with strict mTLS...")
    await serve(app, config)

if __name__ == "__main__":
    asyncio.run(start_server())