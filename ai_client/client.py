import tempfile
import ssl
import httpx
import asyncio
from cryptography.hazmat.primitives import serialization
from spiffe import WorkloadApiClient
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession

async def run_agent():
    print("Starting AI Client...")
    print("Fetching identity from SPIRE...")
    
    # 1. Fetch SPIFFE identity
    with WorkloadApiClient() as client:
        svid = client.fetch_x509_svid()
        print(f"Successfully fetched agent identity: {svid.spiffe_id}")
        
        bundles = client.fetch_x509_bundles()
        
        with tempfile.NamedTemporaryFile(delete=False) as cert_file, \
             tempfile.NamedTemporaryFile(delete=False) as key_file, \
             tempfile.NamedTemporaryFile(delete=False) as ca_file:
            
            cert_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in svid.cert_chain)
            key_pem = svid.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            ca_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for b in bundles.bundles for c in b.x509_authorities)
            
            cert_file.write(cert_pem)
            key_file.write(key_pem)
            ca_file.write(ca_pem)

    # 2. Configure HTTP mTLS client
    print("Configuring mTLS HTTP client...")
    ssl_context = ssl.create_default_context(cafile=ca_file.name)
    ssl_context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
    
    # 3. Connect to MCP via SSE
    print("Connecting to TrustMCP server...")
    async with httpx.AsyncClient(verify=ssl_context) as http_client:
        url = "https://trustmcp-server:8000/sse"
        
        async with sse_client(url, httpx_client=http_client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("MCP Session initialized successfully.\n")
                
                print(">>> Attempting to call 'read_sqlite' (Should be ALLOWED)")
                try:
                    result = await session.call_tool("read_sqlite", {"query": "SELECT * FROM users"})
                    print(f"Result: {result}\n")
                except Exception as e:
                    print(f"Error: {e}\n")
                
                print(">>> Attempting to call 'drop_table' (Should be DENIED by RBAC)")
                try:
                    result = await session.call_tool("drop_table", {"table_name": "users"})
                    print(f"Result: {result}\n")
                except Exception as e:
                    print(f"Intercepted Error (RBAC): {e}\n")

if __name__ == "__main__":
    # Add a small delay to let the server start and fetch its own certs
    print("Waiting 10 seconds for TrustMCP server to be ready...")
    asyncio.run(asyncio.sleep(10))
    asyncio.run(run_agent())