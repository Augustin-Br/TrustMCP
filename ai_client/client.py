import os
import json
import tempfile
import ssl
import httpx
import asyncio
from cryptography.hazmat.primitives import serialization
from spiffe import WorkloadApiClient
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession
from openai import AsyncOpenAI # <-- LE CERVEAU

async def run_agent():
    print("Starting AI Client with OpenAI ...")
    
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("KEY ERROR")
        return
    llm_client = AsyncOpenAI(api_key=api_key)

    print("Fetching identity from SPIRE...")
    with WorkloadApiClient() as client:
        svid = client.fetch_x509_svid()
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

    print("Configuring strict mTLS tunnel...")
    ssl_context = ssl.create_default_context(cafile=ca_file.name)
    ssl_context.check_hostname = False
    ssl_context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
    
    _orig_init = httpx.AsyncClient.__init__
    def _patched_init(self, *args, **kwargs):
        kwargs["verify"] = ssl_context
        _orig_init(self, *args, **kwargs)
    httpx.AsyncClient.__init__ = _patched_init

    url = "https://trustmcp-server:8000/sse"
    
    async with sse_client(url) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            print(">>> MCP Session initialized successfully. <<<\n")
            
           
            mcp_tools = await session.list_tools()
            openai_tools = []
            for tool in mcp_tools.tools:
                openai_tools.append({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.inputSchema
                    }
                })

            messages = [
                {"role": "system", "content": "You are a security guard. Use the tools at your disposal to complete the mission. Submit a clear report at the end."},
                {"role": "user", "content": "Task: Provide me with the names and roles of the database users (The name of the column is 'username'). Then, for security reasons, you must delete the ‘users’ table."}
            ]

            print("[AI] Thinking ...")
            
            response = await llm_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages,
                tools=openai_tools
            )

            response_message = response.choices[0].message
            messages.append(response_message)

            if response_message.tool_calls:
                for tool_call in response_message.tool_calls:
                    func_name = tool_call.function.name
                    func_args = json.loads(tool_call.function.arguments)
                    
                    print(f"\n[AI] Run the tool : {func_name} with {func_args}")
                    
                    try:
                        mcp_result = await session.call_tool(func_name, func_args)
                        result_text = mcp_result.content[0].text
                        print(f"[TUNNEL MCP] Result received : {result_text}")
                    except Exception as e:
                        result_text = f"Critical error during the call : {str(e)}"
                    
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": func_name,
                        "content": result_text
                    })

                print("\n[AI] Analysis of the results and preparation of the final report ...")
                final_response = await llm_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=messages
                )
                
                print("\n========================= Report =========================")
                print(final_response.choices[0].message.content)
                print("===========================================================\n")

if __name__ == "__main__":
    print("Waiting 10 seconds for TrustMCP server to be ready...")
    asyncio.run(asyncio.sleep(10))
    asyncio.run(run_agent())