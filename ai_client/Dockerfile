FROM python:3.11-slim

WORKDIR /app

# Install MCP client dependencies
RUN pip install --no-cache-dir spiffe mcp httpx openai

CMD ["python", "client.py"]