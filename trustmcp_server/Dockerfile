FROM python:3.11-slim

WORKDIR /app

# Install MCP server dependencies
RUN pip install --no-cache-dir spiffe mcp fastapi hypercorn pyyaml

CMD ["python", "server.py"]