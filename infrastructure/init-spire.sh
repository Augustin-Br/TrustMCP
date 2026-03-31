#!/bin/bash

echo "--- 1. Generating Join Token for Agent ---"
TOKEN=$(docker compose exec spire-server /opt/spire/bin/spire-server token generate -spiffeID spiffe://blog.local/agent-poc | grep "Token:" | awk '{print $2}')

if [ -z "$TOKEN" ]; then
    echo "Error: Could not generate token."
    exit 1
fi

echo "Token generated: $TOKEN"
echo "IMPORTANT: Do not forget to copy this token into infrastructure/agent.conf if not already done, then restart the agent!"

echo "--- 2. Registering Workloads in SPIRE Server ---"

# Registration of TrustMCP Server
docker compose exec spire-server /opt/spire/bin/spire-server entry create \
    -parentID spiffe://blog.local/agent-poc \
    -spiffeID spiffe://blog.local/server \
    -selector docker:label:app:trustmcp_server

# Registration of AI Client (Agent Reader)
docker compose exec spire-server /opt/spire/bin/spire-server entry create \
    -parentID spiffe://blog.local/agent-poc \
    -spiffeID spiffe://blog.local/agent_reader \
    -selector docker:label:app:ai_client

echo "--- Registration Complete ---"