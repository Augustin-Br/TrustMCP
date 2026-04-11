# TrustMCP - Zero Trust Model Context Protocol

TrustMCP is a secure implementation of the **MCP (Model Context Protocol)** based on a **Zero Trust** architecture.

This project solves one of the critical flaws in current MCP servers: the lack of granular identity management. By protecting the MCP server with **SPIFFE/SPIRE** and strict **mTLS**, TrustMCP prevents privilege escalation in the event of a *Prompt Injection* attack on an AI Agent.



![TrustMCP Architecture](img/trustmcp_architecture.png)

## Features (Proof of Concept)

- **Cryptographic Identities:** Uses SPIFFE/SPIRE to issue unique and ephemeral certificates (SVIDs) to containers.

- **Strict mTLS:** The MCP server rejects any connection that does not present a valid client certificate signed by the SPIRE authority.

- **RBAC Middleware (Role-Based Access Control):** A pure ASGI proxy intercepts JSON-RPC requests from the MCP protocol. It verifies the client's identity (SPIFFE ID) and strictly blocks the execution of unauthorized tools (e.g., `drop_table`).

- **Asynchronous & Native:** Built with FastAPI, Hypercorn, and the official Python MCP 1.0 SDK (via Server-Sent Events).

## Project Architecture

```text
TrustMCP/
├── infrastructure/               # SPIRE configuration files
│   ├── init-spire.sh             # Workload registration script
│   ├── server.conf               # SPIRE Server configuration
│   └── agent.conf                # SPIRE Agent configuration
├── trustmcp_server/              # Secured MCP Tool Server
│   ├── Dockerfile
│   └── server.py                 # Security core (mTLS + ASGI RBAC proxy)
├── ai_client/                    # AI Agent (Client)
│   ├── Dockerfile
│   └── client.py                 # Patched HTTPX client for mTLS + MCP Client
├── docker-compose.yml            # Infrastructure orchestration
└── README.md
```

## Quickstart

### Prerequisites

- Docker and Docker Compose installed on your machine.

### Step 1: Initialize the Security Authority (SPIRE)

First, start the SPIRE server:

```bash
docker compose up -d spire-server
```

Then, generate the authentication token for the SPIRE agent:

```bash
docker compose exec spire-server /opt/spire/bin/spire-server token generate -spiffeID spiffe://blog.local/agent-poc
```

**Important:** Copy the generated token (`Token: xxxx-xxxx...`) and paste it into the `infrastructure/agent.conf` file at the `join_token = "..."` line.

### Step 2: Start TrustMCP and AI Agent

Build and start the Python containers:

```bash
docker compose up -d --build
```

### Step 3: Register Workloads

Authorize the containers to receive their mTLS certificates:

```bash
chmod +x infrastructure/init-spire.sh
./infrastructure/init-spire.sh
```

### Step 4: Observe the Zero Trust Magic

Restart the Python applications so they fetch their certificates and establish the secure connection:

```bash
docker compose restart trustmcp-server ai-client
```

Watch the live logs:

```bash
docker compose logs -f trustmcp-server ai-client
```

You will see the server **grant access** to the `read_sqlite` tool but **firmly block** the `drop_table` attempt thanks to its RBAC firewall.

## Roadmap

- [ ] Connect a real SQLite database.

- [ ] Externalize RBAC rules into a `policy.yaml` file.

- [ ] Connect the client to a real LLM (OpenAI / Claude / Ollama) via LangChain.

