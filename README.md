<div align="center">

# NetKit MCP

**One pure-Go MCP server that lets an AI agent speak HTTP, GraphQL, gRPC, WebSocket, Socket.IO, SOAP, MQTT, AMQP, Kafka, NATS, STOMP, CoAP, SFTP, FTP, tus, S3, DNS, raw TCP/UDP and TLS, plus the auth those protocols use.**

[![CI](https://github.com/HamedFathi/NetKitMCP/actions/workflows/ci.yml/badge.svg)](https://github.com/HamedFathi/NetKitMCP/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/HamedFathi/NetKitMCP?sort=semver)](https://github.com/HamedFathi/NetKitMCP/releases)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8?logo=go)](go.mod)
[![MCP](https://img.shields.io/badge/MCP-2026--07--28-6E56CF)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

NetKit MCP is a [Model Context Protocol](https://modelcontextprotocol.io) server with **67 tools** for calling, testing and debugging network services from Claude, or any other MCP client. It's a protocol toolkit, not a Postman clone: there are no collections, environments or scripting. The model does the sequencing, and NetKit does the networking safely.

- **One static binary.** It's pure Go, built with `CGO_ENABLED=0`, and needs no `curl`, `protoc`, `ssh`, browser or system libraries. It never spawns a process.
- **Safe by default.** An SSRF guard runs on every connection of every protocol. File access is limited to directories you allow, size and time limits all have ceilings, and secrets are redacted.
- **Files never pass through the model.** Uploads stream from disk and downloads stream to disk, and both report size and SHA-256.
- **Bounded streaming.** Each stateful protocol has a one-shot tool that collects messages for N messages or T seconds and returns. Interactive sessions are available when you need them.
- **Tested end to end.** Every tool is tested through an in-memory MCP client against real in-process servers (gRPC, NATS, MQTT, Kafka, SFTP, tus, CoAP, HTTP/3, ...), with no internet needed.

---

## Contents

- [Quick start](#quick-start)
- [Installation](#installation)
- [Connecting an MCP client](#connecting-an-mcp-client)
- [Tool groups](#tool-groups)
- [How the tools behave](#how-the-tools-behave)
- [Examples](#examples)
- [Authentication](#authentication)
- [Working with files](#working-with-files)
- [Security model](#security-model)
- [Configuration](#configuration)
- [Common options](#common-options)
- [Tool reference](#tool-reference)
- [Remote (HTTP) deployment](#remote-http-deployment)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [Upgrading and uninstalling](#upgrading-and-uninstalling)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Quick start

1. **Install.** Download the archive for your platform from the [latest release](https://github.com/HamedFathi/NetKitMCP/releases/latest), extract it and put `netkit-mcp` on your `PATH`. Other options are under [Installation](#installation).
2. **Create the folders** NetKit may read from and write to. The server refuses to start if they're missing.

   Linux and macOS:
   ```bash
   mkdir -p ~/netkit/in ~/netkit/out
   ```
   Windows (PowerShell):
   ```powershell
   New-Item -ItemType Directory -Force "$HOME\netkit\in", "$HOME\netkit\out"
   ```
3. **Register it** with your MCP client. For Claude Code:

   Linux and macOS:
   ```bash
   claude mcp add netkit -- netkit-mcp --allow-read-dir ~/netkit/in --allow-write-dir ~/netkit/out
   ```
   Windows (PowerShell):
   ```powershell
   claude mcp add netkit -- netkit-mcp --allow-read-dir "$HOME\netkit\in" --allow-write-dir "$HOME\netkit\out"
   ```
   Then run `claude mcp list`; netkit should show as connected. If it doesn't, see [Troubleshooting](#troubleshooting).
4. **Ask your agent** things like:

   > *"Introspect the GraphQL API at https://countries.trevorblades.com and list all continents."*
   >
   > *"Describe the gRPC services on grpc.example.com:443 via reflection and call the health check."*
   >
   > *"Subscribe to `sensors/#` on mqtt://broker.example.com for 20 seconds and summarise the readings."*
   >
   > *"Check the TLS certificate of example.com: who issued it and when does it expire?"*
   >
   > *"Upload ~/netkit/in/report.pdf to this presigned S3 URL and confirm the checksum."*
   >
   > *"Here's a curl command from the API docs; run it and explain the response."*

Want everything? Add `--groups all`. See [Tool groups](#tool-groups).

---

## Installation

### Pre-built binaries (recommended)

Every [release](https://github.com/HamedFathi/NetKitMCP/releases) has static binaries; there is nothing else to install:

| OS | x86-64 (`amd64`) | ARM64 (`arm64`) |
|---|---|---|
| Linux | `netkit-mcp_1.0.0_linux_amd64.tar.gz` | `netkit-mcp_1.0.0_linux_arm64.tar.gz` |
| macOS | `netkit-mcp_1.0.0_darwin_amd64.tar.gz` | `netkit-mcp_1.0.0_darwin_arm64.tar.gz` (Apple silicon) |
| Windows | `netkit-mcp_1.0.0_windows_amd64.zip` | `netkit-mcp_1.0.0_windows_arm64.zip` |

**Linux and macOS:**

```bash
VERSION=1.0.0
OS=$(uname -s | tr '[:upper:]' '[:lower:]')                       # linux or darwin
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')         # amd64 or arm64
curl -fsSLO "https://github.com/HamedFathi/NetKitMCP/releases/download/v${VERSION}/netkit-mcp_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "netkit-mcp_${VERSION}_${OS}_${ARCH}.tar.gz"
sudo install -m 755 netkit-mcp /usr/local/bin/netkit-mcp            # or move it anywhere on your PATH
netkit-mcp --version
```

> On macOS, a binary downloaded with a browser may be quarantined by Gatekeeper. Clear the flag once with `xattr -d com.apple.quarantine /usr/local/bin/netkit-mcp`.

**Windows (PowerShell):**

```powershell
$v = "1.0.0"
Invoke-WebRequest "https://github.com/HamedFathi/NetKitMCP/releases/download/v$v/netkit-mcp_${v}_windows_amd64.zip" -OutFile netkit.zip
Expand-Archive netkit.zip -DestinationPath "$env:LOCALAPPDATA\netkit-mcp" -Force
# Add the folder to your user PATH (open a new terminal afterwards):
[Environment]::SetEnvironmentVariable("Path", "$([Environment]::GetEnvironmentVariable('Path','User'));$env:LOCALAPPDATA\netkit-mcp", "User")
netkit-mcp --version
```

**Verify the download** against `checksums.txt` from the same release:

```bash
sha256sum --ignore-missing -c checksums.txt          # Linux
shasum -a 256 --ignore-missing -c checksums.txt      # macOS
```
```powershell
(Get-FileHash .\netkit-mcp_1.0.0_windows_amd64.zip -Algorithm SHA256).Hash   # compare with checksums.txt
```

### With Go

```bash
go install github.com/HamedFathi/NetKitMCP@latest
```

This needs Go 1.27 or newer. Go names the binary after the module, so it's installed as `NetKitMCP` in `$(go env GOPATH)/bin`. Rename it to `netkit-mcp` if you want the commands in this README to work unchanged.

### Docker

A distroless, non-root image is published for `linux/amd64` and `linux/arm64`:

```bash
docker run -i --rm \
  -v "$PWD/in:/data/in:ro" -v "$PWD/out:/data/out" \
  ghcr.io/hamedfathi/netkitmcp:1.0.0
```

The image is preconfigured to read from `/data/in` and write to `/data/out`; mount your folders there. With `-i` it speaks MCP over stdio. For HTTP, see [Remote deployment](#remote-http-deployment).

### From source

```bash
git clone https://github.com/HamedFathi/NetKitMCP.git
cd NetKitMCP
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o netkit-mcp .
./netkit-mcp --version
```

---

## Connecting an MCP client

NetKit speaks MCP over **stdio** (the default) or **stateless streamable HTTP**. Current clients negotiate protocol revision `2026-07-28`; older clients get `2025-11-25` or earlier.

> **Paths in client configs.** Clients start the server directly, without a shell, so nothing expands `~`, `$HOME` or `%USERPROFILE%` for you (PowerShell doesn't expand `~` in arguments to programs either). NetKit expands a leading `~` in `--allow-read-dir` and `--allow-write-dir` itself, so `~/netkit/in` works everywhere. Any other path, including the path to the binary, must be absolute. Use the full path to the binary if it isn't on the `PATH` the client sees.

<details open>
<summary><b>Claude Code</b></summary>

Linux and macOS:

```bash
# this project only
claude mcp add netkit -- netkit-mcp --allow-read-dir ~/netkit/in --allow-write-dir ~/netkit/out

# every project, with all tool groups
claude mcp add --scope user netkit -- netkit-mcp --groups all \
  --allow-read-dir ~/netkit/in --allow-write-dir ~/netkit/out

claude mcp list        # check that it's connected
```

Windows (PowerShell):

```powershell
# this project only
claude mcp add netkit -- netkit-mcp --allow-read-dir "$HOME\netkit\in" --allow-write-dir "$HOME\netkit\out"

# every project, with all tool groups
claude mcp add --scope user netkit -- netkit-mcp --groups all `
  --allow-read-dir "$HOME\netkit\in" --allow-write-dir "$HOME\netkit\out"

claude mcp list        # check that it's connected
```

`claude mcp get netkit` shows the exact arguments that were saved. To change them, run `claude mcp remove netkit` (add `-s user` for a user-scoped server) and add it again.

Inside a session, `/mcp` shows the server and its tools.
</details>

<details>
<summary><b>Claude Desktop</b></summary>

Open **Settings → Developer → Edit Config** and add this to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "netkit": {
      "command": "/usr/local/bin/netkit-mcp",
      "args": [
        "--allow-read-dir", "/Users/you/netkit/in",
        "--allow-write-dir", "/Users/you/netkit/out"
      ]
    }
  }
}
```

On Windows, use the full path to `netkit-mcp.exe` and escape backslashes:

```json
{
  "mcpServers": {
    "netkit": {
      "command": "C:\\Users\\you\\AppData\\Local\\netkit-mcp\\netkit-mcp.exe",
      "args": [
        "--allow-read-dir", "C:\\Users\\you\\netkit\\in",
        "--allow-write-dir", "C:\\Users\\you\\netkit\\out"
      ]
    }
  }
}
```

Restart Claude Desktop after editing the file.
</details>

<details>
<summary><b>VS Code (GitHub Copilot agent mode)</b></summary>

Create `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "netkit": {
      "type": "stdio",
      "command": "netkit-mcp",
      "args": ["--groups", "http,grpc,ws", "--allow-write-dir", "${workspaceFolder}/.netkit"]
    }
  }
}
```
</details>

<details>
<summary><b>Cursor, Windsurf and other clients</b></summary>

Any client that can launch a stdio MCP server works. Most use the same `mcpServers` JSON shape as Claude Desktop: set `command` to the binary and `args` to the flags you want. For Cursor, that's `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per project).
</details>

<details>
<summary><b>Docker as a stdio server</b></summary>

```json
{
  "mcpServers": {
    "netkit": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "-v", "/Users/you/netkit/in:/data/in:ro",
               "-v", "/Users/you/netkit/out:/data/out",
               "ghcr.io/hamedfathi/netkitmcp:1.0.0", "--groups", "all"]
    }
  }
}
```

The container runs on Docker's network, so `localhost` inside it is the container, not your machine. Use `host.docker.internal` (Docker Desktop) to reach services on your host, and set `allow_private=true` on the call, because that address is private.
</details>

<details>
<summary><b>A remote NetKit over HTTP</b></summary>

Clients that support remote MCP servers connect to `https://your-host/mcp` with the header `Authorization: Bearer <token>`. See [Remote deployment](#remote-http-deployment). For Claude Code:

```bash
claude mcp add --transport http netkit https://your-host/mcp --header "Authorization: Bearer <token>"
```
</details>

---

## Tool groups

67 tools, in groups you can switch on and off. Every tool's schema costs the model context, so only the groups you need are registered. The **default** set (43 tools) is `http`, `grpc`, `ws`, `soap`, `auth` and `mqtt`.

```bash
netkit-mcp                                       # default groups
netkit-mcp --groups default,transfer,lowlevel    # defaults plus extras
netkit-mcp --groups http,mcp                     # only these groups
netkit-mcp --groups all                          # all 67 tools
```

| Group | Default | Tools | Covers |
|---|:---:|:---:|---|
| `http` | ✅ | 12 | HTTP/1.1/2/3, forms, multipart, uploads, GraphQL, JSON-RPC, XML-RPC, SSE, web-to-Markdown, curl import |
| `grpc` | ✅ | 10 | gRPC (unary, all streaming modes, sessions, health), gRPC-Web, Connect |
| `ws` | ✅ | 11 | WebSocket and Socket.IO, one-shot and interactive |
| `soap` | ✅ | 2 | WSDL 1.1 discovery and SOAP 1.1/1.2 calls with WS-Security |
| `auth` | ✅ | 5 | OAuth2 token, authorization-code + PKCE, and device flows |
| `mqtt` | ✅ | 2 | MQTT 3.1.1 and 5 |
| `messaging` | | 10 (+2) | AMQP 0-9-1, Kafka, NATS, STOMP, CoAP; also turns on `mqtt` |
| `transfer` | | 8 | SFTP, FTP/FTPS, tus resumable uploads, S3 multipart |
| `lowlevel` | | 4 | Raw TCP, UDP, DNS (UDP/TCP/DoT/DoH), TLS inspection |
| `mcp` | | 2 | Call tools on other (remote) MCP servers |

`netkit_info` is always registered. It returns the version, enabled groups, allowed directories, network policy and limits, so the agent can check what it may do before trying.

| Group | Tools |
|---|---|
| `http` | `http_request`, `http_form_request`, `http_multipart_request`, `http_upload`, `graphql_request`, `graphql_introspect`, `graphql_subscribe`, `jsonrpc_request`, `xmlrpc_request`, `sse_listen`, `fetch_web`, `curl_to_request` |
| `grpc` | `grpc_describe`, `grpc_unary_request`, `grpc_stream_request`, `grpc_stream_open`, `grpc_stream_send`, `grpc_stream_recv`, `grpc_stream_close`, `grpc_health_check`, `grpcweb_request`, `connect_request` |
| `ws` | `ws_exchange`, `ws_connect`, `ws_send`, `ws_receive`, `ws_close`, `ws_list`, `sio_exchange`, `sio_connect`, `sio_emit`, `sio_receive`, `sio_close` |
| `soap` | `soap_describe`, `soap_request` |
| `auth` | `oauth2_get_token`, `oauth2_auth_url`, `oauth2_exchange_code`, `oauth2_device_start`, `oauth2_device_poll` |
| `mqtt` | `mqtt_publish`, `mqtt_subscribe` |
| `messaging` | `amqp_publish`, `amqp_consume`, `kafka_produce`, `kafka_consume`, `nats_publish`, `nats_request`, `nats_subscribe`, `stomp_send`, `stomp_subscribe`, `coap_request` |
| `transfer` | `sftp_upload`, `sftp_download`, `sftp_list`, `ftp_upload`, `ftp_download`, `ftp_list`, `tus_upload`, `s3_multipart_upload` |
| `lowlevel` | `tcp_request`, `udp_request`, `dns_query`, `tls_inspect` |
| `mcp` | `mcp_client_list_tools`, `mcp_client_call_tool` |

Every argument of every tool is listed in the [Tool reference](#tool-reference).

---

## How the tools behave

### One-shot vs. sessions

Every stateful protocol has a **one-shot** tool: `ws_exchange`, `sio_exchange`, `grpc_stream_request`, `graphql_subscribe`, `sse_listen`, `mqtt_subscribe`, `kafka_consume` and the rest. It connects, sends what you give it, collects incoming messages until a limit fires, then closes and returns everything at once. One-shot tools are the most reliable choice for an LLM and they work behind load balancers. Prefer them.

The limits are `max_messages` (default 100), `max_duration_seconds` (default 10) and `idle_timeout_seconds` (stop after this much silence; off by default). Some tools add their own stop conditions, such as `stop_on` for WebSocket and `stop_data: "[DONE]"` for SSE.

**Interactive sessions** (`ws_connect`, `sio_connect`, `grpc_stream_open`) return a `session_id` that later calls use to send and receive. A background reader buffers incoming messages in a bounded ring buffer (1,000 messages; the oldest are dropped and counted in `dropped`). Sessions live in the server's memory, close after 10 minutes idle, and are capped at 64. `ws_list` shows the open ones.

### Results

Results are structured JSON in three shapes.

**HTTP-like** (`http_*`, GraphQL, JSON/XML-RPC, SOAP, `fetch_web`, ...)

```json
{ "status": 200, "status_text": "OK", "headers": {}, "body": "…", "body_encoding": "text",
  "content_type": "application/json", "saved_to": null, "final_url": "…", "protocol": "HTTP/2.0",
  "timing_ms": { "dns": 1.2, "connect": 8.4, "tls": 21.0, "ttfb": 54.3, "total": 60.1 },
  "tls": { "version": "TLS 1.3", "cipher": "…", "peer_cn": "…" }, "size_bytes": 512, "truncated": false }
```

**Message streams** (WebSocket, Socket.IO, SSE, MQTT, gRPC streams, brokers)

```json
{ "messages": [ { "seq": 1, "dir": "in", "ts": "2026-11-10T15:32:03.488Z", "type": "text",
                  "event": "", "data": "…", "encoding": "text" } ],
  "ended_by": "max_messages", "close": { "code": 1000, "reason": "" }, "truncated": false }
```

`ended_by` says why collection stopped:

| Value | Meaning |
|---|---|
| `max_messages` | the message limit was reached |
| `max_duration` | the time limit was reached (or the receive wait expired) |
| `idle` | no message arrived for `idle_timeout_seconds` |
| `peer_closed` | the server closed the connection or stream |
| `stop_event` | a stop condition (`stop_on`, `stop_event`, `stop_data`, ...) matched |
| `complete` | the protocol signalled completion (e.g. a GraphQL subscription completed) |
| `drained` | a receive returned the buffered messages without waiting |
| `error` | the stream failed; see `error` |

**Transfers** (uploads and downloads)

```json
{ "file": { "name": "report.pdf", "size_bytes": 1048576, "sha256": "…", "content_type": "application/pdf" },
  "bytes_transferred": 1048576, "resumed_from": 0, "parts": 1,
  "timing_ms": { "total": 812.5 }, "remote": { "status": 201, "location": "…", "etag": "…" } }
```

### Errors vs. results

- **Remote protocol errors are results.** An HTTP 500, a non-OK gRPC status, a SOAP fault, GraphQL `errors`, a JSON-RPC error object or an XML-RPC fault comes back as a normal result the agent can read and reason about.
- **Tool errors** (`isError: true`) mean the call itself couldn't run: invalid arguments, a blocked target, a file outside the allowed directories, a timeout, a refused connection. The message says how to fix it, e.g. *"set allow_private=true"* or *"use save_to"*.
- **Binary data** is returned base64-encoded with `"encoding": "base64"`. Large bodies are truncated at `max_response_bytes` with `"truncated": true`; use `save_to` to download them to disk instead.

---

## Examples

These are tool arguments as the agent sends them. You normally just ask in plain language and the agent fills them in; the examples show what's possible and are handy when you want to be specific.

### HTTP

```jsonc
// http_request: GET with headers and query parameters
{ "url": "https://api.github.com/repos/golang/go", "headers": { "Accept": "application/vnd.github+json" } }

// http_request: POST JSON with a bearer token
{ "method": "POST", "url": "https://api.example.com/v1/items",
  "json": { "name": "widget", "qty": 3 },
  "auth": { "type": "bearer", "token": "…" } }

// http_request: download a large file to disk (never returned inline)
{ "url": "https://example.com/big.iso", "save_to": "/Users/you/netkit/out/big.iso", "timeout_seconds": 600 }

// http_request: force HTTP/3
{ "url": "https://cloudflare-quic.com/", "http_version": "3" }

// http_multipart_request: form fields plus a file streamed from disk
{ "url": "https://httpbin.org/post",
  "fields": [ { "name": "title", "value": "Q3 report" } ],
  "parts":  [ { "name": "file", "file": "/Users/you/netkit/in/report.pdf" } ] }

// http_upload: PUT a file to a presigned URL with a SHA-256 checksum header
{ "url": "https://bucket.s3.amazonaws.com/report.pdf?X-Amz-Signature=…",
  "file": "/Users/you/netkit/in/report.pdf", "checksum": "sha256" }

// curl_to_request: turn a pasted curl command into tool arguments (sends nothing)
{ "command": "curl -X POST https://api.example.com/login -H 'Content-Type: application/json' -d '{\"user\":\"a\"}'" }
```

### APIs: GraphQL, JSON-RPC, SSE, web pages

```jsonc
// graphql_introspect: learn the schema first
{ "url": "https://countries.trevorblades.com/" }

// graphql_request
{ "url": "https://countries.trevorblades.com/",
  "query": "query($c: ID!) { country(code: $c) { name capital currency } }",
  "variables": { "c": "NL" } }

// jsonrpc_request: a batch of two calls
{ "url": "https://rpc.example.com/",
  "batch": [ { "method": "eth_blockNumber" }, { "method": "eth_chainId" } ] }

// sse_listen: stream an LLM-style API until it sends [DONE]
{ "url": "https://api.example.com/v1/stream", "method": "POST",
  "body": { "json": { "prompt": "hi", "stream": true } },
  "stop_data": "[DONE]", "max_duration_seconds": 60 }

// fetch_web: a page as Markdown; pass next_start_index back as start_index for more
{ "url": "https://go.dev/doc/effective_go", "max_length": 20000 }
```

### gRPC

```jsonc
// grpc_describe: list services via server reflection
{ "target": "grpc.example.com:443" }

// grpc_describe: one method, with a JSON request template
{ "target": "grpc.example.com:443", "symbol": "helloworld.Greeter/SayHello" }

// grpc_unary_request: with metadata and a .proto file instead of reflection
{ "target": "localhost:50051", "plaintext": true, "allow_private": true,
  "method": "helloworld.Greeter/SayHello", "request": { "name": "Ada" },
  "metadata": { "x-request-id": "42" },
  "proto_files": ["/Users/you/netkit/in/protos/helloworld.proto"] }

// grpc_stream_request: a bidi stream, one-shot
{ "target": "localhost:50051", "plaintext": true, "allow_private": true,
  "method": "chat.Chat/Talk", "messages": [ { "text": "hello" }, { "text": "bye" } ],
  "max_messages": 10 }

// grpc_health_check
{ "target": "grpc.example.com:443", "service": "" }
```

### WebSocket and Socket.IO

```jsonc
// ws_exchange: send two messages and collect replies for 5 seconds
{ "url": "wss://echo.websocket.org",
  "messages": [ { "text": "hello" }, { "json": { "type": "ping" } } ],
  "max_duration_seconds": 5 }

// sio_exchange: emit an event with an ack and listen for replies
{ "url": "https://chat.example.com", "namespace": "/",
  "events": [ { "event": "join", "args": ["room-1"], "ack": true } ],
  "max_duration_seconds": 10 }
```

### Messaging

```jsonc
// mqtt_subscribe: wildcards, 20 seconds
{ "broker": "mqtts://broker.example.com:8883", "topic": "sensors/#",
  "max_duration_seconds": 20, "auth": { "type": "basic", "username": "u", "password": "…" } }

// mqtt_publish: QoS 1, retained
{ "broker": "tcp://broker.example.com:1883", "topic": "lights/kitchen",
  "payload": { "json": { "on": true } }, "qos": 1, "retain": true }

// kafka_produce
{ "brokers": ["kafka.example.com:9092"], "topic": "orders",
  "records": [ { "key": { "text": "o-1" }, "value": { "json": { "total": 42 } } } ] }

// nats_request: request/reply
{ "url": "nats://demo.nats.io:4222", "subject": "time.now", "payload": { "text": "?" } }
```

### File transfer

```jsonc
// sftp_download: host key pinned via known_hosts, saved under the write directory
{ "host": "sftp.example.com", "remote_path": "/exports/data.csv",
  "save_to": "/Users/you/netkit/out/data.csv",
  "auth": { "type": "ssh_key", "username": "deploy",
            "ssh": { "private_key": "/Users/you/netkit/in/id_ed25519",
                     "known_hosts": "/Users/you/netkit/in/known_hosts" } } }

// s3_multipart_upload: to MinIO
{ "bucket": "backups", "key": "2026/db.tar.gz", "file": "/Users/you/netkit/in/db.tar.gz",
  "endpoint": "https://minio.example.com", "path_style": true,
  "aws": { "access_key_id": "…", "secret_access_key": "…" } }
```

### Low-level network

```jsonc
// dns_query: MX records over DNS-over-HTTPS
{ "name": "example.com", "type": "MX", "transport": "doh", "server": "https://cloudflare-dns.com/dns-query" }

// tls_inspect: certificate chain, expiry and supported TLS versions
{ "host": "example.com", "probe_versions": true }

// tcp_request: talk to a line protocol (Redis PING)
{ "host": "localhost", "port": 6379, "data": "PING\r\n", "escapes": true,
  "delimiter": "\r\n", "allow_private": true }
```

### Multi-step workflows

**OAuth2 authorization code with PKCE.** NetKit never opens a browser, so it works as two steps:

1. `oauth2_auth_url` with `authorization_url`, `client_id`, `scopes` and `redirect_uri` returns a `url`, `state` and `code_verifier`.
2. You open the URL, sign in, and paste the code (or the whole redirect URL) back into the chat.
3. `oauth2_exchange_code` with `token_url`, `client_id`, `code` (or `redirect_url`), `code_verifier` and `state` returns the tokens.
4. Later calls use `"auth": { "type": "bearer", "token": "<access_token>" }`.

For machine-to-machine APIs you don't need these steps at all: give any HTTP tool `"auth": { "type": "oauth2", "oauth2": { "token_url": "…", "client_id": "…", "client_secret": "…" } }` and NetKit fetches, caches and refreshes the token itself.

**SOAP.** Call `soap_describe` with `wsdl_url` to get the operations and a JSON skeleton of each input. Then call `soap_request` with the same `wsdl_url`, the `operation` name and `args` shaped like that skeleton.

**Interactive gRPC stream.**

1. `grpc_stream_open` (`target`, `method`, optional first `messages`) returns a `session_id`.
2. Alternate `grpc_stream_send` (`session_id`, `messages`) and `grpc_stream_recv` (`session_id`, `wait_seconds`).
3. `grpc_stream_close` returns the final status and trailers.

`ws_connect`/`ws_send`/`ws_receive`/`ws_close` and the `sio_*` tools work the same way.

---

## Authentication

Tools that authenticate take one shared `auth` object, with `type` selecting the scheme. Every field is listed under [The `auth` object](#the-auth-object).

| `type` | Fields | Notes |
|---|---|---|
| `none` | | The default |
| `basic` | `username`, `password` | |
| `bearer` | `token`, `prefix` | `prefix` defaults to `Bearer` |
| `api_key` | `key`, `value`, `in` | `in`: `header` (default), `query` or `cookie` |
| `custom_header` | `headers` | Any headers |
| `cookie` | `cookies` | |
| `digest` | `username`, `password` | HTTP Digest (RFC 7616) |
| `oauth2` | `oauth2.{grant, token_url, client_id, client_secret, scopes, …}` | Grants: client_credentials, password, refresh_token, jwt_bearer, token_exchange, access_token; tokens cached and refreshed |
| `oauth1` | `oauth1.{consumer_key, consumer_secret, token, token_secret, signature_method, …}` | HMAC-SHA1/SHA256, RSA-SHA1/SHA256, PLAINTEXT |
| `jwt` | `jwt.{algorithm, secret \| private_key, iss, sub, aud, claims, …}` | Signs a fresh JWT per request: HS*, RS*, ES*, PS*, EdDSA |
| `asap` | `asap.{…}` | Atlassian service-to-service JWT |
| `aws_sigv4` | `aws.{access_key_id, secret_access_key, session_token, region, service}` | Any AWS service, including S3 payload signing |
| `hawk` | `hawk.{id, key, algorithm, …}` | |
| `akamai_edgegrid` | `edgegrid.{client_token, client_secret, access_token}` | |
| `ntlm` | `username`, `password`, `domain` | |
| `negotiate` | `kerberos.{…}` | Kerberos/SPNEGO |
| `mtls` | `mtls.{…}` or the TLS options | Client certificate |
| `ws_security` | `username`, `password`, `ws_security.{password_type, timestamp, …}` | SOAP WS-Security UsernameToken (text or digest) |
| `ssh_password` | `username`, `password`, `ssh.{known_hosts \| host_key_fingerprint}` | SFTP |
| `ssh_key` | `username`, `ssh.{private_key, passphrase, known_hosts \| host_key_fingerprint}` | SFTP |

Each protocol applies the object in its own way:

| Protocol | How auth applies |
|---|---|
| HTTP, GraphQL, SOAP, SSE, JSON/XML-RPC, uploads, `fetch_web`, tus, S3 | Signed or added to each request (re-signed on retries) |
| WebSocket, Socket.IO | The handshake request; Socket.IO also takes an `auth_payload` |
| gRPC, gRPC-Web, Connect | Per-RPC credentials and metadata; TLS client certificates |
| MQTT, AMQP, NATS, Kafka, STOMP | Username/password, token, SASL or NKey, and TLS/mTLS |
| SFTP | SSH password or key, with host-key verification |
| FTP/FTPS | Username/password, TLS |

```json
{ "url": "https://api.example.com/v1/me",
  "auth": { "type": "oauth2",
            "oauth2": { "token_url": "https://idp.example.com/oauth/token",
                        "client_id": "app", "client_secret": "…", "scopes": ["read"] } } }
```

> Credentials are only sent to the original host (or its subdomains) when a request is redirected. They are masked in every echoed request and never written to logs.

---

## Working with files

Files are first-class, and they stream: uploads are read from disk and downloads written to disk without ever being loaded whole into memory or passed through the model's context.

| Option | Used by |
|---|---|
| `body_file` | `http_request` raw body |
| file parts | `http_multipart_request`, `graphql_request` uploads |
| `file` | `http_upload`, `tus_upload`, `s3_multipart_upload`, `sftp_upload`, `ftp_upload`, and payloads (`{"file": "…"}`) in `ws_send`, `mqtt_publish`, `kafka_produce`, `tcp_request`, ... |
| `{"$file": "path"}` | `bytes` fields in gRPC requests |
| `save_to` | `http_request` (and the other `http_*` tools), `sftp_download`, `ftp_download` |
| key and certificate fields | `ca_cert`, `client_cert`, `client_key`, `private_key`, `known_hosts`: inline PEM or a file path |

Rules:

- **Reads** are allowed only inside `--allow-read-dir` directories; **writes** only inside `--allow-write-dir` directories (which are also readable). With no directories configured, file options are refused with a message saying so.
- The allowed directories must exist when the server starts. A leading `~` in them is expanded to your home directory.
- Paths in tool calls should be absolute. A relative path is resolved against the first allowed directory.
- Symbolic links and Windows junctions are resolved before the check, and `..` traversal is refused. The errors never reveal whether a path outside the allowed directories exists.
- Downloads never overwrite an existing file unless `overwrite=true`. They are written to a temporary file and moved into place only when complete, so a failed download leaves nothing half-written. The exception is `resume=true` (SFTP/FTP), which deliberately continues an existing partial file.
- Every transfer reports name, size and SHA-256.
- Uploads and downloads default to 1 GiB per call and can be raised up to the server ceilings (16 GiB by default; see [Configuration](#configuration)).

> **Chat attachments are not on the server's disk.** A local stdio server can use any file in its allowed directories, so copy the file there first. A remote server can only use files placed in *its* allowed directories, or small payloads sent as base64.

---

## Security model

NetKit makes outbound connections for an AI agent, so its defaults are conservative.

- **SSRF guard.** Loopback, private (RFC 1918), CGNAT, link-local (including the cloud metadata address `169.254.169.254`) and multicast ranges are blocked. The check runs in the dialer on the resolved IP, so DNS rebinding can't get around it. It's repeated on every redirect, applies to every protocol, and also covers FTP passive-mode data connections. The `--private-networks` setting decides how private targets are treated:

  | Mode | Behaviour | Use for |
  |---|---|---|
  | `optin` (default) | blocked unless the call sets `allow_private=true` | a personal machine where the agent should ask first |
  | `deny` | always blocked, even with `allow_private` | shared or remote deployments |
  | `allow` | always permitted | local development against `localhost` services |

- **Host and port lists.** `--allow-hosts` and `--deny-hosts` (globs like `*.example.com` or CIDRs like `10.0.0.0/8`) restrict targets for every protocol; `--allow-ports` limits the raw TCP, UDP and DNS tools.
- **Limits with ceilings.** Timeouts, response size, upload and download size, redirects, message counts, stream duration, session count and buffer size all have defaults. A call can lower them but never raise them above the server's ceiling.
- **TLS.** Certificates are verified by default. `insecure_skip_verify` must be set explicitly, and the result flags it whenever it is used.
- **SSH.** SFTP requires a known_hosts entry or a pinned host-key fingerprint. Skipping verification (`insecure_ignore_host_key`) must be explicit and is flagged; every result reports the server's fingerprint so you can pin it.
- **Redaction.** `Authorization`, cookies, API keys, tokens in URLs, passwords, private keys and WS-Security passwords are masked in echoed requests, including when a server echoes them back.
- **No process execution.** There is no shell and no plugin loading, and `mcp_client_*` refuses to spawn stdio MCP servers.

> NetKit gives an agent real network access. Run it with the smallest set of groups you need, keep `--private-networks` at `optin` or `deny`, and point `--allow-write-dir` at a dedicated folder.

---

## Configuration

Every option is a command-line flag; most also have an environment variable, which is handy in Docker. List options are repeatable (`--allow-read-dir a --allow-read-dir b`) and also accept comma-separated values (`NETKIT_ALLOW_READ_DIR=a,b`). Flags override environment variables.

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--groups` | `NETKIT_GROUPS` | `default` | Tool groups to register: `all`, `default`, or a list such as `http,grpc` |
| `--transport` | `NETKIT_TRANSPORT` | `stdio` | `stdio` or `http` |
| `--addr` | `NETKIT_ADDR` | `127.0.0.1:8080` | Listen address for `--transport http` |
| `--path` | `NETKIT_HTTP_PATH` | `/mcp` | MCP endpoint path for HTTP |
| `--http-token` | `NETKIT_HTTP_TOKEN` | | Bearer token required on the HTTP endpoint (strongly recommended) |
| `--allow-read-dir` | `NETKIT_ALLOW_READ_DIR` | | Directories files may be read from. They must exist; a leading `~` is expanded |
| `--allow-write-dir` | `NETKIT_ALLOW_WRITE_DIR` | | Directories files may be written to (and read from). They must exist; a leading `~` is expanded |
| `--private-networks` | `NETKIT_PRIVATE_NETWORKS` | `optin` | `deny`, `optin` or `allow` (see [Security model](#security-model)) |
| `--allow-hosts` | `NETKIT_ALLOW_HOSTS` | all hosts | Host allow list (globs or CIDRs) |
| `--deny-hosts` | `NETKIT_DENY_HOSTS` | | Host deny list (globs or CIDRs) |
| `--allow-ports` | `NETKIT_ALLOW_PORTS` | all ports | Ports allowed for `tcp_request`, `udp_request` and `dns_query` |
| `--max-timeout` | | `10m` | Ceiling for per-call timeouts |
| `--max-response-bytes` | | `16777216` (16 MiB) | Ceiling for inline response bodies |
| `--max-upload-bytes` | | `17179869184` (16 GiB) | Ceiling for uploads |
| `--max-download-bytes` | | `17179869184` (16 GiB) | Ceiling for downloads |
| `--max-sessions` | | `64` | Maximum open interactive sessions |
| `--session-idle-ttl` | | `10m` | Idle time after which a session is closed |
| `--log-level` | `NETKIT_LOG_LEVEL` | `warn` | `debug`, `info`, `warn` or `error`; logs go to **stderr** (stdout carries MCP) |
| `--version` | | | Print the version and exit |

Byte values are plain integers; durations use Go syntax (`90s`, `10m`, `1h`). Run `netkit-mcp --help` for the same list.

**Per-call defaults and ceilings.** A call can lower any of these; it can raise them only up to the ceiling.

| Setting | Default per call | Ceiling |
|---|---|---|
| Timeout (`timeout_seconds`) | 30 s | `--max-timeout` (10 min) |
| Inline response body (`max_response_bytes`) | 1 MiB | `--max-response-bytes` (16 MiB) |
| Upload size | 1 GiB | `--max-upload-bytes` (16 GiB) |
| Download size (`max_download_bytes`) | 1 GiB | `--max-download-bytes` (16 GiB) |
| Redirects (`max_redirects`) | 10 | 30 |
| Stream messages (`max_messages`) | 100 | 10,000 |
| Stream duration (`max_duration_seconds`) | 10 s | 10 min |
| Inline base64 payload | 8 MiB | 8 MiB |
| Session ring buffer | 1,000 messages | 1,000 messages |

### Example setups

```bash
# Local development: reach localhost services freely, all tools
netkit-mcp --groups all --private-networks allow \
  --allow-read-dir ~/netkit/in --allow-write-dir ~/netkit/out
#   (on Windows: --allow-read-dir "$HOME\netkit\in" --allow-write-dir "$HOME\netkit\out")

# Locked down: only public HTTP APIs of one company, no files
netkit-mcp --groups http --private-networks deny --allow-hosts "*.example.com"

# Network diagnostics only
netkit-mcp --groups lowlevel --allow-ports 53,443,853
```

---

## Common options

Many tools share these arguments. To keep the [Tool reference](#tool-reference) short, they are listed once here, and each tool says which sets it accepts.

**Network options** (almost every tool that connects)

| Argument | Type | Description |
|---|---|---|
| `timeout_seconds` | number | Overall timeout in seconds (default 30, ceiling `--max-timeout`) |
| `allow_private` | boolean | Permit loopback, private and link-local targets (only honoured in `optin` mode) |
| `insecure_skip_verify` | boolean | Skip server certificate verification (flagged in the result) |
| `ca_cert` | string | Extra CA certificate(s): inline PEM or a file path |
| `client_cert` | string | Client certificate for mTLS: inline PEM or a file path |
| `client_key` | string | Client private key for mTLS: inline PEM or a file path |
| `server_name` | string | Override the TLS SNI / verification name |

**HTTP options** (HTTP-based tools)

| Argument | Type | Description |
|---|---|---|
| `follow_redirects` | boolean | Follow redirects (default true) |
| `max_redirects` | integer | Maximum redirects to follow (default 10) |
| `proxy` | string | Proxy URL (`http`, `https` or `socks5`) |
| `max_response_bytes` | integer | Maximum response body bytes returned inline (default 1 MiB) |
| `http_version` | string | `1.1`, `2` or `3` (default: negotiate 1.1/2) |

**Stream limits** (one-shot streaming tools)

| Argument | Type | Description |
|---|---|---|
| `max_messages` | integer | Stop after this many received messages (default 100) |
| `max_duration_seconds` | number | Stop after this many seconds (default 10) |
| `idle_timeout_seconds` | number | Stop when no message arrives for this many seconds (default: off) |

**Payload objects.** Arguments named `payload`, `body`, `value`, `key` and the like take an object with exactly one of: `text` (UTF-8 string), `json` (any JSON value, sent compactly), `base64` (small binary data) or `file` (a path inside an allowed read directory, streamed).

---

## Tool reference

Every tool with every argument, generated from the server's own schemas. Expand a tool to see its arguments; nested fields are shown as `parent.child`, and list items as `parent[].child`.

<!-- BEGIN GENERATED TOOL REFERENCE (go test -run TestReadmeToolReference -update-readme .) -->

### `http`: HTTP and API protocols

12 tools, on by default.

<details>
<summary><code>curl_to_request</code>: Convert curl command <sub>(local, no network)</sub></summary>

Parse a pasted curl command (bash, cmd ^ or PowerShell ` line continuations) into arguments for http_request, http_form_request, http_multipart_request or http_upload. Returns {tool, arguments, warnings}; call the named tool with the arguments. Does not send anything. @file references become file paths that must be inside an allowed read directory.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `command` | string | yes | the curl command line as pasted (bash, cmd or PowerShell quoting) |

</details>

<details>
<summary><code>fetch_web</code>: Fetch a web page as Markdown <sub>(read-only)</sub></summary>

Fetch a URL and return clean GitHub-flavoured Markdown: decodes the charset, extracts the main article (main_content_only, default true) or a css_selector, strips scripts, navigation and cookie banners, resolves relative links. JSON is pretty-printed, text/XML passed through, binary reported as metadata only. Long pages are paged: pass next_start_index back as start_index. JavaScript is not executed, so client-rendered pages may come back empty.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `css_selector` | string |  | convert only elements matching this CSS selector (overrides main_content_only) |
| `headers` | map&lt;string, string&gt; |  | extra request headers |
| `include_images` | boolean |  | keep images as Markdown images (default false) |
| `include_links` | boolean |  | keep hyperlinks as Markdown links (default true) |
| `include_metadata` | boolean |  | prepend title, byline, site and published date as front matter (default true) |
| `main_content_only` | boolean |  | extract the main article with readability (default true) |
| `max_length` | integer |  | maximum Markdown characters returned (default 20000) |
| `start_index` | integer |  | character offset to continue from (use next_start_index of the previous call) |
| `url` | string | yes | page URL (http or https) |
| `user_agent` | string |  | User-Agent header (default: the server's user agent) |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>graphql_introspect</code>: GraphQL introspection <sub>(read-only)</sub></summary>

Fetch a GraphQL schema with the standard introspection query and return it as compact SDL (types, fields with arguments and defaults, enums, inputs, interfaces, unions, scalars, custom directives). type_name prints a single type; include_descriptions adds docs; format=json returns the raw introspection result. Fails gracefully (errors in the result) when introspection is disabled.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `format` | string |  | sdl (default) or json (raw introspection result) |
| `headers` | map&lt;string, string&gt; |  | extra request headers |
| `include_descriptions` | boolean |  | include descriptions in the SDL (default false, more compact) |
| `type_name` | string |  | print only this type (or @directive) |
| `url` | string | yes | GraphQL endpoint (http or https) |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>graphql_request</code>: GraphQL request <sub>(mutating)</sub></summary>

Run a GraphQL query or mutation over HTTP. Returns the HTTP status plus data, errors and extensions separately (GraphQL errors are results, not tool failures). Uploads files with the GraphQL multipart request spec: files=[{variable_path: "variables.file", file: "/path"}] (streamed from disk, never buffered). method=GET sends the operation in the query string (persisted or cached queries; persisted_query_hash adds the APQ extension). Use graphql_introspect first to learn the schema.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `extensions` | object |  | request extensions object |
| `files` | object[] |  | file uploads (GraphQL multipart request spec); streamed from disk, POST only |
| `files[].content_type` | string |  | part content type (default: detected from the extension) |
| `files[].file` | string |  | **required.** path of the file inside an allowed read directory |
| `files[].filename` | string |  | filename sent to the server (default: base name of file) |
| `files[].variable_path` | string |  | where the file goes in the operation, e.g. variables.file or variables.files.0 |
| `files[].variable_paths` | string[] |  | several paths that share this file |
| `headers` | map&lt;string, string&gt; |  | extra request headers |
| `include_headers` | boolean |  | include response headers in the result |
| `method` | string |  | POST (default) or GET (query string encoding, for persisted/cached queries) |
| `operation_name` | string |  | operation to run when the document has several |
| `persisted_query_hash` | string |  | sha256 hash for Apollo automatic persisted queries (adds extensions.persistedQuery) |
| `query` | string |  | GraphQL document (may be omitted when persisted_query_hash is set) |
| `url` | string | yes | GraphQL endpoint (http or https) |
| `variables` | object |  | operation variables |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>graphql_subscribe</code>: GraphQL subscription <sub>(read-only)</sub></summary>

Run a bounded GraphQL subscription and collect the events. Protocols: graphql-transport-ws (graphql-ws library, default), legacy subscriptions-transport-ws (Apollo), or sse (graphql-sse distinct-connections mode). connection_params is sent in connection_init. Stops after max_messages events, max_duration_seconds, idle_timeout_seconds without events, or when the server completes. Each message has event next\|error\|complete and data = the JSON payload; ended_by explains why collection stopped.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `ack_timeout_seconds` | number |  | how long to wait for connection_ack (default 10) |
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `connection_params` | any |  | payload of connection_init (e.g. {authToken: ...}) for WebSocket protocols |
| `extensions` | object |  | request extensions object |
| `headers` | map&lt;string, string&gt; |  | extra handshake / request headers |
| `operation_name` | string |  | operation to run when the document has several |
| `protocol` | string |  | auto (default: graphql-transport-ws, or the legacy protocol if the server picks it), graphql-transport-ws, subscriptions-transport-ws or sse |
| `query` | string | yes | GraphQL subscription document |
| `url` | string | yes | subscription endpoint: ws:// or wss:// (http(s) also accepted) for WebSocket protocols, http(s) for sse |
| `variables` | object |  | operation variables |

Also accepts the [network options](#common-options), [HTTP options](#common-options) and [stream limits](#common-options).

</details>

<details>
<summary><code>http_form_request</code>: HTTP form request <sub>(mutating)</sub></summary>

Send an application/x-www-form-urlencoded form (default POST). fields is a list of {name, value} (order kept, repeated names allowed) or an object of name -&gt; string or list. Same transport, auth and save_to options as http_request.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `fields` | any | yes | form fields: a list of {name, value} objects (order kept, names may repeat) or an object mapping name to a string or list of strings |
| `headers` | map&lt;string, string&gt; |  | request headers |
| `include_request` | boolean |  | include a redacted echo of the request |
| `max_download_bytes` | integer |  | size limit for save_to downloads (default 1 GiB, capped by server policy) |
| `method` | string |  | HTTP method (default POST) |
| `overwrite` | boolean |  | allow save_to to replace an existing file (default false) |
| `query` | object |  | query parameters appended to the URL; each value is a string or a list of strings |
| `save_to` | string |  | stream the response body to this file (inside an allowed write directory) instead of returning it inline; reports name, size and sha256 |
| `url` | string | yes | absolute http:// or https:// URL |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>http_multipart_request</code>: HTTP multipart request <sub>(mutating)</sub></summary>

Send multipart/form-data (default POST): text fields plus parts that are text (value), JSON (json), files streamed from disk (file) or small binary (base64). Repeat a part name for several files in one field; set filename, content_type and headers per part. Files are streamed, never buffered, and Content-Length is computed up front. Reports name, size and sha256 of each uploaded file.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `fields` | any |  | text fields sent first: a list of {name, value} objects or an object mapping name to a string or list of strings |
| `headers` | map&lt;string, string&gt; |  | request headers (Content-Type is set automatically) |
| `include_request` | boolean |  | include a redacted echo of the request (part names, file sizes and hashes; never file contents) |
| `max_download_bytes` | integer |  | size limit for save_to downloads (default 1 GiB, capped by server policy) |
| `method` | string |  | HTTP method (default POST) |
| `overwrite` | boolean |  | allow save_to to replace an existing file (default false) |
| `parts` | object[] |  | parts in order: text (value), JSON (json), file (file streamed from disk) or binary (base64) |
| `parts[].base64` | string |  | binary part content as base64 (small payloads only) |
| `parts[].content_type` | string |  | part Content-Type (default: detected for files, application/octet-stream for base64) |
| `parts[].file` | string |  | stream this file as the part content (inside an allowed read directory) |
| `parts[].filename` | string |  | filename sent with the part (default: the file's base name; base64 parts have none unless set) |
| `parts[].headers` | map&lt;string, string&gt; |  | extra part headers |
| `parts[].json` | any |  | JSON value sent as an application/json part |
| `parts[].name` | string |  | **required.** form field name (repeat the name to send several files in one field) |
| `parts[].value` | string |  | text value (a plain text field) |
| `query` | object |  | query parameters appended to the URL; each value is a string or a list of strings |
| `save_to` | string |  | stream the response body to this file (inside an allowed write directory) instead of returning it inline; reports name, size and sha256 |
| `url` | string | yes | absolute http:// or https:// URL |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>http_request</code>: HTTP request <sub>(mutating)</sub></summary>

Send an HTTP request with any method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, PROPFIND, REPORT, PURGE, ...). Body: one of body (text), json, body_base64 (small) or body_file (streamed from disk). Supports query params, headers, auth, HTTP/1.1, 2 or 3 (http_version), redirects, proxy and TLS options. Large responses are truncated to max_response_bytes (default 1 MiB); use save_to to stream a download to disk (reports size and sha256). Private/loopback targets need allow_private=true.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `body` | string |  | raw text body |
| `body_base64` | string |  | binary body as base64 (small payloads only) |
| `body_file` | string |  | stream the body from this file (inside an allowed read directory) |
| `content_type` | string |  | Content-Type of the body (default derived from the body kind or file extension) |
| `headers` | map&lt;string, string&gt; |  | request headers |
| `include_request` | boolean |  | include a redacted echo of the request (method, URL, headers, body size and sha256) |
| `json` | any |  | JSON body (serialized; Content-Type application/json) |
| `max_download_bytes` | integer |  | size limit for save_to downloads (default 1 GiB, capped by server policy) |
| `method` | string |  | HTTP method; any token incl. PROPFIND, REPORT, PURGE (default GET, or POST when a body is given) |
| `overwrite` | boolean |  | allow save_to to replace an existing file (default false) |
| `query` | object |  | query parameters appended to the URL; each value is a string or a list of strings (repeated keys) |
| `save_to` | string |  | stream the response body to this file (inside an allowed write directory) instead of returning it inline; reports name, size and sha256 |
| `url` | string | yes | absolute http:// or https:// URL |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>http_upload</code>: HTTP file upload <sub>(mutating)</sub></summary>

Stream a file from disk as a raw PUT (default) or POST body, e.g. to a presigned S3, GCS or Azure Blob URL (no auth needed; add headers like x-ms-blob-type as required). Detects the content type, optionally sends an md5/sha256 checksum header, retries on network errors/408/429/5xx (re-reading the file), and returns file name/size/sha256, bytes transferred, timing and the remote status/location/etag. Raise timeout_seconds for large files.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `checksum` | string |  | md5 or sha256: hash the file first and send it (Content-MD5 or x-amz-checksum-sha256 by default) |
| `checksum_encoding` | string |  | base64 (default) or hex |
| `checksum_header` | string |  | header name for the checksum (overrides the default) |
| `content_type` | string |  | Content-Type (default detected from the extension or content); must match what a presigned URL was signed with |
| `file` | string | yes | file to upload (inside an allowed read directory); streamed, never loaded into memory |
| `headers` | map&lt;string, string&gt; |  | extra headers, e.g. x-ms-blob-type: BlockBlob, x-amz-acl, Content-Disposition |
| `method` | string |  | PUT (default) or POST |
| `query` | object |  | query parameters appended to the URL |
| `retries` | integer |  | retry this many times on network errors, 408, 429 and 5xx (default 0, max 10); the file is re-read each attempt |
| `retry_delay_seconds` | number |  | initial retry delay, doubled each attempt (default 1) |
| `url` | string | yes | target URL, e.g. a presigned S3/GCS/Azure Blob URL |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>jsonrpc_request</code>: JSON-RPC 2.0 request <sub>(mutating)</sub></summary>

Call a JSON-RPC 2.0 endpoint over HTTP POST. Single call: method + params (object or array) + optional id. Batch: batch=[{method, params, id?, notification?}] sent as one array. Notifications get no response. Responses are matched to requests by id; JSON-RPC errors are results ({ok:false, error:{code, message, data}}), not tool failures. missing_ids lists calls the server did not answer.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `batch` | object[] |  | several calls sent as one JSON-RPC batch array |
| `batch[].id` | any |  | request id (string or integer; default: assigned sequentially) |
| `batch[].method` | string |  | **required.** remote method name |
| `batch[].notification` | boolean |  | send as a notification (no id, no response expected) |
| `batch[].params` | any |  | params: a JSON object (by name) or array (by position) |
| `headers` | map&lt;string, string&gt; |  | extra request headers |
| `id` | any |  | id for a single call (default 1) |
| `include_headers` | boolean |  | include response headers in the result |
| `method` | string |  | method for a single call (omit when using batch) |
| `notification` | boolean |  | send the single call as a notification |
| `params` | any |  | params for a single call: object or array |
| `url` | string | yes | JSON-RPC endpoint (http or https) |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>sse_listen</code>: Listen to Server-Sent Events <sub>(read-only)</sub></summary>

Open a Server-Sent Events stream (GET, or POST with a body for LLM-style streaming APIs) and collect events. Stops after max_messages events, max_duration_seconds, idle_timeout_seconds without events, when the server closes the stream, or on stop_event (event name) / stop_data (exact data, e.g. "[DONE]"). Each message carries event, id and data; ended_by explains why collection stopped. meta.last_event_id can be passed back as last_event_id to resume.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `body` | object |  | request body for POST: text, json, base64 or file |
| `body.base64` | string |  | binary payload as base64 (small payloads only) |
| `body.file` | string |  | path of a file inside an allowed read directory |
| `body.json` | any |  | JSON payload (serialized compactly) |
| `body.text` | string |  | UTF-8 text payload |
| `content_type` | string |  | request body content type (default: application/json for json bodies) |
| `headers` | map&lt;string, string&gt; |  | extra request headers |
| `last_event_id` | string |  | resume a stream: sent as the Last-Event-ID header |
| `method` | string |  | GET (default) or POST (e.g. LLM streaming APIs) |
| `stop_data` | string |  | stop after an event whose data equals this exactly, e.g. [DONE] |
| `stop_event` | string |  | stop after an event with this event name (it is included) |
| `url` | string | yes | event stream URL (http or https) |

Also accepts the [network options](#common-options), [HTTP options](#common-options) and [stream limits](#common-options).

</details>

<details>
<summary><code>xmlrpc_request</code>: XML-RPC request <sub>(mutating)</sub></summary>

Call an XML-RPC method over HTTP POST. params are positional JSON values: numbers become int or double, strings, booleans, arrays and objects (struct) map naturally; force a type with {"$type": "base64", "value": "..."} (also i8, dateTime.iso8601, nil). Returns result (the first return value). A fault is a result ({ok:false, fault:{faultCode, faultString}}), not a tool failure.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `allow_nil` | boolean |  | encode JSON null as the &lt;nil/&gt; extension (otherwise null is rejected) |
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `headers` | map&lt;string, string&gt; |  | extra request headers |
| `include_headers` | boolean |  | include response headers in the result |
| `method` | string | yes | methodName to call |
| `params` | any[] |  | positional params as JSON; force a type with {"$type": "int\|i4\|i8\|double\|boolean\|string\|base64\|dateTime.iso8601\|nil", "value": ...} |
| `url` | string | yes | XML-RPC endpoint (http or https) |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

### `grpc`: gRPC, gRPC-Web and Connect

10 tools, on by default.

<details>
<summary><code>connect_request</code>: Connect RPC call <sub>(mutating)</sub></summary>

Call a unary or server-streaming method with the Connect protocol (encoding json or proto) through the shared HTTP client (SSRF guard, TLS, proxy, auth apply). JSON calls work without descriptors (request passed through; set server_streaming for streams); proto encoding needs proto_files or descriptor_sets. Returns the Connect/gRPC status with decoded error details, the response JSON or streamed messages, headers and trailers.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `descriptor_sets` | string[] |  | binary FileDescriptorSet files (protoc -o / buf build -o) instead of server reflection |
| `emit_defaults` | boolean |  | include fields that have default values in response JSON |
| `encoding` | string |  | json (default) or proto |
| `import_paths` | string[] |  | import paths for proto_files (default: each file's directory); well-known google/protobuf imports are built in |
| `metadata` | map&lt;string, string&gt; |  | request headers / metadata |
| `method` | string | yes | package.Service/Method (or package.Service.Method) |
| `proto_files` | string[] |  | .proto files or directories compiled in-process instead of server reflection (paths inside allowed read dirs) |
| `request` | any |  | request message as protojson (object); bytes fields take base64 or {"$file": "path"} |
| `server_streaming` | boolean |  | force server-streaming mode (only needed for JSON calls without descriptors) |
| `url` | string | yes | base URL of the endpoint, e.g. https://api.example.com/prefix (the /package.Service/Method path is appended) |
| `use_proto_names` | boolean |  | use proto field names (snake_case) instead of lowerCamelCase in response JSON |

Also accepts the [network options](#common-options), [HTTP options](#common-options) and [stream limits](#common-options).

</details>

<details>
<summary><code>grpc_describe</code>: Describe gRPC services <sub>(read-only)</sub></summary>

List a gRPC server's services and methods, or describe one service, method, message or enum by full name. Descriptors come from server reflection (v1, falling back to v1alpha) on target, or from proto_files / descriptor_sets compiled in-process. Returns proto-like text plus a structured form (fields, types, streaming flags) and, for methods, a request JSON template.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `authority` | string |  | override the :authority header |
| `descriptor_sets` | string[] |  | binary FileDescriptorSet files (protoc -o / buf build -o) instead of server reflection |
| `import_paths` | string[] |  | import paths for proto_files (default: each file's directory); well-known google/protobuf imports are built in |
| `metadata` | map&lt;string, string&gt; |  | request metadata; keys ending in -bin take base64 values |
| `plaintext` | boolean |  | use plaintext HTTP/2 (h2c) instead of TLS (default TLS) |
| `proto_files` | string[] |  | .proto files or directories compiled in-process instead of server reflection (paths inside allowed read dirs) |
| `symbol` | string |  | fully-qualified service, method (pkg.Service/Method or pkg.Service.Method), message or enum name; empty lists all services and methods |
| `target` | string |  | gRPC server host:port for server reflection (optional when proto_files or descriptor_sets are given) |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>grpc_health_check</code>: gRPC health check <sub>(read-only)</sub></summary>

Run the standard grpc.health.v1 Check RPC (serving_status SERVING / NOT_SERVING / SERVICE_UNKNOWN) for the whole server or one service; watch=true runs the Watch stream and collects status updates until max_messages or max_duration_seconds (default 1 message, 10 s).

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `authority` | string |  | override the :authority header |
| `metadata` | map&lt;string, string&gt; |  | request metadata; keys ending in -bin take base64 values |
| `plaintext` | boolean |  | use plaintext HTTP/2 (h2c) instead of TLS (default TLS) |
| `service` | string |  | service name (empty = overall server health) |
| `target` | string | yes | gRPC server host:port (grpc:// = plaintext, grpcs:// = TLS) |
| `watch` | boolean |  | use the streaming Watch RPC and collect status changes (bounded by max_messages / max_duration_seconds) |

Also accepts the [network options](#common-options) and [stream limits](#common-options).

</details>

<details>
<summary><code>grpc_stream_close</code>: Close gRPC stream session <sub>(mutating)</sub></summary>

Half-close and close a gRPC stream session: waits up to wait_seconds for the server to finish, then cancels. Returns the final status, trailers and any messages still buffered.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `session_id` | string | yes | handle from grpc_stream_open |
| `wait_seconds` | number |  | after half-closing, wait up to this long for the server to finish before cancelling (default 2) |

</details>

<details>
<summary><code>grpc_stream_open</code>: Open gRPC stream session <sub>(mutating)</sub></summary>

Open an interactive gRPC stream (any streaming method) and return a session_id. Responses are buffered in the background; use grpc_stream_send, grpc_stream_recv and grpc_stream_close. Sessions expire after the server's idle TTL.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `authority` | string |  | override the :authority header |
| `close_send` | boolean |  | half-close the send side after sending messages |
| `descriptor_sets` | string[] |  | binary FileDescriptorSet files (protoc -o / buf build -o) instead of server reflection |
| `emit_defaults` | boolean |  | include fields that have default values in response JSON |
| `import_paths` | string[] |  | import paths for proto_files (default: each file's directory); well-known google/protobuf imports are built in |
| `messages` | any[] |  | optional request messages to send right away |
| `metadata` | map&lt;string, string&gt; |  | request metadata; keys ending in -bin take base64 values |
| `method` | string | yes | package.Service/Method of a streaming method |
| `plaintext` | boolean |  | use plaintext HTTP/2 (h2c) instead of TLS (default TLS) |
| `proto_files` | string[] |  | .proto files or directories compiled in-process instead of server reflection (paths inside allowed read dirs) |
| `target` | string | yes | gRPC server host:port (grpc:// = plaintext, grpcs:// = TLS) |
| `use_proto_names` | boolean |  | use proto field names (snake_case) instead of lowerCamelCase in response JSON |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>grpc_stream_recv</code>: Receive from gRPC stream <sub>(read-only)</sub></summary>

Return buffered response messages from a gRPC stream session, waiting up to wait_seconds for the first one. When the stream has ended, stream_ended is true and the final status and trailers are included.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `max_messages` | integer |  | return at most this many messages (default 100) |
| `session_id` | string | yes | handle from grpc_stream_open |
| `wait_seconds` | number |  | wait up to this long for the first message (default 5) |

</details>

<details>
<summary><code>grpc_stream_request</code>: gRPC streaming call (one-shot) <sub>(mutating)</sub></summary>

Bounded one-shot call for server-, client- and bidi-streaming methods: sends messages[] in order, half-closes, and collects responses until the server ends the stream or max_messages / max_duration_seconds / idle_timeout_seconds is reached. Returns sent and received messages, final status (decoded details), headers and trailers. Use grpc_stream_open for interactive streams.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `authority` | string |  | override the :authority header |
| `descriptor_sets` | string[] |  | binary FileDescriptorSet files (protoc -o / buf build -o) instead of server reflection |
| `emit_defaults` | boolean |  | include fields that have default values in response JSON |
| `import_paths` | string[] |  | import paths for proto_files (default: each file's directory); well-known google/protobuf imports are built in |
| `messages` | any[] |  | request messages (protojson objects) sent in order before half-closing; server-streaming/unary methods take exactly one (default {}) |
| `metadata` | map&lt;string, string&gt; |  | request metadata; keys ending in -bin take base64 values |
| `method` | string | yes | package.Service/Method of a streaming (or unary) method |
| `plaintext` | boolean |  | use plaintext HTTP/2 (h2c) instead of TLS (default TLS) |
| `proto_files` | string[] |  | .proto files or directories compiled in-process instead of server reflection (paths inside allowed read dirs) |
| `target` | string | yes | gRPC server host:port (grpc:// = plaintext, grpcs:// = TLS) |
| `use_proto_names` | boolean |  | use proto field names (snake_case) instead of lowerCamelCase in response JSON |

Also accepts the [network options](#common-options) and [stream limits](#common-options).

</details>

<details>
<summary><code>grpc_stream_send</code>: Send on gRPC stream <sub>(mutating)</sub></summary>

Send request messages on an open gRPC stream session; set close_send=true to half-close (end the client stream). If the server stops reading, the send gives up after timeout_seconds and cancels the stream.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `close_send` | boolean |  | half-close the send side after sending (signals end of client stream) |
| `messages` | any[] |  | request messages (protojson objects) to send in order |
| `session_id` | string | yes | handle from grpc_stream_open |
| `timeout_seconds` | number |  | give up (and cancel the stream) if the server does not accept the messages within this many seconds (default 30) |

</details>

<details>
<summary><code>grpc_unary_request</code>: gRPC unary call <sub>(mutating)</sub></summary>

Call a unary gRPC method with a JSON request and get the JSON response, status (code, message, decoded google.rpc details), headers, trailers and timing. TLS by default (plaintext=true for h2c); TLS/mTLS options and auth become credentials and metadata. Descriptors come from server reflection unless proto_files/descriptor_sets are given. Non-OK gRPC statuses are results, not tool errors. Use grpc_stream_request for streaming methods.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `authority` | string |  | override the :authority header |
| `descriptor_sets` | string[] |  | binary FileDescriptorSet files (protoc -o / buf build -o) instead of server reflection |
| `emit_defaults` | boolean |  | include fields that have default values in response JSON |
| `import_paths` | string[] |  | import paths for proto_files (default: each file's directory); well-known google/protobuf imports are built in |
| `metadata` | map&lt;string, string&gt; |  | request metadata; keys ending in -bin take base64 values |
| `method` | string | yes | package.Service/Method (or package.Service.Method) |
| `plaintext` | boolean |  | use plaintext HTTP/2 (h2c) instead of TLS (default TLS) |
| `proto_files` | string[] |  | .proto files or directories compiled in-process instead of server reflection (paths inside allowed read dirs) |
| `request` | any |  | request message as protojson (object); bytes fields take base64 or {"$file": "path"} |
| `target` | string | yes | gRPC server host:port (grpc:// = plaintext, grpcs:// = TLS) |
| `use_proto_names` | boolean |  | use proto field names (snake_case) instead of lowerCamelCase in response JSON |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>grpcweb_request</code>: gRPC-Web call <sub>(mutating)</sub></summary>

Call a unary or server-streaming method over gRPC-Web (binary application/grpc-web+proto, or format=text for application/grpc-web-text) through the shared HTTP client (SSRF guard, TLS, proxy, auth apply). Needs proto_files or descriptor_sets (reflection is not available over gRPC-Web). Returns status (with decoded details), response JSON or streamed messages, headers and trailers.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `descriptor_sets` | string[] |  | binary FileDescriptorSet files (protoc -o / buf build -o) instead of server reflection |
| `emit_defaults` | boolean |  | include fields that have default values in response JSON |
| `format` | string |  | binary (application/grpc-web+proto, default) or text (application/grpc-web-text, base64 body) |
| `import_paths` | string[] |  | import paths for proto_files (default: each file's directory); well-known google/protobuf imports are built in |
| `metadata` | map&lt;string, string&gt; |  | request headers / metadata |
| `method` | string | yes | package.Service/Method (or package.Service.Method) |
| `proto_files` | string[] |  | .proto files or directories compiled in-process instead of server reflection (paths inside allowed read dirs) |
| `request` | any |  | request message as protojson (object); bytes fields take base64 or {"$file": "path"} |
| `url` | string | yes | base URL of the endpoint, e.g. https://api.example.com/prefix (the /package.Service/Method path is appended) |
| `use_proto_names` | boolean |  | use proto field names (snake_case) instead of lowerCamelCase in response JSON |

Also accepts the [network options](#common-options), [HTTP options](#common-options) and [stream limits](#common-options).

</details>

### `ws`: WebSocket and Socket.IO

11 tools, on by default.

<details>
<summary><code>sio_close</code>: Socket.IO close <sub>(mutating)</sub></summary>

Disconnect all namespaces, close a sio_connect session and return any messages still buffered.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `session_id` | string | yes | session handle |

</details>

<details>
<summary><code>sio_connect</code>: Socket.IO connect <sub>(mutating)</sub></summary>

Open an interactive Socket.IO session (Engine.IO v4 over websocket, or long-polling with optional upgrade) and join one or more namespaces with an optional CONNECT auth_payload. Incoming events, acks and disconnects are buffered until read with sio_receive. Returns session_id, engine sid, transport and namespace states.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `auth_payload` | any |  | Socket.IO CONNECT auth payload (JSON object) sent when joining each namespace |
| `compression` | boolean |  | negotiate permessage-deflate compression |
| `headers` | map&lt;string, string&gt; |  | extra handshake request headers |
| `max_message_bytes` | integer |  | maximum size of one incoming message (default 1 MiB) |
| `namespaces` | string[] |  | namespaces to join on this connection (default: the URL path namespace or /) |
| `origin` | string |  | Origin header to send (none by default) |
| `path` | string |  | Engine.IO endpoint path (default /socket.io/) |
| `query` | map&lt;string, string&gt; |  | extra handshake query parameters |
| `transport` | string |  | websocket (default) or polling (HTTP long-polling) |
| `upgrade` | boolean |  | with transport=polling: upgrade to websocket when offered (default true) |
| `url` | string | yes | server URL (http, https, ws or wss); a path other than the endpoint path is used as the namespace, like the JS client |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>sio_emit</code>: Socket.IO emit <sub>(mutating)</sub></summary>

Emit an event on a sio_connect session (JSON args plus optional binary attachments). ack=true requests an acknowledgement (delivered to sio_receive); wait_ack_seconds waits for it and returns it here. Set ack_id to answer an ack the server requested (meta.ack_id of a received event). Unjoined namespaces are joined automatically.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `ack` | boolean |  | request an acknowledgement; it arrives in sio_receive as type ack with meta.ack_id |
| `ack_id` | integer |  | answer the server's ack request with this id (from meta.ack_id of a received event) instead of emitting an event |
| `args` | any[] |  | event (or ack) arguments as JSON values |
| `attachments` | object[] |  | binary attachments (base64 or file), appended after args as placeholders unless args contain {"_placeholder":true,"num":N} |
| `attachments[].base64` | string |  | binary payload as base64 (small payloads only) |
| `attachments[].file` | string |  | path of a file inside an allowed read directory |
| `attachments[].json` | any |  | JSON payload (serialized compactly) |
| `attachments[].text` | string |  | UTF-8 text payload |
| `event` | string |  | event name (required unless ack_id is set) |
| `namespace` | string |  | namespace (default /); joined automatically if needed |
| `session_id` | string | yes | session handle from sio_connect |
| `wait_ack_seconds` | number |  | request an ack and wait up to this many seconds for it (returned in ack) |

</details>

<details>
<summary><code>sio_exchange</code>: Socket.IO exchange <sub>(mutating)</sub></summary>

One-shot Socket.IO (Engine.IO v4 / Socket.IO v5) call: connect over websocket or long-polling, join namespace (auth_payload is the CONNECT auth object), emit events[] (JSON args, binary attachments from base64/file, optional ack), then collect incoming events and acks until max_messages, max_duration_seconds, idle_timeout_seconds or stop_on_event. Events come back as type event with the event name and JSON args; acks as type ack with meta.ack_id; binary attachments as {"_binary":true,"base64":...}. Use sio_connect for interactive sessions.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `auth_payload` | any |  | Socket.IO CONNECT auth payload (JSON object), e.g. {"token":"..."} |
| `auto_ack` | boolean |  | answer server ack requests automatically with auto_ack_args |
| `auto_ack_args` | any[] |  | arguments for automatic acks (default none) |
| `compression` | boolean |  | negotiate permessage-deflate compression |
| `events` | object[] |  | events to emit in order after joining |
| `events[].ack` | boolean |  | request an acknowledgement (it is collected with type ack and meta.ack_id) |
| `events[].args` | any[] |  | event arguments (JSON values) |
| `events[].attachments` | object[] |  | binary attachments (base64 or file); sent as BINARY_EVENT and appended after args as placeholders unless args already contain {"_placeholder":true,"num":N} |
| `events[].attachments[].base64` | string |  | binary payload as base64 (small payloads only) |
| `events[].attachments[].file` | string |  | path of a file inside an allowed read directory |
| `events[].attachments[].json` | any |  | JSON payload (serialized compactly) |
| `events[].attachments[].text` | string |  | UTF-8 text payload |
| `events[].delay_ms` | integer |  | wait this many milliseconds before emitting |
| `events[].event` | string |  | **required.** event name |
| `events[].namespace` | string |  | namespace (default: the tool's namespace) |
| `headers` | map&lt;string, string&gt; |  | extra handshake request headers |
| `listen` | string[] |  | only collect these incoming event names (acks are always collected) |
| `max_message_bytes` | integer |  | maximum size of one incoming message (default 1 MiB) |
| `namespace` | string |  | namespace to join (default /) |
| `origin` | string |  | Origin header to send (none by default) |
| `path` | string |  | Engine.IO endpoint path (default /socket.io/) |
| `query` | map&lt;string, string&gt; |  | extra handshake query parameters |
| `stop_on_event` | string |  | stop collecting when this event name arrives |
| `transport` | string |  | websocket (default) or polling (HTTP long-polling) |
| `upgrade` | boolean |  | with transport=polling: upgrade to websocket when offered (default true) |
| `url` | string | yes | server URL (http, https, ws or wss); a path other than the endpoint path is used as the namespace, like the JS client |

Also accepts the [network options](#common-options), [HTTP options](#common-options) and [stream limits](#common-options).

</details>

<details>
<summary><code>sio_receive</code>: Socket.IO receive <sub>(read-only)</sub></summary>

Drain buffered incoming Socket.IO messages from a sio_connect session (events with name and JSON args, acks with meta.ack_id, disconnects). Waits up to wait_seconds when empty; dropped counts messages lost to buffer overflow.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `max_messages` | integer |  | return at most this many buffered messages (default 100) |
| `session_id` | string | yes | session handle |
| `wait_seconds` | number |  | wait up to this many seconds for a message when the buffer is empty (default 1) |

</details>

<details>
<summary><code>ws_close</code>: WebSocket close <sub>(mutating)</sub></summary>

Close a ws_connect session with a close code and reason, and return any frames still buffered.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `code` | integer |  | close code to send (default 1000) |
| `reason` | string |  | close reason to send |
| `session_id` | string | yes | session handle |

</details>

<details>
<summary><code>ws_connect</code>: WebSocket connect <sub>(mutating)</sub></summary>

Open an interactive WebSocket session and return a session_id. Incoming frames are buffered in the background (bounded ring buffer; oldest dropped when full) until read with ws_receive. Supports headers, subprotocols, Origin, auth, compression and keepalive pings (ping_interval_seconds). Close with ws_close.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `compression` | boolean |  | negotiate permessage-deflate compression |
| `headers` | map&lt;string, string&gt; |  | extra handshake request headers |
| `max_message_bytes` | integer |  | maximum size of one incoming message (default 1 MiB) |
| `origin` | string |  | Origin header to send (none by default) |
| `ping_interval_seconds` | number |  | send a keepalive ping this often (default off) |
| `subprotocols` | string[] |  | subprotocols to offer (Sec-WebSocket-Protocol); the negotiated one is reported |
| `url` | string | yes | WebSocket URL (ws:// or wss://; http/https are converted) |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>ws_exchange</code>: WebSocket exchange <sub>(mutating)</sub></summary>

One-shot WebSocket call: connect (custom headers, subprotocols, Origin, auth), send messages[] in order (text, json, base64 binary or a file streamed as one frame; optional delay_ms), collect incoming frames until max_messages, max_duration_seconds, idle_timeout_seconds or stop_on, then close with close_code/close_reason. Returns all frames in order (dir in/out; binary as base64), the close code/reason and the handshake (negotiated subprotocol, response headers). Use ws_connect for interactive sessions.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `close_code` | integer |  | close code to send at the end (default 1000) |
| `close_reason` | string |  | close reason to send at the end |
| `compression` | boolean |  | negotiate permessage-deflate compression |
| `headers` | map&lt;string, string&gt; |  | extra handshake request headers |
| `max_message_bytes` | integer |  | maximum size of one incoming message (default 1 MiB) |
| `messages` | object[] |  | frames to send in order after connecting |
| `messages[].base64` | string |  | binary payload as base64 (small payloads only) |
| `messages[].delay_ms` | integer |  | wait this many milliseconds before sending |
| `messages[].file` | string |  | path of a file inside an allowed read directory |
| `messages[].json` | any |  | JSON payload (serialized compactly) |
| `messages[].text` | string |  | UTF-8 text payload |
| `messages[].type` | string |  | frame type text or binary (default: text for text/json, binary for base64/file) |
| `origin` | string |  | Origin header to send (none by default) |
| `stop_on` | string |  | stop collecting when an incoming message contains this substring |
| `stop_on_regex` | boolean |  | treat stop_on as a regular expression |
| `subprotocols` | string[] |  | subprotocols to offer (Sec-WebSocket-Protocol); the negotiated one is reported |
| `url` | string | yes | WebSocket URL (ws:// or wss://; http/https are converted) |

Also accepts the [network options](#common-options), [HTTP options](#common-options) and [stream limits](#common-options).

</details>

<details>
<summary><code>ws_list</code>: List WebSocket/Socket.IO sessions <sub>(local, no network)</sub></summary>

List open ws and sio sessions with their state (open/closed, buffered messages, namespaces, transport).

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `kind` | string |  | ws, sio or empty for both |

</details>

<details>
<summary><code>ws_receive</code>: WebSocket receive <sub>(read-only)</sub></summary>

Drain buffered incoming frames from a ws_connect session (waits up to wait_seconds when empty). ended_by is peer_closed (with the close code) once the server closed and the buffer is empty; dropped counts frames lost to buffer overflow.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `max_messages` | integer |  | return at most this many buffered messages (default 100) |
| `session_id` | string | yes | session handle |
| `wait_seconds` | number |  | wait up to this many seconds for a message when the buffer is empty (default 1) |

</details>

<details>
<summary><code>ws_send</code>: WebSocket send <sub>(mutating)</sub></summary>

Send one frame on a ws_connect session: text, json, base64 (binary) or a file streamed as one frame; type overrides text/binary. Set ping=true to send a ping and measure the pong round trip.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `base64` | string |  | binary payload as base64 (small payloads only) |
| `file` | string |  | path of a file inside an allowed read directory |
| `json` | any |  | JSON payload (serialized compactly) |
| `ping` | boolean |  | send a ping and wait for the pong instead of a data frame |
| `session_id` | string | yes | session handle from ws_connect |
| `text` | string |  | UTF-8 text payload |
| `type` | string |  | frame type text or binary (default: text for text/json, binary for base64/file) |

</details>

### `soap`: SOAP and WSDL

2 tools, on by default.

<details>
<summary><code>soap_describe</code>: Describe a SOAP service (WSDL) <sub>(read-only)</sub></summary>

Parse a WSDL 1.1 (wsdl_url, wsdl_file or inline wsdl; wsdl:import, xs:import and xs:include are resolved) and list services, ports (SOAP 1.1/1.2, document/rpc, endpoint), operations (soapAction, literal/encoded) and JSON skeletons of each operation's input and output derived from the XML Schema. Skeleton keys ending in '?' are optional, '@x' are attributes, [ ] means repeated. Set operation for one operation in detail. Use the input skeleton as args for soap_request. WSDL 2.0 is not supported.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `operation` | string |  | describe only this operation in detail (parts, input/output shapes, faults) |
| `port` | string |  | port name (narrows the operation lookup) |
| `service` | string |  | service name (narrows the operation lookup) |
| `wsdl` | string |  | inline WSDL XML (only absolute http(s) imports can be resolved) |
| `wsdl_file` | string |  | path of a WSDL file inside an allowed read directory; imports are resolved relative to it |
| `wsdl_url` | string |  | URL of a WSDL 1.1 document; imports are resolved relative to it |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>soap_request</code>: Call a SOAP operation <sub>(mutating)</sub></summary>

Call a SOAP operation by name with JSON args (built into a document/literal or rpc body from the WSDL, with correct namespaces), or send raw_body XML (a full Envelope or Body content). Supports SOAP 1.1 and 1.2, SOAPAction, custom soap_headers, HTTP auth and WS-Security UsernameToken (text or digest) with Timestamp (auth.type=ws_security). Returns HTTP status, the Body as JSON, the raw XML (truncated per max_response_bytes) and a parsed fault (SOAP faults are results, not errors). MTOM/XOP attachments and WS-Security signing/encryption are not supported.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `args` | any |  | operation input as JSON, shaped like the soap_describe input skeleton |
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `endpoint` | string |  | endpoint URL (default: the port address from the WSDL) |
| `headers` | map&lt;string, string&gt; |  | extra HTTP headers |
| `operation` | string |  | operation name from the WSDL (requires wsdl_url, wsdl_file or wsdl) |
| `port` | string |  | port name (e.g. pick the SOAP 1.2 port) |
| `raw_body` | string |  | raw XML instead of args: a full soap Envelope, or Body content to wrap |
| `service` | string |  | service name when several services define the operation |
| `soap_action` | string |  | override the SOAP action (default from the WSDL) |
| `soap_headers` | string[] |  | raw XML header blocks to put in soap:Header (declare their namespaces) |
| `soap_version` | string |  | 1.1 (text/xml + SOAPAction header) or 1.2 (application/soap+xml; action=...); default from the binding, else 1.1 |
| `typed_response` | boolean |  | type response values (numbers, booleans, arrays) using the WSDL output shape (default true) |
| `wsdl` | string |  | inline WSDL XML (only absolute http(s) imports can be resolved) |
| `wsdl_file` | string |  | path of a WSDL file inside an allowed read directory; imports are resolved relative to it |
| `wsdl_url` | string |  | URL of a WSDL 1.1 document; imports are resolved relative to it |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

### `mqtt`: MQTT

2 tools, on by default.

<details>
<summary><code>mqtt_publish</code>: MQTT publish <sub>(mutating)</sub></summary>

Publish one message to an MQTT broker (MQTT 5 by default, or 3.1.1) and report the broker's CONNACK and PUBACK/PUBCOMP reason codes. Supports tcp/ssl/ws/wss brokers, QoS 0-2, retain, MQTT 5 properties (content_type, response_topic, correlation_data, message_expiry, user_properties), username/password or auth, TLS/mTLS and a last will. The payload may be text, JSON, base64 or a file from an allowed directory (buffered in memory, bounded by the upload limit).

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `broker` | string | yes | broker URL: tcp:// or mqtt:// (1883), ssl:// tls:// or mqtts:// (8883), ws:// or wss:// (path defaults to /mqtt); bare host:port means tcp:// |
| `clean_session` | boolean |  | alias of clean_start |
| `clean_start` | boolean |  | MQTT 5 clean start / 3.1.1 clean session (default true) |
| `client_id` | string |  | client identifier (default: random netkit-...) |
| `disconnect_with_will` | boolean |  | end the session so the broker publishes the will (MQTT 5 reason 0x04; 3.1.x drops the connection) |
| `keepalive_seconds` | integer |  | keepalive in seconds (default 30, 0 disables) |
| `password` | string |  | broker password (overrides auth) |
| `payload` | object |  | message payload: text, json, base64 or file (omit for an empty payload) |
| `payload.base64` | string |  | binary payload as base64 (small payloads only) |
| `payload.file` | string |  | path of a file inside an allowed read directory |
| `payload.json` | any |  | JSON payload (serialized compactly) |
| `payload.text` | string |  | UTF-8 text payload |
| `properties` | object |  | MQTT 5 publish properties |
| `properties.content_type` | string |  | MQTT 5 content type (e.g. application/json) |
| `properties.correlation_data` | string |  | MQTT 5 correlation data as text |
| `properties.correlation_data_base64` | string |  | MQTT 5 correlation data as base64 (binary) |
| `properties.message_expiry` | integer |  | MQTT 5 message expiry interval in seconds |
| `properties.payload_format` | integer |  | MQTT 5 payload format indicator: 0 = bytes, 1 = UTF-8 text |
| `properties.response_topic` | string |  | MQTT 5 response topic for request/response |
| `properties.user_properties` | map&lt;string, string&gt; |  | MQTT 5 user properties (key/value) |
| `protocol_version` | string |  | 5 (default) or 3.1.1 (also 4); 3.1 for very old brokers |
| `qos` | integer |  | QoS 0 (default), 1 or 2 |
| `retain` | boolean |  | set the retain flag (an empty retained payload clears the retained message) |
| `session_expiry_seconds` | integer |  | MQTT 5 session expiry interval in seconds |
| `topic` | string | yes | topic name (no wildcards) |
| `username` | string |  | broker username (overrides auth) |
| `will` | object |  | last-will message |
| `will.delay_seconds` | integer |  | MQTT 5 will delay interval in seconds |
| `will.payload` | object |  | will payload |
| `will.payload.base64` | string |  | binary payload as base64 (small payloads only) |
| `will.payload.file` | string |  | path of a file inside an allowed read directory |
| `will.payload.json` | any |  | JSON payload (serialized compactly) |
| `will.payload.text` | string |  | UTF-8 text payload |
| `will.properties` | object |  | MQTT 5 will properties |
| `will.properties.content_type` | string |  | MQTT 5 content type (e.g. application/json) |
| `will.properties.correlation_data` | string |  | MQTT 5 correlation data as text |
| `will.properties.correlation_data_base64` | string |  | MQTT 5 correlation data as base64 (binary) |
| `will.properties.message_expiry` | integer |  | MQTT 5 message expiry interval in seconds |
| `will.properties.payload_format` | integer |  | MQTT 5 payload format indicator: 0 = bytes, 1 = UTF-8 text |
| `will.properties.response_topic` | string |  | MQTT 5 response topic for request/response |
| `will.properties.user_properties` | map&lt;string, string&gt; |  | MQTT 5 user properties (key/value) |
| `will.qos` | integer |  | will QoS 0-2 |
| `will.retain` | boolean |  | retain the will message |
| `will.topic` | string |  | **required.** will topic |
| `ws_headers` | map&lt;string, string&gt; |  | extra HTTP headers for the ws:// / wss:// handshake |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>mqtt_subscribe</code>: MQTT subscribe <sub>(read-only)</sub></summary>

Subscribe to MQTT topic filters (wildcards + and #, shared subscriptions $share/group/filter) and collect messages until max_messages, max_duration_seconds (default 10) or idle_timeout_seconds. Per-filter QoS and MQTT 5 options (no_local, retain_as_published, retain_handling). Retained messages arrive first. publish_first sends a message after subscribing, for request/response tests. Payloads are returned as text or base64 with QoS, retain and properties.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `broker` | string | yes | broker URL: tcp:// or mqtt:// (1883), ssl:// tls:// or mqtts:// (8883), ws:// or wss:// (path defaults to /mqtt); bare host:port means tcp:// |
| `clean_session` | boolean |  | alias of clean_start |
| `clean_start` | boolean |  | MQTT 5 clean start / 3.1.1 clean session (default true) |
| `client_id` | string |  | client identifier (default: random netkit-...) |
| `disconnect_with_will` | boolean |  | end the session so the broker publishes the will (MQTT 5 reason 0x04; 3.1.x drops the connection) |
| `keepalive_seconds` | integer |  | keepalive in seconds (default 30, 0 disables) |
| `password` | string |  | broker password (overrides auth) |
| `protocol_version` | string |  | 5 (default) or 3.1.1 (also 4); 3.1 for very old brokers |
| `publish_first` | object |  | publish this message after subscribing (request/response testing) |
| `publish_first.payload` | object |  | payload: text, json, base64 or file |
| `publish_first.payload.base64` | string |  | binary payload as base64 (small payloads only) |
| `publish_first.payload.file` | string |  | path of a file inside an allowed read directory |
| `publish_first.payload.json` | any |  | JSON payload (serialized compactly) |
| `publish_first.payload.text` | string |  | UTF-8 text payload |
| `publish_first.properties` | object |  | MQTT 5 properties (e.g. response_topic, correlation_data) |
| `publish_first.properties.content_type` | string |  | MQTT 5 content type (e.g. application/json) |
| `publish_first.properties.correlation_data` | string |  | MQTT 5 correlation data as text |
| `publish_first.properties.correlation_data_base64` | string |  | MQTT 5 correlation data as base64 (binary) |
| `publish_first.properties.message_expiry` | integer |  | MQTT 5 message expiry interval in seconds |
| `publish_first.properties.payload_format` | integer |  | MQTT 5 payload format indicator: 0 = bytes, 1 = UTF-8 text |
| `publish_first.properties.response_topic` | string |  | MQTT 5 response topic for request/response |
| `publish_first.properties.user_properties` | map&lt;string, string&gt; |  | MQTT 5 user properties (key/value) |
| `publish_first.qos` | integer |  | QoS 0-2 |
| `publish_first.retain` | boolean |  | retain flag |
| `publish_first.topic` | string |  | **required.** topic to publish to |
| `qos` | integer |  | default maximum QoS 0-2 (default 0) |
| `session_expiry_seconds` | integer |  | MQTT 5 session expiry interval in seconds |
| `topic` | string |  | single topic filter (shortcut for topics) |
| `topics` | object[] |  | topic filters with per-filter options |
| `topics[].filter` | string |  | **required.** topic filter; wildcards + (one level) and # (rest); shared: $share/&lt;group&gt;/&lt;filter&gt; |
| `topics[].no_local` | boolean |  | MQTT 5: do not receive messages published by this client |
| `topics[].qos` | integer |  | maximum QoS for this filter (default: the top-level qos) |
| `topics[].retain_as_published` | boolean |  | MQTT 5: keep the original retain flag |
| `topics[].retain_handling` | integer |  | MQTT 5: 0 send retained messages, 1 only for new subscriptions, 2 never |
| `username` | string |  | broker username (overrides auth) |
| `will` | object |  | last-will message |
| `will.delay_seconds` | integer |  | MQTT 5 will delay interval in seconds |
| `will.payload` | object |  | will payload |
| `will.payload.base64` | string |  | binary payload as base64 (small payloads only) |
| `will.payload.file` | string |  | path of a file inside an allowed read directory |
| `will.payload.json` | any |  | JSON payload (serialized compactly) |
| `will.payload.text` | string |  | UTF-8 text payload |
| `will.properties` | object |  | MQTT 5 will properties |
| `will.properties.content_type` | string |  | MQTT 5 content type (e.g. application/json) |
| `will.properties.correlation_data` | string |  | MQTT 5 correlation data as text |
| `will.properties.correlation_data_base64` | string |  | MQTT 5 correlation data as base64 (binary) |
| `will.properties.message_expiry` | integer |  | MQTT 5 message expiry interval in seconds |
| `will.properties.payload_format` | integer |  | MQTT 5 payload format indicator: 0 = bytes, 1 = UTF-8 text |
| `will.properties.response_topic` | string |  | MQTT 5 response topic for request/response |
| `will.properties.user_properties` | map&lt;string, string&gt; |  | MQTT 5 user properties (key/value) |
| `will.qos` | integer |  | will QoS 0-2 |
| `will.retain` | boolean |  | retain the will message |
| `will.topic` | string |  | **required.** will topic |
| `ws_headers` | map&lt;string, string&gt; |  | extra HTTP headers for the ws:// / wss:// handshake |

Also accepts the [network options](#common-options) and [stream limits](#common-options).

</details>

### `messaging`: Message brokers and IoT

10 tools.

<details>
<summary><code>amqp_consume</code>: AMQP consume <sub>(mutating)</sub></summary>

Bounded consume from an AMQP 0-9-1 queue (RabbitMQ): collects up to max_messages within max_duration_seconds (or until idle). Give queue, or exchange (+routing_key) to bind a temporary queue. ack_mode: ack (default), reject, requeue (peek without removing), none (auto-ack). mode=get polls with basic.get and stops when the queue is empty. Returns body, properties, headers, delivery tag, redelivered flag, exchange and routing key.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `ack_mode` | string |  | ack (default: remove collected messages), reject (drop or dead-letter), requeue (peek: leave messages on the queue) or none (auto-ack) |
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `binding_arguments` | object |  | binding arguments (e.g. x-match for headers exchanges) |
| `consumer_arguments` | object |  | basic.consume arguments, e.g. x-stream-offset for streams |
| `consumer_tag` | string |  |  |
| `declare` | object |  | exchange/queue/bindings to declare before consuming |
| `declare.bindings` | object[] |  |  |
| `declare.bindings[].arguments` | object |  | binding arguments, e.g. x-match for headers exchanges |
| `declare.bindings[].exchange` | string |  | **required.** source exchange |
| `declare.bindings[].queue` | string |  | queue name (default: the declared queue) |
| `declare.bindings[].routing_key` | string |  | binding key (topic patterns allowed for topic exchanges) |
| `declare.exchange` | object |  |  |
| `declare.exchange.arguments` | object |  | x-arguments, e.g. alternate-exchange |
| `declare.exchange.auto_delete` | boolean |  |  |
| `declare.exchange.durable` | boolean |  |  |
| `declare.exchange.internal` | boolean |  |  |
| `declare.exchange.name` | string |  | **required.** exchange name |
| `declare.exchange.passive` | boolean |  | only check that the exchange exists |
| `declare.exchange.type` | string |  | direct (default), fanout, topic, headers or a plugin type |
| `declare.queue` | object |  |  |
| `declare.queue.arguments` | object |  | x-arguments, e.g. x-message-ttl, x-queue-type, x-dead-letter-exchange |
| `declare.queue.auto_delete` | boolean |  |  |
| `declare.queue.durable` | boolean |  |  |
| `declare.queue.exclusive` | boolean |  | exclusive to this connection (deleted when the call ends) |
| `declare.queue.name` | string |  | queue name (empty = server-generated) |
| `declare.queue.passive` | boolean |  | only check that the queue exists (returns its message count) |
| `exchange` | string |  | bind the queue (or a temporary queue) to this exchange before consuming |
| `exclusive` | boolean |  | request exclusive consumer access |
| `heartbeat_seconds` | number |  | requested heartbeat interval (default 10) |
| `max_response_bytes` | integer |  | maximum total message bytes returned (default 1 MiB) |
| `mode` | string |  | consume (default: push delivery, waits for messages) or get (basic.get polling; stops when the queue is empty) |
| `prefetch` | integer |  | basic.qos prefetch count (default: max_messages) |
| `queue` | string |  | queue to consume from; when empty, a temporary exclusive queue is declared and bound to exchange |
| `routing_key` | string |  | binding key used with exchange (topic patterns allowed) |
| `sasl_mechanism` | string |  | PLAIN (default), AMQPLAIN or EXTERNAL (client certificate) |
| `url` | string | yes | amqp://user:pass@host:5672/vhost or amqps://... (vhost is the URL path; %2F for /) |
| `vhost` | string |  | override the virtual host from the URL |

Also accepts the [network options](#common-options) and [stream limits](#common-options).

</details>

<details>
<summary><code>amqp_publish</code>: AMQP publish <sub>(mutating)</sub></summary>

Publish one message to an AMQP 0-9-1 broker (RabbitMQ): exchange, routing_key, payload (text/json/base64/file), properties (content_type, delivery_mode, headers, ...). Publisher confirms are on by default and the result reports ack/nack; with mandatory=true an unroutable message is reported under returned. Optional declare sets up exchange/queue/bindings first.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `confirm` | boolean |  | use publisher confirms and wait for ack/nack (default true) |
| `declare` | object |  | exchange/queue/bindings to declare before publishing |
| `declare.bindings` | object[] |  |  |
| `declare.bindings[].arguments` | object |  | binding arguments, e.g. x-match for headers exchanges |
| `declare.bindings[].exchange` | string |  | **required.** source exchange |
| `declare.bindings[].queue` | string |  | queue name (default: the declared queue) |
| `declare.bindings[].routing_key` | string |  | binding key (topic patterns allowed for topic exchanges) |
| `declare.exchange` | object |  |  |
| `declare.exchange.arguments` | object |  | x-arguments, e.g. alternate-exchange |
| `declare.exchange.auto_delete` | boolean |  |  |
| `declare.exchange.durable` | boolean |  |  |
| `declare.exchange.internal` | boolean |  |  |
| `declare.exchange.name` | string |  | **required.** exchange name |
| `declare.exchange.passive` | boolean |  | only check that the exchange exists |
| `declare.exchange.type` | string |  | direct (default), fanout, topic, headers or a plugin type |
| `declare.queue` | object |  |  |
| `declare.queue.arguments` | object |  | x-arguments, e.g. x-message-ttl, x-queue-type, x-dead-letter-exchange |
| `declare.queue.auto_delete` | boolean |  |  |
| `declare.queue.durable` | boolean |  |  |
| `declare.queue.exclusive` | boolean |  | exclusive to this connection (deleted when the call ends) |
| `declare.queue.name` | string |  | queue name (empty = server-generated) |
| `declare.queue.passive` | boolean |  | only check that the queue exists (returns its message count) |
| `exchange` | string |  | exchange to publish to (default "" = default exchange, routing_key = queue name) |
| `heartbeat_seconds` | number |  | requested heartbeat interval (default 10) |
| `mandatory` | boolean |  | ask the broker to return the message if it cannot be routed to any queue |
| `payload` | object |  | message body: text, json, base64 or file |
| `payload.base64` | string |  | binary payload as base64 (small payloads only) |
| `payload.file` | string |  | path of a file inside an allowed read directory |
| `payload.json` | any |  | JSON payload (serialized compactly) |
| `payload.text` | string |  | UTF-8 text payload |
| `properties` | object |  | message properties and headers |
| `properties.app_id` | string |  |  |
| `properties.content_encoding` | string |  | MIME content encoding, e.g. gzip |
| `properties.content_type` | string |  | MIME type (default: derived from the payload kind) |
| `properties.correlation_id` | string |  |  |
| `properties.delivery_mode` | integer |  | 1 = transient, 2 = persistent |
| `properties.expiration` | string |  | per-message TTL in milliseconds as a string, e.g. "60000" |
| `properties.headers` | object |  | application headers table (strings, numbers, booleans, nested objects, arrays) |
| `properties.message_id` | string |  |  |
| `properties.persistent` | boolean |  | shortcut for delivery_mode=2 |
| `properties.priority` | integer |  | message priority 0-9 |
| `properties.reply_to` | string |  |  |
| `properties.timestamp` | string |  | RFC 3339 time, unix seconds, or "now" |
| `properties.type` | string |  | application message type name |
| `properties.user_id` | string |  | must match the authenticated user on RabbitMQ |
| `routing_key` | string |  | routing key |
| `sasl_mechanism` | string |  | PLAIN (default), AMQPLAIN or EXTERNAL (client certificate) |
| `url` | string | yes | amqp://user:pass@host:5672/vhost or amqps://... (vhost is the URL path; %2F for /) |
| `vhost` | string |  | override the virtual host from the URL |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>coap_request</code>: CoAP request <sub>(mutating)</sub></summary>

Send a CoAP request (GET/POST/PUT/DELETE/FETCH/PATCH) over UDP (coap://), TCP (coap+tcp://) or TLS (coaps+tcp://); DTLS is not supported. Confirmable by default, content_format/accept by name or number, extra options (uri-query, etag, ...), payload as text/JSON/base64/file with block-wise transfer. Returns the response code (e.g. 2.05 Content), options and payload. observe=true registers an observation and collects notifications until max_notifications or max_duration_seconds.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `accept` | string |  | Accept option: number or content format name |
| `confirmable` | boolean |  | send as Confirmable with retransmission (default true; UDP only) |
| `content_format` | string |  | payload content format: number or name (text/plain, application/json, application/cbor, application/octet-stream, ...); default from the payload |
| `idle_timeout_seconds` | number |  | observe: stop when no notification arrives for this many seconds |
| `max_duration_seconds` | number |  | observe: stop after this many seconds (default 10) |
| `max_notifications` | integer |  | observe: stop after this many notifications (default 100) |
| `max_response_bytes` | integer |  | maximum response payload bytes (default 1 MiB) |
| `method` | string |  | GET (default), POST, PUT, DELETE, FETCH, PATCH or iPATCH |
| `observe` | boolean |  | register an observation (GET) and collect notifications |
| `options` | object[] |  | extra CoAP options |
| `options[].name` | string |  | **required.** option name or number: uri-query, accept, etag, if-match, if-none-match, max-age, uri-host, proxy-uri, ... |
| `options[].value` | string |  | value: decimal for integer options, hex for opaque options (etag, if-match), text otherwise |
| `payload` | object |  | request payload: text, json, base64 or file (large payloads use block-wise transfer) |
| `payload.base64` | string |  | binary payload as base64 (small payloads only) |
| `payload.file` | string |  | path of a file inside an allowed read directory |
| `payload.json` | any |  | JSON payload (serialized compactly) |
| `payload.text` | string |  | UTF-8 text payload |
| `query` | string[] |  | extra Uri-Query values (key=value) |
| `url` | string | yes | coap://host[:5683]/path?query (UDP), coap+tcp:// (TCP) or coaps+tcp:// (TLS); coaps:// (DTLS) is not supported |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>kafka_consume</code>: Kafka consume <sub>(read-only)</sub></summary>

Bounded consume from Kafka topics: collects up to max_messages within max_duration_seconds (or until idle). start: earliest (default), latest, offset, tail or timestamp; or exact partition_offsets. Without group, partitions are read directly and nothing is committed; with group (and commit=true) offsets of returned records are committed. Returns topic, partition, offset, timestamp, key, value and headers.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `brokers` | string[] | yes | seed brokers as host:port (default port 9092) |
| `client_id` | string |  | Kafka client.id (default netkit-mcp) |
| `commit` | boolean |  | with group: commit offsets of the returned records |
| `group` | string |  | consumer group id (default: none, read partitions directly without committing) |
| `isolation_level` | string |  | read_uncommitted (default) or read_committed |
| `max_response_bytes` | integer |  | maximum total value bytes returned (default 1 MiB) |
| `offset` | integer |  | offset for start=offset, or record count for start=tail |
| `partition_offsets` | map&lt;string, integer&gt; |  | exact start offset per partition, e.g. {"0": 42, "3": 0} (direct consuming, no group) |
| `partitions` | integer[] |  | only these partitions (direct consuming, no group) |
| `sasl` | object |  | SASL authentication; auth basic alone implies SASL PLAIN |
| `sasl.mechanism` | string |  | PLAIN (default), SCRAM-SHA-256 or SCRAM-SHA-512 |
| `sasl.password` | string |  | SASL password (default: from auth basic) |
| `sasl.username` | string |  | SASL username (default: from auth basic) |
| `start` | string |  | earliest (default), latest, offset (uses offset), tail (last &lt;offset&gt; records per partition) or timestamp (uses timestamp) |
| `timestamp` | string |  | for start=timestamp: RFC 3339 or unix milliseconds |
| `tls` | boolean |  | connect with TLS (implied by ca_cert, client_cert, server_name, insecure_skip_verify or auth mtls) |
| `topics` | string[] | yes | topics to consume |

Also accepts the [network options](#common-options) and [stream limits](#common-options).

</details>

<details>
<summary><code>kafka_produce</code>: Kafka produce <sub>(mutating)</sub></summary>

Produce records to Kafka and wait for the broker acks. Each record has key/value (text, json, base64 or file), headers and an optional partition. Supports acks (all/leader/none), compression (gzip/snappy/lz4/zstd), idempotence (default on), SASL PLAIN/SCRAM and TLS. Returns partition, offset, timestamp or error per record.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `acks` | string |  | all (default), leader or none |
| `allow_auto_topic_creation` | boolean |  | let the broker auto-create a missing topic (if enabled on the broker) |
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `brokers` | string[] | yes | seed brokers as host:port (default port 9092) |
| `client_id` | string |  | Kafka client.id (default netkit-mcp) |
| `compression` | string |  | none (default), gzip, snappy, lz4 or zstd |
| `idempotent` | boolean |  | idempotent producer (default true; requires acks=all) |
| `records` | object[] | yes | records to produce, in order |
| `records[].headers` | map&lt;string, string&gt; |  | record headers |
| `records[].key` | object |  | record key (text, json, base64 or file); omitted = null key |
| `records[].key.base64` | string |  | binary payload as base64 (small payloads only) |
| `records[].key.file` | string |  | path of a file inside an allowed read directory |
| `records[].key.json` | any |  | JSON payload (serialized compactly) |
| `records[].key.text` | string |  | UTF-8 text payload |
| `records[].partition` | integer |  | explicit partition (default: murmur2 hash of the key, like the Java client) |
| `records[].timestamp` | string |  | record timestamp, RFC 3339 or unix milliseconds (default: now) |
| `records[].topic` | string |  | override the call's topic for this record |
| `records[].value` | object |  | record value (text, json, base64 or file); omitted = null value (tombstone) |
| `records[].value.base64` | string |  | binary payload as base64 (small payloads only) |
| `records[].value.file` | string |  | path of a file inside an allowed read directory |
| `records[].value.json` | any |  | JSON payload (serialized compactly) |
| `records[].value.text` | string |  | UTF-8 text payload |
| `sasl` | object |  | SASL authentication; auth basic alone implies SASL PLAIN |
| `sasl.mechanism` | string |  | PLAIN (default), SCRAM-SHA-256 or SCRAM-SHA-512 |
| `sasl.password` | string |  | SASL password (default: from auth basic) |
| `sasl.username` | string |  | SASL username (default: from auth basic) |
| `tls` | boolean |  | connect with TLS (implied by ca_cert, client_cert, server_name, insecure_skip_verify or auth mtls) |
| `topic` | string |  | topic for records that do not set their own |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>nats_publish</code>: NATS publish <sub>(mutating)</sub></summary>

Publish one message to a core NATS subject (with optional headers and reply subject) and flush it to the server. Auth: username/password, token, NKey seed, .creds, or the auth object; TLS/mTLS via tls:// or TLS options. JetStream is not supported yet (core NATS only).

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `creds` | string |  | NATS .creds (user JWT + seed) inline, or a file path in an allowed read directory |
| `headers` | map&lt;string, string&gt; |  | NATS message headers (requires server 2.2+) |
| `nkey_seed` | string |  | NKey user seed (SU...) inline, or a file path in an allowed read directory |
| `password` | string |  | password (overrides auth) |
| `payload` | object |  | payload: text, json, base64 or file (omit for empty) |
| `payload.base64` | string |  | binary payload as base64 (small payloads only) |
| `payload.file` | string |  | path of a file inside an allowed read directory |
| `payload.json` | any |  | JSON payload (serialized compactly) |
| `payload.text` | string |  | UTF-8 text payload |
| `reply_to` | string |  | reply subject to attach to the message |
| `subject` | string | yes | subject to publish to (no wildcards) |
| `tls_handshake_first` | boolean |  | perform the TLS handshake before the NATS INFO exchange |
| `token` | string |  | authentication token (overrides auth bearer) |
| `url` | string | yes | NATS server URL(s), comma-separated: nats://host:4222, tls://host:4222, ws:// or wss://; bare host:port means nats:// |
| `username` | string |  | user name (overrides auth) |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>nats_request</code>: NATS request/reply <sub>(mutating)</sub></summary>

Send a core NATS request and wait for the first reply (timeout_seconds, default 30). Returns the reply data (text or base64) and headers; reports 'no responders' when nothing listens on the subject. JetStream is not supported yet.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `creds` | string |  | NATS .creds (user JWT + seed) inline, or a file path in an allowed read directory |
| `headers` | map&lt;string, string&gt; |  | NATS message headers (requires server 2.2+) |
| `nkey_seed` | string |  | NKey user seed (SU...) inline, or a file path in an allowed read directory |
| `password` | string |  | password (overrides auth) |
| `payload` | object |  | payload: text, json, base64 or file (omit for empty) |
| `payload.base64` | string |  | binary payload as base64 (small payloads only) |
| `payload.file` | string |  | path of a file inside an allowed read directory |
| `payload.json` | any |  | JSON payload (serialized compactly) |
| `payload.text` | string |  | UTF-8 text payload |
| `reply_to` | string |  | reply subject to attach to the message |
| `subject` | string | yes | subject to publish to (no wildcards) |
| `tls_handshake_first` | boolean |  | perform the TLS handshake before the NATS INFO exchange |
| `token` | string |  | authentication token (overrides auth bearer) |
| `url` | string | yes | NATS server URL(s), comma-separated: nats://host:4222, tls://host:4222, ws:// or wss://; bare host:port means nats:// |
| `username` | string |  | user name (overrides auth) |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>nats_subscribe</code>: NATS subscribe <sub>(read-only)</sub></summary>

Subscribe to core NATS subjects (wildcards * and &gt;, optional queue group) and collect messages until max_messages, max_duration_seconds (default 10) or idle_timeout_seconds. publish_first sends a message after subscribing. Returns subject, data, headers and reply subject per message. JetStream is not supported yet.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `creds` | string |  | NATS .creds (user JWT + seed) inline, or a file path in an allowed read directory |
| `nkey_seed` | string |  | NKey user seed (SU...) inline, or a file path in an allowed read directory |
| `password` | string |  | password (overrides auth) |
| `publish_first` | object |  | publish this message after subscribing (request/response testing) |
| `publish_first.headers` | map&lt;string, string&gt; |  | message headers |
| `publish_first.payload` | object |  | payload: text, json, base64 or file |
| `publish_first.payload.base64` | string |  | binary payload as base64 (small payloads only) |
| `publish_first.payload.file` | string |  | path of a file inside an allowed read directory |
| `publish_first.payload.json` | any |  | JSON payload (serialized compactly) |
| `publish_first.payload.text` | string |  | UTF-8 text payload |
| `publish_first.reply_to` | string |  | reply subject (subscribe to it as well to capture replies) |
| `publish_first.subject` | string |  | **required.** subject to publish to |
| `queue` | string |  | queue group name (messages are load-balanced across members) |
| `subject` | string |  | subject to subscribe to; wildcards * (one token) and &gt; (rest) |
| `subjects` | string[] |  | several subjects |
| `tls_handshake_first` | boolean |  | perform the TLS handshake before the NATS INFO exchange |
| `token` | string |  | authentication token (overrides auth bearer) |
| `url` | string | yes | NATS server URL(s), comma-separated: nats://host:4222, tls://host:4222, ws:// or wss://; bare host:port means nats:// |
| `username` | string |  | user name (overrides auth) |

Also accepts the [network options](#common-options) and [stream limits](#common-options).

</details>

<details>
<summary><code>stomp_send</code>: STOMP send <sub>(mutating)</sub></summary>

Send one message to a STOMP 1.0-1.2 broker (ActiveMQ, Artemis, RabbitMQ STOMP plugin): destination, payload (text/json/base64/file), content_type and headers. Waits for a RECEIPT by default so delivery to the broker is confirmed.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `address` | string | yes | host:port, stomp://host:port or stomp+ssl://host:port (default port 61613, 61614 with TLS) |
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `connect_headers` | map&lt;string, string&gt; |  | extra CONNECT frame headers |
| `content_type` | string |  | content-type header (default: derived from the payload kind) |
| `destination` | string | yes | destination, e.g. /queue/orders or /topic/news |
| `headers` | map&lt;string, string&gt; |  | extra SEND headers (e.g. persistent, priority, expires, reply-to) |
| `heart_beat_seconds` | number[] |  | [send, receive] heart-beat intervals in seconds (default [0, 0] = off) |
| `host` | string |  | CONNECT host header / virtual host (default: the target host; RabbitMQ uses the vhost, e.g. /) |
| `login` | string |  | STOMP login (default: from auth basic) |
| `passcode` | string |  | STOMP passcode (default: from auth basic) |
| `payload` | object |  | message body: text, json, base64 or file |
| `payload.base64` | string |  | binary payload as base64 (small payloads only) |
| `payload.file` | string |  | path of a file inside an allowed read directory |
| `payload.json` | any |  | JSON payload (serialized compactly) |
| `payload.text` | string |  | UTF-8 text payload |
| `receipt` | boolean |  | request a RECEIPT and wait for it (default true) |
| `tls` | boolean |  | connect with TLS (implied by stomp+ssl:// and by ca_cert, client_cert, server_name, insecure_skip_verify) |
| `versions` | string[] |  | accepted protocol versions: 1.0, 1.1, 1.2 (default all) |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>stomp_subscribe</code>: STOMP subscribe <sub>(mutating)</sub></summary>

Bounded STOMP subscription: collects up to max_messages within max_duration_seconds (or until idle) from a destination. ack: auto (default), client or client-individual; with client acks, settle chooses ack (default), nack or none. Returns body, headers and message-id per message.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `ack` | string |  | auto (default), client or client-individual |
| `address` | string | yes | host:port, stomp://host:port or stomp+ssl://host:port (default port 61613, 61614 with TLS) |
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `connect_headers` | map&lt;string, string&gt; |  | extra CONNECT frame headers |
| `destination` | string | yes | destination to subscribe to |
| `headers` | map&lt;string, string&gt; |  | extra SUBSCRIBE headers (e.g. selector, prefetch-count, durable-subscription-name) |
| `heart_beat_seconds` | number[] |  | [send, receive] heart-beat intervals in seconds (default [0, 0] = off) |
| `host` | string |  | CONNECT host header / virtual host (default: the target host; RabbitMQ uses the vhost, e.g. /) |
| `login` | string |  | STOMP login (default: from auth basic) |
| `max_response_bytes` | integer |  | maximum total message bytes returned (default 1 MiB) |
| `passcode` | string |  | STOMP passcode (default: from auth basic) |
| `receipt` | boolean |  | request a RECEIPT for the SUBSCRIBE frame |
| `settle` | string |  | with client acks: ack (default), nack, or none (leave unacknowledged so the broker redelivers) |
| `tls` | boolean |  | connect with TLS (implied by stomp+ssl:// and by ca_cert, client_cert, server_name, insecure_skip_verify) |
| `versions` | string[] |  | accepted protocol versions: 1.0, 1.1, 1.2 (default all) |

Also accepts the [network options](#common-options) and [stream limits](#common-options).

</details>

### `transfer`: File transfer

8 tools.

<details>
<summary><code>ftp_download</code>: FTP download <sub>(read-only)</sub></summary>

Download a file from an FTP or FTPS server to save_to (streamed to disk, never returned inline). Will not replace an existing local file unless overwrite=true; resume=true continues a partial download (REST).

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `disable_epsv` | boolean |  | use PASV instead of EPSV for data connections |
| `host` | string | yes | FTP server host name or IP |
| `overwrite` | boolean |  | replace an existing local file |
| `port` | integer |  | port (default 21, or 990 for implicit TLS) |
| `remote_path` | string | yes | remote file to download |
| `resume` | boolean |  | continue a partial download with REST: keep the bytes already in save_to and fetch the rest |
| `save_to` | string | yes | local destination path (inside an allowed write directory) |
| `tls` | string |  | none (plain FTP, default), explicit (AUTH TLS upgrade) or implicit (FTPS, TLS from the start) |
| `trust_pasv_ip` | boolean |  | connect data channels to the address in the PASV reply even if it differs from the control host (still SSRF-checked); default uses the control host |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>ftp_list</code>: FTP list <sub>(read-only)</sub></summary>

List a directory on an FTP or FTPS server (MLSD when supported, falling back to LIST): name, type, size, mtime, symlink target. recursive=true walks subdirectories within max_depth/max_entries.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `disable_epsv` | boolean |  | use PASV instead of EPSV for data connections |
| `host` | string | yes | FTP server host name or IP |
| `max_depth` | integer |  | maximum depth when recursive (default 5, max 20) |
| `max_entries` | integer |  | maximum entries returned (default 1000, max 10000) |
| `path` | string |  | remote directory (default: the login directory) |
| `port` | integer |  | port (default 21, or 990 for implicit TLS) |
| `recursive` | boolean |  | descend into subdirectories (bounded by max_depth and max_entries) |
| `tls` | string |  | none (plain FTP, default), explicit (AUTH TLS upgrade) or implicit (FTPS, TLS from the start) |
| `trust_pasv_ip` | boolean |  | connect data channels to the address in the PASV reply even if it differs from the control host (still SSRF-checked); default uses the control host |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>ftp_upload</code>: FTP upload <sub>(mutating)</sub></summary>

Upload a local file to an FTP or FTPS server (tls: explicit or implicit), streamed from disk. Fails if the remote file exists unless overwrite=true; mkdirs creates parent directories. Login with auth.type=basic or anonymously. timeout_seconds bounds connecting and inactivity.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `disable_epsv` | boolean |  | use PASV instead of EPSV for data connections |
| `file` | string | yes | path of the local file to upload (inside an allowed read directory) |
| `host` | string | yes | FTP server host name or IP |
| `mkdirs` | boolean |  | create missing remote parent directories |
| `overwrite` | boolean |  | replace an existing remote file (default: fail if it exists) |
| `port` | integer |  | port (default 21, or 990 for implicit TLS) |
| `remote_path` | string | yes | remote file path; a trailing / uploads into that directory with the local file name |
| `tls` | string |  | none (plain FTP, default), explicit (AUTH TLS upgrade) or implicit (FTPS, TLS from the start) |
| `trust_pasv_ip` | boolean |  | connect data channels to the address in the PASV reply even if it differs from the control host (still SSRF-checked); default uses the control host |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>s3_multipart_upload</code>: S3 multipart upload <sub>(mutating)</sub></summary>

Upload a local file to S3 or an S3-compatible store (MinIO, R2, ...) with a SigV4-signed multipart upload: CreateMultipartUpload, UploadPart (streamed from disk, retried), CompleteMultipartUpload. On failure the upload is aborted unless keep_on_failure=true; resume a kept upload with resume_upload_id. For a single presigned URL use http_upload instead. timeout_seconds applies per request (each part).

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `aws` | object |  | credentials (alternatively auth.type=aws_sigv4 with auth.aws) |
| `aws.access_key_id` | string |  | **required.** AWS access key id |
| `aws.secret_access_key` | string |  | **required.** AWS secret access key |
| `aws.session_token` | string |  | session token for temporary credentials |
| `bucket` | string | yes | bucket name |
| `content_type` | string |  | object Content-Type (default: detected from the file extension) |
| `endpoint` | string |  | S3-compatible endpoint URL (MinIO, R2, Wasabi, ...); default https://s3.&lt;region&gt;.amazonaws.com |
| `file` | string | yes | path of the file to upload (inside an allowed read directory) |
| `headers` | map&lt;string, string&gt; |  | extra headers for CreateMultipartUpload, e.g. x-amz-acl or x-amz-server-side-encryption |
| `keep_on_failure` | boolean |  | do not abort the multipart upload on failure, so it can be resumed with resume_upload_id |
| `key` | string | yes | object key, e.g. backups/2026/db.tar.gz |
| `max_retries` | integer |  | retries per part on network errors / 5xx (default 3) |
| `metadata` | map&lt;string, string&gt; |  | user metadata (sent as x-amz-meta-&lt;key&gt;) |
| `part_size` | integer |  | bytes per part (default 8 MiB, min 5 MiB; raised automatically to stay within 10000 parts) |
| `path_style` | boolean |  | path-style URLs (endpoint/bucket/key); default true for a custom endpoint, false for AWS (virtual-hosted) |
| `region` | string |  | signing region (default auth.aws.region, else us-east-1; R2 uses auto) |
| `resume_upload_id` | string |  | continue this multipart upload: parts already on the server (matching size/MD5) are skipped |
| `storage_class` | string |  | e.g. STANDARD_IA, GLACIER_IR, INTELLIGENT_TIERING |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>sftp_download</code>: SFTP download <sub>(read-only)</sub></summary>

Download a remote file from an SFTP server to save_to (streamed to disk, never returned inline). Requires auth.type ssh_password (auth.username, auth.password) or ssh_key (auth.username, auth.ssh.private_key, optional auth.ssh.passphrase); host key verification via auth.ssh.known_hosts or auth.ssh.host_key_fingerprint (or explicitly auth.ssh.insecure_ignore_host_key=true). Will not replace an existing local file unless overwrite=true; resume=true continues a partial download.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object | yes | credentials; see [The `auth` object](#the-auth-object) |
| `host` | string | yes | SFTP server host name or IP |
| `overwrite` | boolean |  | replace an existing local file |
| `port` | integer |  | SSH port (default 22) |
| `remote_path` | string | yes | remote file to download |
| `resume` | boolean |  | continue a partial download: keep the bytes already in save_to and fetch the rest |
| `save_to` | string | yes | local destination path (inside an allowed write directory) |
| `timeout_seconds` | number |  | connect timeout and maximum inactivity during the transfer, in seconds (default 30) |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>sftp_list</code>: SFTP list <sub>(read-only)</sub></summary>

List a remote directory on an SFTP server: name, size, mode, mtime, is_dir and symlink target. recursive=true walks subdirectories within max_depth/max_entries. Requires auth.type ssh_password (auth.username, auth.password) or ssh_key (auth.username, auth.ssh.private_key, optional auth.ssh.passphrase); host key verification via auth.ssh.known_hosts or auth.ssh.host_key_fingerprint (or explicitly auth.ssh.insecure_ignore_host_key=true).

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object | yes | credentials; see [The `auth` object](#the-auth-object) |
| `host` | string | yes | SFTP server host name or IP |
| `max_depth` | integer |  | maximum depth when recursive (default 5, max 20) |
| `max_entries` | integer |  | maximum entries returned (default 1000, max 10000) |
| `path` | string |  | remote directory (default: the login directory) |
| `port` | integer |  | SSH port (default 22) |
| `recursive` | boolean |  | descend into subdirectories (bounded by max_depth and max_entries) |
| `timeout_seconds` | number |  | connect timeout and maximum inactivity during the transfer, in seconds (default 30) |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>sftp_upload</code>: SFTP upload <sub>(mutating)</sub></summary>

Upload a local file to an SFTP server (streamed, concurrent writes). Requires auth.type ssh_password (auth.username, auth.password) or ssh_key (auth.username, auth.ssh.private_key, optional auth.ssh.passphrase); host key verification via auth.ssh.known_hosts or auth.ssh.host_key_fingerprint (or explicitly auth.ssh.insecure_ignore_host_key=true). Fails if the remote file exists unless overwrite=true; mkdirs creates parent directories. Every result reports the server's host key fingerprint so it can be pinned.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object | yes | credentials; see [The `auth` object](#the-auth-object) |
| `file` | string | yes | path of the local file to upload (inside an allowed read directory) |
| `host` | string | yes | SFTP server host name or IP |
| `mkdirs` | boolean |  | create missing remote parent directories |
| `overwrite` | boolean |  | replace an existing remote file (default: fail if it exists) |
| `port` | integer |  | SSH port (default 22) |
| `preserve` | boolean |  | copy the local permission bits and modification time to the remote file |
| `remote_path` | string | yes | remote file path; a trailing / uploads into that directory with the local file name |
| `timeout_seconds` | number |  | connect timeout and maximum inactivity during the transfer, in seconds (default 30) |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>tus_upload</code>: tus resumable upload <sub>(mutating)</sub></summary>

Upload a local file with the tus 1.0 resumable protocol: discovers capabilities (OPTIONS), creates the upload (POST) and sends it in PATCH chunks with per-chunk retries. The result (and any error) includes upload_url: pass it back as upload_url to resume an interrupted upload from the server's offset. timeout_seconds applies per HTTP request (each chunk). Auth and the SSRF guard apply.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `checksum` | boolean |  | send Upload-Checksum (sha1) with each chunk when the server supports the checksum extension |
| `chunk_size` | integer |  | bytes per PATCH request (default 8 MiB, max 256 MiB) |
| `content_type` | string |  | filetype sent in Upload-Metadata (default: detected from the extension) |
| `creation_with_upload` | boolean |  | send the first chunk in the creation POST (creation-with-upload extension) |
| `file` | string | yes | path of the file to upload (inside an allowed read directory) |
| `filename` | string |  | filename sent in Upload-Metadata (default: the local file name) |
| `headers` | map&lt;string, string&gt; |  | extra HTTP headers for every request |
| `max_retries` | integer |  | retries per chunk on network errors / 5xx / offset conflicts, with backoff (default 3) |
| `metadata` | map&lt;string, string&gt; |  | extra Upload-Metadata key/values (values are base64-encoded for you) |
| `upload_url` | string |  | resume an upload created earlier (the upload_url from a previous result or error) |
| `url` | string |  | tus creation endpoint (POST target), e.g. https://host/files/; required unless upload_url is set |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

### `lowlevel`: Low-level network

4 tools.

<details>
<summary><code>dns_query</code>: DNS query <sub>(read-only)</sub></summary>

Resolve any DNS record type (A, AAAA, MX, TXT, SRV, CAA, DNSKEY, HTTPS, PTR for IPs, ANY ...) against a chosen resolver over udp (TCP retry on truncation), tcp, dot (DNS over TLS) or doh (DNS over HTTPS, RFC 8484). Flags: rd, cd, ad, dnssec (DO bit), EDNS buffer size and client subnet. Returns rcode, flags, structured answer/authority/additional records and dig-style text. The resolver address is subject to the SSRF guard and port allowlist.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `ad` | boolean |  | set the AD flag in the query (ask for the authenticated-data bit) |
| `cd` | boolean |  | set the CD (checking disabled) flag |
| `class` | string |  | query class: IN (default), CH, HS |
| `client_subnet` | string |  | EDNS client subnet (ECS), e.g. 203.0.113.0/24 |
| `dnssec` | boolean |  | set the EDNS DO bit to request DNSSEC records (RRSIG, ...) |
| `doh_method` | string |  | doh only: POST (default) or GET |
| `edns_buffer_size` | integer |  | EDNS UDP buffer size (default 1232) |
| `name` | string | yes | domain name to query; an IP address with type PTR (or no type) does a reverse lookup |
| `no_edns` | boolean |  | send a plain query without an EDNS OPT record |
| `no_tcp_fallback` | boolean |  | udp: return the truncated reply instead of retrying over TCP |
| `rd` | boolean |  | set the RD (recursion desired) flag (default true) |
| `server` | string |  | resolver: host[:port] for udp/tcp/dot (default port 53/853), an https URL for doh. Default: the system resolver (1.1.1.1 where unknown) |
| `transport` | string |  | udp (default; retries over TCP when truncated), tcp, dot (DNS over TLS) or doh (DNS over HTTPS) |
| `type` | string |  | record type: A (default), AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, CAA, DS, DNSKEY, RRSIG, HTTPS, SVCB, NAPTR, TLSA, ANY, TYPEnnn ... |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>tcp_request</code>: Raw TCP request <sub>(mutating)</sub></summary>

Open a raw TCP connection (optionally TLS) to host:port, send data (text with optional escapes, hex, base64, or a streamed file), then read until a delimiter, a byte count, connection close, or read_timeout_seconds of silence. Use it for line protocols (SMTP, Redis, memcached), banners and custom binary protocols. Returns received data, bytes sent/received, ended_by, timing and TLS details. Subject to the SSRF guard and port allowlist.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `alpn` | string[] |  | TLS ALPN protocols to offer, e.g. ["h2","http/1.1"] |
| `data` | string |  | data to send, interpreted according to encoding |
| `delimiter` | string |  | stop reading once this text is received (escapes apply when escapes=true) |
| `delimiter_hex` | string |  | stop reading once these bytes (hex) are received |
| `encoding` | string |  | encoding of data: text (default), hex or base64 |
| `escapes` | boolean |  | interpret backslash escapes in text data and text delimiter (\r \n \t \0 \xHH) |
| `file` | string |  | send this file (path inside an allowed read directory), streamed; instead of data |
| `half_close` | boolean |  | close the write side after sending (signals EOF to the server) |
| `hex_preview` | boolean |  | also return a hexdump of the first 512 received bytes |
| `host` | string | yes | target hostname or IP (may include :port) |
| `max_response_bytes` | integer |  | maximum received bytes returned (default 1 MiB) |
| `no_read` | boolean |  | only send; do not wait for a response |
| `output` | string |  | how to return received data: auto (text if printable else base64), text, base64 or hex |
| `port` | integer |  | target TCP port |
| `read_bytes` | integer |  | stop reading after this many bytes |
| `read_timeout_seconds` | number |  | stop when no data arrives for this many seconds (default 3 when no delimiter/read_bytes is set) |
| `tls` | boolean |  | wrap the connection in TLS (SNI = server_name or host) |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>tls_inspect</code>: Inspect TLS <sub>(read-only)</sub></summary>

Connect to a TLS server and report the negotiated version, cipher, ALPN, OCSP stapling and the full certificate chain (subject, issuer, SANs, validity, days_until_expiry, algorithms, SHA-256 fingerprint). Verification against system roots (plus ca_cert) and the hostname is reported separately (verification.trusted, chain_error, hostname_error), so expired, self-signed or mismatched certificates are still inspected. Optional: probe_versions (TLS 1.0-1.3 support), STARTTLS for smtp/imap/pop3/ftp, client certificates.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `alpn` | string[] |  | ALPN protocols to offer, e.g. ["h2","http/1.1"] |
| `host` | string | yes | server hostname or IP (may include :port); a https:// URL is also accepted |
| `include_pem` | boolean |  | include each certificate as PEM |
| `max_version` | string |  | maximum TLS version to offer (default 1.3) |
| `min_version` | string |  | minimum TLS version to offer: 1.0, 1.1, 1.2 or 1.3 (default 1.0) |
| `port` | integer |  | TCP port (default 443, or the STARTTLS protocol's port) |
| `probe_versions` | boolean |  | also probe which of TLS 1.0, 1.1, 1.2 and 1.3 the server accepts |
| `starttls` | string |  | upgrade a plaintext protocol first: smtp, imap, pop3 or ftp |

Also accepts the [network options](#common-options).

</details>

<details>
<summary><code>udp_request</code>: Raw UDP request <sub>(mutating)</sub></summary>

Send one UDP datagram (text with optional escapes, hex or base64) to host:port and collect up to max_responses reply datagrams within wait_seconds. Use it for UDP protocols such as NTP, SNMP, syslog, game or custom binary protocols. ended_by is max_responses or timeout (no reply is normal for fire-and-forget protocols). Subject to the SSRF guard and port allowlist.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `data` | string |  | data to send, interpreted according to encoding |
| `encoding` | string |  | encoding of data: text (default), hex or base64 |
| `escapes` | boolean |  | interpret backslash escapes in text data and text delimiter (\r \n \t \0 \xHH) |
| `hex_preview` | boolean |  | also return a hexdump of each reply (first 512 bytes) |
| `host` | string | yes | target hostname or IP (may include :port) |
| `max_response_bytes` | integer |  | maximum total reply bytes returned (default 1 MiB) |
| `max_responses` | integer |  | stop after this many reply datagrams (default 1, max 1000) |
| `output` | string |  | how to return reply data: auto (text if printable else base64), text, base64 or hex |
| `port` | integer |  | target UDP port |
| `wait_seconds` | number |  | how long to collect replies after sending (default 2) |

Also accepts the [network options](#common-options).

</details>

### `mcp`: MCP client

2 tools.

<details>
<summary><code>mcp_client_call_tool</code>: Call remote MCP tool <sub>(mutating)</sub></summary>

Connect to a remote MCP server over streamable HTTP (default) or legacy SSE and call one tool with arguments. Returns the content items (text as text; images, audio and blobs as base64 with size and sha256; resources and links), structured_content and is_error. A remote tool failure is a successful result with is_error=true. Use mcp_client_list_tools first to learn tool names and schemas. Spawning stdio servers is not supported.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `arguments` | object |  | arguments object for the remote tool |
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `headers` | map&lt;string, string&gt; |  | extra HTTP headers sent on every request |
| `tool` | string | yes | name of the remote tool to call |
| `transport` | string |  | streamable_http (default) or sse (legacy HTTP+SSE; url is then the SSE endpoint) |
| `url` | string | yes | HTTP(S) endpoint of the remote MCP server, e.g. https://example.com/mcp (stdio commands are not supported) |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>mcp_client_list_tools</code>: List remote MCP tools <sub>(read-only)</sub></summary>

Connect to a remote MCP server over streamable HTTP (default) or legacy SSE and list its tools (name, title, description, input schema), following pagination. compact=true returns names and descriptions only. Supports the shared auth object (bearer, oauth2, ...), headers and TLS options. Spawning stdio servers is not supported.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth` | object |  | credentials; see [The `auth` object](#the-auth-object) |
| `compact` | boolean |  | return only tool names and descriptions (no schemas) |
| `headers` | map&lt;string, string&gt; |  | extra HTTP headers sent on every request |
| `max_pages` | integer |  | maximum tools/list pages to fetch (default 20) |
| `transport` | string |  | streamable_http (default) or sse (legacy HTTP+SSE; url is then the SSE endpoint) |
| `url` | string | yes | HTTP(S) endpoint of the remote MCP server, e.g. https://example.com/mcp (stdio commands are not supported) |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

### `auth`: OAuth2 helpers

5 tools, on by default.

<details>
<summary><code>oauth2_auth_url</code>: OAuth2 authorization URL <sub>(local, no network)</sub></summary>

Step 1 of the OAuth2 authorization-code flow with PKCE (stateless, no callback listener). Builds the authorization URL and returns it with state and code_verifier. Ask the user to open the URL, sign in and paste back the code or the full redirect URL, then call oauth2_exchange_code with code_verifier and state. redirect_uri defaults to urn:ietf:wg:oauth:2.0:oob.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `audience` | string |  |  |
| `authorization_url` | string | yes | the authorization endpoint |
| `client_id` | string | yes |  |
| `code_verifier` | string |  | use this verifier instead of generating one (43-128 chars) |
| `extra_params` | map&lt;string, string&gt; |  | additional query parameters (prompt, login_hint, access_type, ...) |
| `pkce_method` | string |  | S256 (default), plain or none |
| `redirect_uri` | string |  | registered redirect URI (default urn:ietf:wg:oauth:2.0:oob) |
| `resource` | string |  |  |
| `response_type` | string |  | default code |
| `scopes` | string[] |  |  |
| `state` | string |  | state value (default: random) |

</details>

<details>
<summary><code>oauth2_device_poll</code>: OAuth2 device flow poll <sub>(mutating)</sub></summary>

Poll the token endpoint for a device flow started with oauth2_device_start. Polls at interval_seconds until the user approves, a terminal error occurs, or max_wait_seconds (default 30) elapses. Returns status authorized (with the tokens), authorization_pending (call again), access_denied or expired_token.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth_style` | string |  |  |
| `client_id` | string | yes |  |
| `client_secret` | string |  |  |
| `device_code` | string | yes | device_code from oauth2_device_start |
| `extra_params` | map&lt;string, string&gt; |  |  |
| `interval_seconds` | number |  | polling interval from oauth2_device_start (default 5) |
| `max_wait_seconds` | number |  | how long this call keeps polling before returning authorization_pending (default 30, max 300) |
| `token_url` | string | yes |  |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>oauth2_device_start</code>: OAuth2 device flow start <sub>(mutating)</sub></summary>

Start the OAuth2 device authorization flow (RFC 8628). Returns user_code and verification_uri for the user to visit, plus device_code and interval to pass to oauth2_device_poll.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `audience` | string |  |  |
| `auth_style` | string |  | header (Basic, default when a secret is set) or body |
| `client_id` | string | yes |  |
| `client_secret` | string |  | omit for public clients |
| `device_authorization_url` | string | yes | the device authorization endpoint |
| `extra_params` | map&lt;string, string&gt; |  |  |
| `scopes` | string[] |  |  |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>oauth2_exchange_code</code>: OAuth2 exchange code <sub>(mutating)</sub></summary>

Step 2 of the OAuth2 authorization-code flow: exchange the authorization code (or a pasted redirect URL containing code and state) plus the PKCE code_verifier from oauth2_auth_url for tokens at token_url. Pass state to have it checked against the redirect URL. redirect_uri must match step 1.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `auth_style` | string |  | header (Basic, default) or body |
| `client_id` | string |  |  |
| `client_secret` | string |  | omit for public clients |
| `code` | string |  | authorization code (or pass redirect_url) |
| `code_verifier` | string |  | PKCE verifier returned by oauth2_auth_url |
| `extra_params` | map&lt;string, string&gt; |  |  |
| `redirect_uri` | string |  | must equal the one used for oauth2_auth_url (default: derived from redirect_url, else urn:ietf:wg:oauth:2.0:oob) |
| `redirect_url` | string |  | the full URL the browser was redirected to; code and state are extracted from it |
| `state` | string |  | expected state; checked against the state in redirect_url |
| `token_url` | string | yes |  |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

<details>
<summary><code>oauth2_get_token</code>: OAuth2 get token <sub>(mutating)</sub></summary>

Request an OAuth2 access token from token_url. Grants: client_credentials (default), password (username/password), refresh_token, jwt_bearer (assertion, or sign one with jwt), token_exchange (RFC 8693: subject_token, actor_token, requested_token_type). Client credentials go in a Basic header (auth_style=header, default) or the form body (auth_style=body). Returns access_token, token_type, expires_in/expiry, refresh_token, scope, id_token and the raw response. Other tools can also fetch tokens themselves with auth {type:"oauth2", oauth2:{...}}.

| Argument | Type | Required | Description |
|---|---|:---:|---|
| `access_token` | string |  | use an existing access token directly |
| `actor_token` | string |  |  |
| `actor_token_type` | string |  |  |
| `assertion` | string |  | jwt_bearer: signed assertion (or use jwt to sign one) |
| `audience` | string |  |  |
| `auth_style` | string |  | header (basic, default) or body (client credentials in form body) |
| `client_id` | string |  |  |
| `client_secret` | string |  |  |
| `extra_params` | map&lt;string, string&gt; |  |  |
| `grant` | string |  | client_credentials (default)\|password\|refresh_token\|jwt_bearer\|token_exchange\|access_token |
| `jwt` | object |  | jwt_bearer: sign the assertion with these settings |
| `jwt.algorithm` | string |  | HS256\|HS384\|HS512\|RS256\|RS384\|RS512\|ES256\|ES384\|ES512\|PS256\|PS384\|PS512\|EdDSA (default HS256) |
| `jwt.aud` | string[] |  |  |
| `jwt.claims` | object |  | extra claims |
| `jwt.expires_in_seconds` | number |  | lifetime (default 300) |
| `jwt.header` | string |  | HTTP header to put the token in (default Authorization) |
| `jwt.headers` | object |  | extra JOSE headers |
| `jwt.iss` | string |  |  |
| `jwt.kid` | string |  |  |
| `jwt.prefix` | string |  | prefix for the header value (default Bearer) |
| `jwt.private_key` | string |  | private key for RS/ES/PS/EdDSA: inline PEM or file path |
| `jwt.query_key` | string |  | send the token as this query parameter instead of a header |
| `jwt.secret` | string |  | HMAC secret |
| `jwt.secret_base64` | boolean |  | secret is base64 encoded |
| `jwt.sub` | string |  |  |
| `jwt.token` | string |  | use this pre-built JWT instead of signing one |
| `password` | string |  |  |
| `refresh_token` | string |  |  |
| `requested_token_type` | string |  |  |
| `resource` | string |  |  |
| `scopes` | string[] |  |  |
| `subject_token` | string |  | token_exchange subject token |
| `subject_token_type` | string |  |  |
| `token_type` | string |  | override token type prefix when applying (default from response, else Bearer) |
| `token_url` | string |  |  |
| `use_cache` | boolean |  | reuse a cached unexpired token for the same settings (refreshing it when expired) and cache the result |
| `username` | string |  |  |

Also accepts the [network options](#common-options) and [HTTP options](#common-options).

</details>

### Always available

<details>
<summary><code>netkit_info</code>: Server info <sub>(local, no network)</sub></summary>

Show netkit-mcp configuration: enabled tool groups, directories files may be read from or saved to, network policy and limits. Call this before using file options (body_file, save_to, file payloads).

No arguments.

</details>

### The `auth` object

Every field of the shared `auth` argument. Set `type`, then only the fields that type uses (see [Authentication](#authentication)).

| Field | Type | Description |
|---|---|---|
| `asap` | object |  |
| `asap.algorithm` | string | RS256 (default) |
| `asap.aud` | string[] | **required.**  |
| `asap.claims` | object |  |
| `asap.expires_in_seconds` | number | lifetime (default 60, max 3600) |
| `asap.iss` | string | **required.**  |
| `asap.kid` | string | **required.**  |
| `asap.private_key` | string | **required.** RSA/EC private key: inline PEM or file path |
| `asap.sub` | string |  |
| `aws` | object |  |
| `aws.access_key_id` | string | **required.**  |
| `aws.region` | string | **required.**  |
| `aws.secret_access_key` | string | **required.**  |
| `aws.service` | string | **required.**  |
| `aws.session_token` | string |  |
| `aws.timestamp` | string | fixed signing time, RFC 3339 or 20060102T150405Z (testing only) |
| `aws.unsigned_payload` | boolean | use UNSIGNED-PAYLOAD (required for streamed bodies of unknown hash) |
| `cookies` | map&lt;string, string&gt; | cookie: cookies to send |
| `domain` | string | NTLM domain |
| `edgegrid` | object |  |
| `edgegrid.access_token` | string | **required.**  |
| `edgegrid.client_secret` | string | **required.**  |
| `edgegrid.client_token` | string | **required.**  |
| `edgegrid.headers_to_sign` | string[] |  |
| `edgegrid.max_body` | integer | bytes of body hashed (default 131072) |
| `edgegrid.nonce` | string | fixed nonce (testing only) |
| `edgegrid.timestamp` | string | fixed timestamp yyyyMMddTHH:mm:ss+0000 (testing only) |
| `hawk` | object |  |
| `hawk.algorithm` | string | sha256 (default) or sha1 |
| `hawk.app` | string |  |
| `hawk.dlg` | string |  |
| `hawk.ext` | string |  |
| `hawk.id` | string | **required.**  |
| `hawk.include_payload_hash` | boolean |  |
| `hawk.key` | string | **required.**  |
| `hawk.nonce` | string | fixed nonce (testing only) |
| `hawk.timestamp` | integer | fixed timestamp (testing only) |
| `headers` | map&lt;string, string&gt; | custom_header: headers to add |
| `in` | string | api_key location: header (default), query or cookie |
| `jwt` | object |  |
| `jwt.algorithm` | string | HS256\|HS384\|HS512\|RS256\|RS384\|RS512\|ES256\|ES384\|ES512\|PS256\|PS384\|PS512\|EdDSA (default HS256) |
| `jwt.aud` | string[] |  |
| `jwt.claims` | object | extra claims |
| `jwt.expires_in_seconds` | number | lifetime (default 300) |
| `jwt.header` | string | HTTP header to put the token in (default Authorization) |
| `jwt.headers` | object | extra JOSE headers |
| `jwt.iss` | string |  |
| `jwt.kid` | string |  |
| `jwt.prefix` | string | prefix for the header value (default Bearer) |
| `jwt.private_key` | string | private key for RS/ES/PS/EdDSA: inline PEM or file path |
| `jwt.query_key` | string | send the token as this query parameter instead of a header |
| `jwt.secret` | string | HMAC secret |
| `jwt.secret_base64` | boolean | secret is base64 encoded |
| `jwt.sub` | string |  |
| `jwt.token` | string | use this pre-built JWT instead of signing one |
| `kerberos` | object |  |
| `kerberos.disable_pafx_fast` | boolean |  |
| `kerberos.kdc` | string | KDC host:port (default from krb5.conf) |
| `kerberos.keytab` | string | keytab file path (alternative to password) |
| `kerberos.krb5_conf` | string | krb5.conf contents or file path |
| `kerberos.realm` | string | **required.**  |
| `kerberos.spn` | string | service principal (default HTTP/&lt;host&gt;) |
| `key` | string | api_key name (header, query parameter or cookie) |
| `mtls` | object |  |
| `mtls.client_cert` | string | **required.** inline PEM or file path |
| `mtls.client_key` | string | **required.** inline PEM or file path |
| `oauth1` | object |  |
| `oauth1.body_hash` | boolean | include oauth_body_hash for non-form bodies |
| `oauth1.callback` | string |  |
| `oauth1.consumer_key` | string | **required.**  |
| `oauth1.consumer_secret` | string |  |
| `oauth1.in_query` | boolean | send oauth params in the query string instead of the Authorization header |
| `oauth1.nonce` | string | fixed nonce (testing only) |
| `oauth1.private_key` | string | RSA key for RSA-SHA*: inline PEM or file path |
| `oauth1.realm` | string |  |
| `oauth1.signature_method` | string | HMAC-SHA1 (default), HMAC-SHA256, RSA-SHA1, RSA-SHA256, PLAINTEXT |
| `oauth1.timestamp` | integer | fixed timestamp (testing only) |
| `oauth1.token` | string |  |
| `oauth1.token_secret` | string |  |
| `oauth1.verifier` | string |  |
| `oauth2` | object |  |
| `oauth2.access_token` | string | use an existing access token directly |
| `oauth2.actor_token` | string |  |
| `oauth2.actor_token_type` | string |  |
| `oauth2.assertion` | string | jwt_bearer: signed assertion (or use jwt to sign one) |
| `oauth2.audience` | string |  |
| `oauth2.auth_style` | string | header (basic, default) or body (client credentials in form body) |
| `oauth2.client_id` | string |  |
| `oauth2.client_secret` | string |  |
| `oauth2.extra_params` | map&lt;string, string&gt; |  |
| `oauth2.grant` | string | client_credentials (default)\|password\|refresh_token\|jwt_bearer\|token_exchange\|access_token |
| `oauth2.jwt` | object | jwt_bearer: sign the assertion with these settings |
| `oauth2.jwt.algorithm` | string | HS256\|HS384\|HS512\|RS256\|RS384\|RS512\|ES256\|ES384\|ES512\|PS256\|PS384\|PS512\|EdDSA (default HS256) |
| `oauth2.jwt.aud` | string[] |  |
| `oauth2.jwt.claims` | object | extra claims |
| `oauth2.jwt.expires_in_seconds` | number | lifetime (default 300) |
| `oauth2.jwt.header` | string | HTTP header to put the token in (default Authorization) |
| `oauth2.jwt.headers` | object | extra JOSE headers |
| `oauth2.jwt.iss` | string |  |
| `oauth2.jwt.kid` | string |  |
| `oauth2.jwt.prefix` | string | prefix for the header value (default Bearer) |
| `oauth2.jwt.private_key` | string | private key for RS/ES/PS/EdDSA: inline PEM or file path |
| `oauth2.jwt.query_key` | string | send the token as this query parameter instead of a header |
| `oauth2.jwt.secret` | string | HMAC secret |
| `oauth2.jwt.secret_base64` | boolean | secret is base64 encoded |
| `oauth2.jwt.sub` | string |  |
| `oauth2.jwt.token` | string | use this pre-built JWT instead of signing one |
| `oauth2.password` | string |  |
| `oauth2.refresh_token` | string |  |
| `oauth2.requested_token_type` | string |  |
| `oauth2.resource` | string |  |
| `oauth2.scopes` | string[] |  |
| `oauth2.subject_token` | string | token_exchange subject token |
| `oauth2.subject_token_type` | string |  |
| `oauth2.token_type` | string | override token type prefix when applying (default from response, else Bearer) |
| `oauth2.token_url` | string |  |
| `oauth2.username` | string |  |
| `password` | string |  |
| `prefix` | string | bearer scheme prefix (default Bearer) |
| `ssh` | object |  |
| `ssh.host_key_fingerprint` | string | pinned host key, e.g. SHA256:base64... |
| `ssh.insecure_ignore_host_key` | boolean | skip host key verification (flagged in the result) |
| `ssh.known_hosts` | string | known_hosts file path or inline contents |
| `ssh.passphrase` | string |  |
| `ssh.private_key` | string | private key: inline PEM/OpenSSH or file path |
| `token` | string | bearer token |
| `type` | string | none\|basic\|bearer\|api_key\|digest\|oauth1\|oauth2\|aws_sigv4\|jwt\|hawk\|ntlm\|negotiate\|akamai_edgegrid\|asap\|mtls\|custom_header\|cookie\|ws_security\|ssh_key\|ssh_password |
| `username` | string |  |
| `value` | string | api_key value |
| `ws_security` | object |  |
| `ws_security.must_understand` | boolean |  |
| `ws_security.password_type` | string | text (default) or digest |
| `ws_security.timestamp` | boolean | add a wsu:Timestamp |
| `ws_security.ttl_seconds` | number | timestamp lifetime (default 300) |
<!-- END GENERATED TOOL REFERENCE -->

---

## Remote (HTTP) deployment

```bash
netkit-mcp --transport http --addr 0.0.0.0:8080 \
  --http-token "$(openssl rand -hex 32)" \
  --private-networks deny --groups http,grpc,lowlevel \
  --allow-write-dir /srv/netkit/out
```

- The MCP endpoint is `http://host:8080/mcp`. Every request needs `Authorization: Bearer <token>`; anything else gets `401`.
- `GET /healthz` returns `ok` without authentication, for load-balancer checks.
- The transport is **stateless** streamable HTTP, so one-shot tools work behind any load balancer. Interactive sessions (`ws_connect`, `sio_connect`, `grpc_stream_open`) live in process memory, so use a single instance or sticky routing if you rely on them.
- NetKit doesn't terminate TLS itself. Put it behind a reverse proxy or your platform's ingress for HTTPS.
- Always set `--http-token`, and prefer `--private-networks deny` so the server can't be used to probe your internal network.

With Docker:

```bash
docker run -d --name netkit -p 8080:8080 \
  -e NETKIT_HTTP_TOKEN=change-me -v /srv/netkit/out:/data/out \
  ghcr.io/hamedfathi/netkitmcp:1.0.0 \
  --transport http --addr 0.0.0.0:8080 --private-networks deny
```

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| *"… is a private/loopback address; set allow_private=true"* | The SSRF guard blocked a private target. Let the call set `allow_private=true`, or start the server with `--private-networks allow` for local development. In `deny` mode, private targets can't be reached at all. |
| *"no readable/writable directories configured"* | Start the server with `--allow-read-dir` / `--allow-write-dir`. |
| *"… is outside the allowed … directories"* | The path isn't inside an allowed directory (after resolving links). Use an absolute path under one of them; `netkit_info` lists them. |
| *"… already exists"* on a download | Downloads never overwrite by default. Set `overwrite=true`, or choose another `save_to`. |
| Response body cut off, `"truncated": true` | It exceeded `max_response_bytes` (1 MiB by default). Raise it (up to 16 MiB), or use `save_to` to stream the body to disk. |
| *"request timed out … (raise timeout_seconds)"* | Raise `timeout_seconds` on the call (up to `--max-timeout`, 10 minutes by default). |
| A stream returns `ended_by: "max_duration"` and too few messages | Raise `max_duration_seconds` and/or `max_messages`, or use `idle_timeout_seconds` so the call returns as soon as the stream goes quiet. |
| *"x509: certificate signed by unknown authority"* | Pass the CA as `ca_cert` (inline PEM or a file path). Use `insecure_skip_verify` only for a quick test; it's flagged in the result. |
| SFTP: *"host key verification failed"* or *"no host key verification configured"* | Provide `auth.ssh.known_hosts` (a file or inline lines) or `auth.ssh.host_key_fingerprint` (`SHA256:…`). Every SFTP result reports the server's fingerprint. |
| gRPC: *"server does not support the reflection API"* | Supply `proto_files` (plus `import_paths` if needed) or `descriptor_sets`. For local plaintext servers, set `plaintext=true`. |
| `fetch_web` returns almost nothing | The page renders on the client with JavaScript, which NetKit doesn't run. Look for an API the page calls (`http_request`) or a server-rendered URL. |
| A tool you expect is missing | Its group isn't enabled. Add it with `--groups` (e.g. `--groups default,transfer`); `netkit_info` shows what's on. |
| The client shows no tools, "server disconnected", "Failed to connect" or `CONNECTION_CLOSED` | The server exited at startup, usually because of a bad flag or a missing directory. Run the exact command the client uses in a terminal (`claude mcp get netkit` shows it): it should wait silently for input (stop it with Ctrl+C). If it prints an error and exits, fix that. Also check that the binary path in the client config is absolute and correct, and look at the client's MCP logs. Add `--log-level debug` to see NetKit's own log on stderr. |
| *"allow-read-dir … directory … does not exist; create it first"* (or `allow-write-dir`) | Create the folder (see [Quick start](#quick-start)), or point the flag at one that exists. |
| *"allow-read-dir … The system cannot find the file specified"* naming a path that ends in `\~` | An older NetKit (before `~` expansion) received a literal `~`. Upgrade, or register the server again with absolute paths (`"$HOME\netkit\in"` in PowerShell). |
| macOS: *"cannot be opened because the developer cannot be verified"* | Run `xattr -d com.apple.quarantine /path/to/netkit-mcp` once. |
| Docker: can't reach a service on your machine | Inside the container `localhost` is the container. Use `host.docker.internal` with `allow_private=true`. |

---

## Known limitations

- **`fetch_web` doesn't execute JavaScript.** Pages rendered on the client may come back nearly empty.
- **SOAP:** WSDL 2.0, MTOM/XOP attachments and WS-Security signing/encryption are not supported. Raw XML (`raw_body`) is the escape hatch. XSD support is a practical subset.
- **CoAP:** DTLS (`coaps://` over UDP) is not supported; `coap+tcp://` and `coaps+tcp://` (TLS) are.
- **NATS:** core NATS only; JetStream is not supported yet.
- **Kafka, AMQP, NATS, STOMP** are bounded produce/consume tools, not long-running consumers.
- **OAuth2 authorization code** needs you to open the URL and paste the code back, because the server never opens a browser.
- **GCS resumable and Azure block-blob** uploads work through `http_upload` with presigned URLs, but have no dedicated tools.
- **Spawning stdio MCP servers** from `mcp_client_*` is deliberately unsupported (no process execution).
- **Sessions and cached OAuth2 tokens** live in memory and are lost when the server restarts.

---

## Upgrading and uninstalling

- **Upgrade:** replace the `netkit-mcp` binary with the new release (or rerun `go install …@latest`, or pull the new image tag) and restart your MCP client. There is no state on disk to migrate.
- **Uninstall:** delete the binary, remove the server from your client (`claude mcp remove netkit`, or delete its entry from the client's JSON config), and delete the folders you created for `--allow-read-dir` / `--allow-write-dir` if you no longer need them.

---

## Development

```bash
go build ./...
go vet ./...
go test ./...            # everything runs in-process; no Docker or internet needed
go test -race ./...      # needs cgo (a C toolchain)
```

- Project layout and the conventions every tool follows (guarded dialing, file policy, limits, result shapes, error style) are in [`docs/DEVELOPING.md`](docs/DEVELOPING.md). The full design is in [`Plan.md`](Plan.md).
- Each tool family is tested end to end through an in-memory MCP client (`internal/tools/tooltest`) against real in-process servers: gRPC with reflection, an embedded NATS server, mochi-mqtt, franz-go's `kfake`, tusd, go-coap, an SSH/SFTP server, quic-go for HTTP/3, and protocol-level fakes for FTP, AMQP and STOMP.
- The [Tool reference](#tool-reference) in this README is generated from the tool schemas. After changing a tool, regenerate it with `go test -run TestReadmeToolReference -update-readme .`. CI fails if it's out of date.

### Releasing

Releases are built by [GoReleaser](https://goreleaser.com) when a `v*` tag is pushed. The workflow produces six static binaries, `.tar.gz`/`.zip` archives with `checksums.txt`, a GitHub release, and a multi-arch image on GHCR.

```bash
git tag v1.0.0 && git push origin v1.0.0
```

To build the release archives locally without publishing: `goreleaser release --snapshot --clean` (the output goes to `dist/`).

---

## Contributing

Issues and pull requests are welcome.

1. Open an issue first for larger changes (a new protocol or tool group), so we can agree on the tool design.
2. Follow [`docs/DEVELOPING.md`](docs/DEVELOPING.md). Every network connection goes through the guard, every file through the file policy, and every new tool needs an end-to-end test.
3. Make sure `go vet ./...` and `go test ./...` pass and the code is `gofmt`-clean.

Please report security issues privately via [GitHub security advisories](https://github.com/HamedFathi/NetKitMCP/security/advisories/new), not public issues.

---

## License

[MIT](LICENSE) © 2026 Hamed Fathi
