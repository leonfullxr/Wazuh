# OpenSearch MCP server

This folder configures the upstream [opensearch-mcp-server-py](https://pypi.org/project/opensearch-mcp-server-py/) package. We do not vendor its source.

## Install

The parent installer creates a virtualenv and installs the PyPI package:

```bash
pip install opensearch-mcp-server-py
```

## Run (streamable HTTP)

Copy `mcp-server.env.example`, set indexer credentials, then start the server.
The CLI flag is `--transport stream` (not `sse`):

```bash
set -a && source mcp-server.env && set +a
opensearch-mcp-server-py --transport stream --host 0.0.0.0 --port 9900
```

The gateway connects to `http://HOST:9900/mcp` via the Python `mcp` SDK
(streamable HTTP). The same server also exposes legacy SSE at `/sse`.

Equivalent module invocation:

```bash
python -m mcp_server_opensearch --transport stream --host 0.0.0.0 --port 9900
```

## systemd

`install_ai_assistant.sh` writes `/etc/systemd/system/wazuh-ai-mcp-server.service` with:

```ini
ExecStart=/opt/wazuh-ai-assistant/venv/bin/opensearch-mcp-server-py --transport stream --host 0.0.0.0 --port 9900
EnvironmentFile=/etc/wazuh-ai-assistant/mcp-server.env
```

Indexer access uses basic auth from `OPENSEARCH_USERNAME` and `OPENSEARCH_PASSWORD`.
