import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import uvicorn
from cryptography.fernet import Fernet

from wazuh_mcp import server
from wazuh_mcp.auth import AuthToken
from wazuh_mcp.clusters import ClusterRegistry
from wazuh_mcp.server.cluster_policy import ClusterPolicy, Rule
from wazuh_mcp.server.product_tools import ProductConfig


class Body(httpx.AsyncByteStream):
    def __init__(self, value): self.value = json.dumps(value).encode()
    async def __aiter__(self): yield self.value
def response(value): return httpx.Response(200, stream=Body(value))
document = {'timestamp':'2026-01-01T00:30:00Z','rule':{'id':'5710','groups':['authentication_failed']}}
def indexer_handler(request):
    if request.url.path.endswith('/_search'):
        return response({'hits':{'total':{'value':1,'relation':'eq'},'hits':[{'_index':'wazuh-alerts-2026.01.01','_id':'event-1','_source':document,'sort':['2026-01-01T00:30:00Z','event-1']}]}})
    if request.url.path.endswith('/_settings'):
        return response({'wazuh-alerts-2026.01.01':{'settings':{'index':{'uuid':'fixture-index'}}}})
    return response({'_source':document})
class Indexer:
    ccs_prefix=''
    base_url='https://indexer.invalid'
    client=httpx.AsyncClient(transport=httpx.MockTransport(indexer_handler))
    async def _ensure_initialized(self): pass
indexer=Indexer()
manager=SimpleNamespace(client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _: response({'data':{'total_failed_items':0,'affected_items':[{'id':'007','status':'active'}]}}))), token='fixture', config=SimpleNamespace(base_url='https://manager.invalid'), _indexer_client=indexer)
server.state.investigation_config=ProductConfig((Fernet.generate_key(),), 'event.id', {})
server.state.config.ENABLED_TOOLS={'investigate_agent_timeline','get_investigation_evidence'}
server.state.cluster_registry=ClusterRegistry({'one':manager}, 'one', False)
server.state.cluster_policy=ClusterPolicy((Rule('api_key','analyst',None,'one',frozenset({'wazuh:read'}),frozenset()),))
token=AuthToken(token='fixture',api_key_id='analyst',created_at=datetime.now(timezone.utc),scopes=['wazuh:read'],owner={'version':1,'family':'api_key','subject':'analyst'})
server.http_security.verify_authentication=AsyncMock(return_value=token)
uvicorn.run(server.app, host='127.0.0.1', port=int(__import__('os').environ['MCP_FIXTURE_PORT']), lifespan='off', log_level='warning')
