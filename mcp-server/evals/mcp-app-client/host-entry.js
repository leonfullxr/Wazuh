import { AppBridge, PostMessageTransport } from '@modelcontextprotocol/ext-apps/app-bridge';
const iframe = document.querySelector('iframe');
const bridge = new AppBridge(null,{name:'SDK test host',version:'1.0.0'},{serverTools:{}});
bridge.oncalltool = async (params) => { window.calls = (window.calls || []); window.calls.push(params.name); return (await fetch('/tool',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(params)})).json(); };
bridge.oninitialized = async () => { window.initialized = true; const args={agent_id:'7',from:'2026-01-01T00:00:00Z',to:'2026-01-01T01:00:00Z',cluster_id:'one'}; await bridge.sendToolInput({arguments:args}); const result=await (await fetch('/tool',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'investigate_agent_timeline',arguments:args})})).json(); await bridge.sendToolResult(result); };
await bridge.connect(new PostMessageTransport(iframe.contentWindow,iframe.contentWindow));
iframe.srcdoc = await (await fetch('/viewer')).text();
