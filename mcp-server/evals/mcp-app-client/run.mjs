import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { build } from 'esbuild';
import { chromium } from 'playwright';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const dir = path.dirname(fileURLToPath(import.meta.url));
const project = process.env.MCP_SERVER_DIR;
const python = process.env.MCP_PYTHON || path.join(project, '.venv/bin/python');
const probe = createTcpServer();
await new Promise((resolve, reject) => probe.once('error', reject).listen(0, '127.0.0.1', resolve));
const port = probe.address().port;
await new Promise(resolve => probe.close(resolve));
const fixture = spawn(python, [path.join(dir, 'fixture_server.py')], {
  cwd: project, env: { ...process.env, MCP_FIXTURE_PORT: String(port) }, stdio: ['ignore', 'pipe', 'pipe'],
});
let fixtureLog = '';
fixture.stdout.on('data', chunk => fixtureLog += chunk);
fixture.stderr.on('data', chunk => fixtureLog += chunk);
let client, host, browser;
try {
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (fixture.exitCode !== null || fixture.signalCode !== null) throw new Error(`Fixture exited: ${fixtureLog}`);
    try { await fetch(`http://127.0.0.1:${port}/`); ready = true; break; } catch { await new Promise(r => setTimeout(r, 100)); }
  }
  if (!ready) throw new Error(`Fixture did not start: ${fixtureLog}`);
  client = new Client({ name: 'independent-apps-pilot', version: '1.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`));
  await client.connect(transport);
  const tools = await client.listTools();
  if (!tools.tools.some(t => t.name === 'investigate_agent_timeline')) throw new Error('Timeline tool missing');
  const resources = await client.listResources();
  const uri = 'ui://wazuh/agent-timeline.html';
  if (!resources.resources.some(r => r.uri === uri)) throw new Error('Viewer resource missing');
  const contents = (await client.readResource({uri})).contents[0];
  if (contents.mimeType !== 'text/html;profile=mcp-app') throw new Error('Unexpected viewer MIME type');
  await build({entryPoints:[path.join(dir, 'host-entry.js')], bundle:true, format:'esm', outfile:path.join(dir,'host-bundle.js'), logLevel:'silent'});
  host = createServer(async (req, res) => {
    try {
      if (req.url === '/viewer') {res.setHeader('content-type','text/html'); res.end(contents.text);}
      else if (req.url === '/host-bundle.js') {res.setHeader('content-type','text/javascript'); res.end(await readFile(path.join(dir,'host-bundle.js')));}
      else if (req.url === '/tool') {
        let body = ''; for await (const chunk of req) body += chunk;
        const result = await client.callTool(JSON.parse(body));
        if (result.structuredContent && JSON.stringify(JSON.parse(result.content[1].text)) !== JSON.stringify(result.structuredContent)) throw new Error('Text and structured results differ');
        res.setHeader('content-type','application/json'); res.end(JSON.stringify(result));
      } else {res.setHeader('content-type','text/html'); res.end('<iframe sandbox="allow-scripts" style="width:100%;height:800px"></iframe><script type="module" src="/host-bundle.js"></script>');}
    } catch (error) {res.statusCode = 500; res.end(String(error));}
  });
  await new Promise((resolve,reject) => host.once('error',reject).listen(0,'127.0.0.1',resolve));
  const browserOptions = {headless:true, args:['--no-sandbox']};
  if (process.env.CHROME_PATH) browserOptions.executablePath = process.env.CHROME_PATH;
  browser = await chromium.launch(browserOptions);
  const page = await browser.newPage();
  page.on('pageerror', error => console.error('Browser error:', error));
  await page.goto(`http://127.0.0.1:${host.address().port}`);
  await page.waitForFunction(() => window.initialized === true, {timeout:10000});
  const frame = page.frameLocator('iframe');
  const event = frame.getByRole('button',{name:/Rule 5710/});
  await event.waitFor({timeout:10000});
  await event.click();
  await frame.locator('#detail').getByText('5710',{exact:false}).waitFor({timeout:10000});
  const calls = await page.evaluate(() => window.calls);
  if (!calls.includes('get_investigation_evidence')) throw new Error('Evidence lookup was not called');
  console.log(`PASS: protocol ${transport.protocolVersion}; official SDK 1.30.0; Apps AppBridge 2.0.4; Playwright 1.64.1; Chrome ${browser.version()}`);
  console.log('PASS: tool/resource listing, viewer read, Apps handshake, timeline rendering, evidence lookup, matching structured/text results');
} finally {
  if (browser) await browser.close();
  if (host) await new Promise(resolve => host.close(resolve));
  if (client) await client.close();
  fixture.kill('SIGTERM');
  if (fixture.exitCode === null && fixture.signalCode === null) await new Promise(resolve => fixture.once('exit', resolve));
}
