'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const crypto = require('node:crypto');

const port = 51000 + Math.floor(Math.random() * 10000);
const base = `http://127.0.0.1:${port}`;
let server;

before(async () => {
  const serverPath = path.join(__dirname, '..', 'server.js');
  const mock = `
    global.fetch = async (input, options = {}) => {
      const url = new URL(input);
      if (url.hostname !== 'www.virustotal.com') return new Response('{}', { status: 502 });
      if (options.headers?.['x-apikey'] !== 'duckspy-local-test-key') return new Response(JSON.stringify({ error: { message: 'test key missing' } }), { status: 401 });
      const method = options.method || 'GET';
      let payload;
      if (url.pathname === '/api/v3/ip_addresses/8.8.8.8' && method === 'GET') {
        payload = { data: { id: '8.8.8.8', type: 'ip_address', attributes: { last_analysis_stats: { harmless: 1, malicious: 0 }, last_analysis_results: { 'Mock AV': { category: 'harmless', result: 'clean' } } } } };
      } else if (url.pathname === '/api/v3/urls' && method === 'POST') {
        payload = { data: { id: 'url-analysis-12345678', type: 'analysis' } };
      } else if (url.pathname === '/api/v3/files' && method === 'POST' && options.body?.get?.('file')?.size > 0) {
        payload = { data: { id: 'file-analysis-12345678', type: 'analysis' } };
      } else if (url.pathname === '/api/v3/analyses/file-analysis-12345678' && method === 'GET') {
        payload = { data: { id: 'file-analysis-12345678', type: 'analysis', attributes: { status: 'completed', stats: { harmless: 1, malicious: 0 }, results: { 'Mock AV': { category: 'harmless', result: 'clean' } } } } };
      } else {
        return new Response(JSON.stringify({ error: { message: 'unexpected mock endpoint' } }), { status: 404 });
      }
      return new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    require(${JSON.stringify(serverPath)});
  `;
  server = spawn(process.execPath, ['-e', mock], {
    env: { ...process.env, PORT: String(port), VT_API_KEY: 'duckspy-local-test-key', APP_RATE_LIMIT: '20', MAX_UPLOAD_MB: '1' },
    stdio: 'ignore'
  });
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error(`Servidor de integração encerrou com código ${server.exitCode}`);
    try { if ((await fetch(`${base}/health`)).ok) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('Servidor de integração não iniciou a tempo');
});

after(async () => {
  if (!server || server.exitCode !== null) return;
  server.kill();
  await Promise.race([new Promise(resolve => server.once('exit', resolve)), new Promise(resolve => setTimeout(resolve, 2000))]);
});

async function json(pathname, options) {
  const response = await fetch(`${base}${pathname}`, options);
  let body = {};
  try { body = await response.json(); } catch {}
  return { response, body };
}

test('fluxos do VirusTotal funcionam com resposta simulada, sem tráfego externo', async () => {
  const ip = await json('/api/lookup?kind=ip&value=8.8.8.8');
  assert.equal(ip.response.status, 200);
  assert.equal(ip.body.data.attributes.last_analysis_stats.harmless, 1);

  const url = await json('/api/urls', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com' })
  });
  assert.equal(url.response.status, 200);
  assert.equal(url.body.data.id, 'url-analysis-12345678');

  const contents = 'duckspy benign upload fixture';
  const form = new FormData();
  form.append('file', new Blob([contents]), 'duckspy-smoke.txt');
  const file = await json('/api/files', { method: 'POST', body: form });
  assert.equal(file.response.status, 200);
  assert.equal(file.body.analysisId, 'file-analysis-12345678');
  assert.equal(file.body.filename, 'duckspy-smoke.txt');
  assert.equal(file.body.size, Buffer.byteLength(contents));
  assert.equal(file.body.sha256, crypto.createHash('sha256').update(contents).digest('hex'));

  const analysis = await json(`/api/analyses/${file.body.analysisId}`);
  assert.equal(analysis.response.status, 200);
  assert.equal(analysis.body.data.attributes.status, 'completed');
  assert.equal(analysis.body.data.attributes.results['Mock AV'].result, 'clean');
});

