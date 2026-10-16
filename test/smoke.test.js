'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

const port = 31000 + Math.floor(Math.random() * 20000);
const base = `http://127.0.0.1:${port}`;
let server;

before(async () => {
  server = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(port), VT_API_KEY: '', APP_RATE_LIMIT: '120', MAX_UPLOAD_MB: '1' },
    stdio: 'ignore'
  });
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error(`Servidor de teste encerrou com código ${server.exitCode}`);
    try { if ((await fetch(`${base}/health`)).ok) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('Servidor de teste não iniciou a tempo');
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

test('health check confirma servidor disponível', async () => {
  const { response, body } = await json('/health');
  assert.equal(response.status, 200);
  assert.deepEqual(body, { ok: true });
});

test('página inicial e ativos da interface carregam', async () => {
  const home = await fetch(base);
  const html = await home.text();
  assert.equal(home.status, 200);
  assert.match(html, /duckspy/i);
  assert.match(html, /mascote-transparente\.png/);
  for (const [file, type] of [['/style.css', 'text/css'], ['/app.js', 'text/javascript'], ['/mascote-transparente.png', 'image/png']]) {
    const response = await fetch(`${base}${file}`);
    assert.equal(response.status, 200, file);
    assert.match(response.headers.get('content-type'), new RegExp(type));
    if (file.endsWith('.png')) assert.deepEqual([...new Uint8Array(await response.arrayBuffer()).slice(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
  }
});

test('arquivos internos e configuração não são servidos', async () => {
  for (const file of ['/server.js', '/package.json', '/.env', '/README.md', '/Dockerfile']) {
    const response = await fetch(`${base}${file}`);
    assert.equal(response.status, 404, file);
  }
});

test('configuração não revela chave e impõe limite de upload', async () => {
  const { response, body } = await json('/api/config');
  assert.equal(response.status, 200);
  assert.equal(body.keyConfigured, false);
  assert.equal(body.maxUploadMB, 1);
  assert.ok(body.maxUploadMB > 0 && body.maxUploadMB <= 32);
  assert.equal(JSON.stringify(body).includes('VT_API_KEY'), false);
});

test('validação rejeita consultas inválidas antes de chamar a API', async () => {
  const cases = [
    '/api/lookup?kind=unknown&value=x',
    '/api/lookup?kind=hash&value=abc',
    '/api/lookup?kind=domain&value=localhost',
    '/api/lookup?kind=ip&value=google.com',
    '/api/lookup?kind=url&value=javascript%3Aalert(1)',
    '/api/lookup?kind=url&value='
  ];
  for (const pathname of cases) {
    const { response, body } = await json(pathname);
    assert.equal(response.status, 400, pathname);
    assert.equal(typeof body.error, 'string');
  }
});

test('consultas válidas falham com mensagem segura quando API não está configurada', async () => {
  const cases = [
    '/api/lookup?kind=url&value=https%3A%2F%2Fexample.com',
    '/api/lookup?kind=hash&value=d41d8cd98f00b204e9800998ecf8427e',
    '/api/lookup?kind=domain&value=example.com',
    '/api/lookup?kind=ip&value=8.8.8.8'
  ];
  for (const pathname of cases) {
    const { response, body } = await json(pathname);
    assert.equal(response.status, 503, pathname);
    assert.equal(body.code, 'API_KEY_MISSING');
    assert.doesNotMatch(JSON.stringify(body), /api.?key\s*[:=]\s*\S+/i);
  }
});

test('submissão de URL é validada e não vaza detalhe de servidor', async () => {
  const invalid = await json('/api/urls', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'javascript:alert(1)' }) });
  assert.equal(invalid.response.status, 400);
  const valid = await json('/api/urls', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'https://example.com' }) });
  assert.equal(valid.response.status, 503);
  assert.equal(valid.body.code, 'API_KEY_MISSING');
});

test('upload rejeita arquivo vazio, aceita multipart válido até a camada protegida', async () => {
  const empty = new FormData();
  empty.append('file', new Blob([]), 'empty.txt');
  const emptyResult = await json('/api/files', { method: 'POST', body: empty });
  assert.equal(emptyResult.response.status, 400);

  const valid = new FormData();
  valid.append('file', new Blob(['safe test fixture']), 'fixture.txt');
  const validResult = await json('/api/files', { method: 'POST', body: valid });
  assert.equal(validResult.response.status, 503);
  assert.equal(validResult.body.code, 'API_KEY_MISSING');
});

test('upload maior que o limite configurado é interrompido', async () => {
  const tooLarge = new FormData();
  tooLarge.append('file', new Blob([new Uint8Array(1024 * 1024 + 1)]), 'oversized.bin');
  const { response, body } = await json('/api/files', { method: 'POST', body: tooLarge });
  assert.equal(response.status, 413);
  assert.match(body.error, /limite/i);
});

test('polling valida identificador da análise', async () => {
  const invalid = await json('/api/analyses/abc');
  assert.equal(invalid.response.status, 400);
  const valid = await json('/api/analyses/abcdefgh');
  assert.equal(valid.response.status, 503);
  assert.equal(valid.body.code, 'API_KEY_MISSING');
});

test('rotas inexistentes e métodos não permitidos retornam status corretos', async () => {
  assert.equal((await fetch(`${base}/nao-existe`)).status, 404);
  const response = await fetch(`${base}/health`, { method: 'POST' });
  assert.equal(response.status, 405);
  assert.match(response.headers.get('allow'), /GET/);
});



