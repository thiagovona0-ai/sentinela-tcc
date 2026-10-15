const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.VT_API_KEY;
const MAX_UPLOAD = Number(process.env.MAX_UPLOAD_MB || 32) * 1024 * 1024;
const WINDOW_MS = 60_000;
const MAX_REQUESTS = Number(process.env.APP_RATE_LIMIT || 20);
const requests = new Map();
const MIME = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.json':'application/json; charset=utf-8', '.svg':'image/svg+xml', '.png':'image/png', '.ico':'image/x-icon' };

function send(res, status, data, type='application/json; charset=utf-8', extra={}) {
  res.writeHead(status, { 'Content-Type':type, 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', 'X-Frame-Options':'DENY', 'Referrer-Policy':'strict-origin-when-cross-origin', 'Content-Security-Policy':"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'", ...extra });
  res.end(typeof data === 'string' || Buffer.isBuffer(data) ? data : JSON.stringify(data));
}
function appLimit(req, res) {
  const ip = req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown';
  const now = Date.now(); const entry = requests.get(ip) || { start:now, count:0 };
  if (now - entry.start > WINDOW_MS) { entry.start = now; entry.count = 0; }
  entry.count++; requests.set(ip, entry);
  if (requests.size > 2000) for (const [k,v] of requests) if (now-v.start > WINDOW_MS) requests.delete(k);
  if (entry.count > MAX_REQUESTS) { send(res,429,{error:'Muitas solicitações. Aguarde um minuto e tente novamente.'},'application/json; charset=utf-8',{'Retry-After':'60'}); return false; }
  return true;
}
async function vt(endpoint, options={}) {
  if (!API_KEY) throw Object.assign(new Error('O servidor ainda não foi configurado com a chave do VirusTotal.'),{status:503});
  let response;
  try { response = await fetch(`https://www.virustotal.com/api/v3${endpoint}`, { ...options, signal:AbortSignal.timeout(45_000), headers:{'x-apikey':API_KEY,...(options.headers||{})} }); }
  catch (e) { throw Object.assign(new Error('Não foi possível alcançar o VirusTotal agora. Tente novamente.'),{status:502}); }
  const raw=await response.text(); let data={}; try { data=raw?JSON.parse(raw):{}; } catch {}
  if (!response.ok) {
    const status=response.status;
    let message=data?.error?.message || 'A consulta não pôde ser concluída.';
    if(status===401||status===403) message='A chave ou o nível de acesso da API não permite esta consulta.';
    if(status===404) message='Não há resultado disponível para este indicador.';
    if(status===429) message='O limite da API pública foi atingido. Aguarde antes de consultar novamente.';
    throw Object.assign(new Error(message),{status});
  }
  return data;
}
function readBody(req, limit) {
  return new Promise((resolve,reject)=>{ const parts=[]; let size=0; req.on('data',chunk=>{size+=chunk.length;if(size>limit){reject(Object.assign(new Error('O arquivo excede o tamanho máximo permitido.'),{status:413}));req.destroy();return;}parts.push(chunk);}); req.on('end',()=>resolve(Buffer.concat(parts))); req.on('error',reject); });
}
function getMultipartFile(body, contentType) {
  const boundaryMatch=/boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType||'');
  if(!boundaryMatch) throw Object.assign(new Error('Envie um arquivo em formato multipart.'),{status:400});
  const boundary=Buffer.from(`--${boundaryMatch[1]||boundaryMatch[2]}`);
  let start=body.indexOf(boundary); if(start<0) throw Object.assign(new Error('Formato de envio inválido.'),{status:400});
  start=body.indexOf(Buffer.from('\r\n\r\n'),start); if(start<0) throw Object.assign(new Error('Formato de envio inválido.'),{status:400});
  const headerStart=body.lastIndexOf(boundary,body.indexOf(Buffer.from('\r\n\r\n'),0));
  const headers=body.subarray(headerStart+boundary.length+2,body.indexOf(Buffer.from('\r\n\r\n'),headerStart)).toString('utf8');
  const disposition=/content-disposition:\s*form-data;[^\r\n]*filename="([^"]*)"/i.exec(headers);
  if(!disposition) throw Object.assign(new Error('Selecione um arquivo para enviar.'),{status:400});
  const contentStart=start+4; let contentEnd=body.indexOf(Buffer.concat([Buffer.from('\r\n'),boundary]),contentStart);
  if(contentEnd<0) throw Object.assign(new Error('O arquivo enviado está incompleto.'),{status:400});
  return { filename:path.basename(disposition[1]).slice(0,180)||'arquivo', bytes:body.subarray(contentStart,contentEnd) };
}
function parseError(e) { return { status:e.status||500, body:{error:e.message||'Erro interno.'} }; }

const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  if(req.method==='GET'&&url.pathname==='/health') return send(res,200,{ok:true});
  if(url.pathname.startsWith('/api/')&&!appLimit(req,res)) return;
  try {
    if(req.method==='GET'&&url.pathname==='/api/lookup') {
      const kind=url.searchParams.get('kind'); const value=(url.searchParams.get('value')||'').trim();
      if(!value||value.length>2048) return send(res,400,{error:'Informe um indicador válido.'});
      let endpoint;
      if(kind==='url') { let normalized; try { normalized=new URL(value).toString(); } catch { return send(res,400,{error:'Informe uma URL completa, começando por https:// ou http://.'}); } endpoint=`/urls/${Buffer.from(normalized).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')}`; }
      else if(kind==='hash') { if(!/^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64})$/i.test(value)) return send(res,400,{error:'Hash inválido. Use MD5, SHA-1 ou SHA-256.'}); endpoint=`/files/${encodeURIComponent(value)}`; }
      else if(kind==='domain') { const host=value.toLowerCase().replace(/\.$/,''); if(host.length>253||! /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?)(?:\.(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?))+$/.test(host)) return send(res,400,{error:'Domínio inválido. Informe um nome como exemplo.com.'}); endpoint=`/domains/${encodeURIComponent(host)}`; }
      else if(kind==='ip') { if(!/^[\da-f:.]+$/i.test(value)||value.length>45) return send(res,400,{error:'Endereço IP inválido.'}); endpoint=`/ip_addresses/${encodeURIComponent(value)}`; }
      else return send(res,400,{error:'Tipo de consulta inválido.'});
      return send(res,200,await vt(endpoint));
    }
    if(req.method==='POST'&&url.pathname==='/api/files') {
      const length=Number(req.headers['content-length']||0); if(length>MAX_UPLOAD+65536) return send(res,413,{error:`O limite de envio é ${Math.floor(MAX_UPLOAD/1024/1024)} MB.`});
      const body=await readBody(req,MAX_UPLOAD+65536); const file=getMultipartFile(body,req.headers['content-type']);
      if(!file.bytes.length) return send(res,400,{error:'O arquivo está vazio.'});
      if(file.bytes.length>MAX_UPLOAD) return send(res,413,{error:`O limite de envio é ${Math.floor(MAX_UPLOAD/1024/1024)} MB.`});
      const form=new FormData(); form.append('file',new Blob([file.bytes]),file.filename);
      const submitted=await vt('/files',{method:'POST',body:form});
      return send(res,200,{analysisId:submitted.data?.id,filename:file.filename,size:file.bytes.length});
    }
    if(req.method==='GET'&&url.pathname.startsWith('/api/analyses/')) {
      const id=url.pathname.slice('/api/analyses/'.length);
      if(!/^[a-z\d_-]{8,160}$/i.test(id)) return send(res,400,{error:'Identificador da análise inválido.'});
      return send(res,200,await vt(`/analyses/${encodeURIComponent(id)}`));
    }
    if(req.method==='GET') {
      const pathname=url.pathname==='/'?'/index.html':url.pathname;
      const filename=path.resolve(ROOT,`.${decodeURIComponent(pathname)}`);
      if(!filename.startsWith(ROOT+path.sep)) return send(res,403,{error:'Acesso negado.'});
      fs.readFile(filename,(err,data)=>err?send(res,404,{error:'Página não encontrada.'}):send(res,200,data,MIME[path.extname(filename)]||'application/octet-stream',{ 'Cache-Control':path.extname(filename)==='.html'?'no-cache':'public, max-age=3600' }));
      return;
    }
    send(res,405,{error:'Método não permitido.'},'application/json; charset=utf-8',{'Allow':'GET, POST'});
  } catch(e) { const result=parseError(e); send(res,result.status,result.body); }
});
server.listen(PORT,'0.0.0.0',()=>console.log(`Sentinela disponível na porta ${PORT}`));
