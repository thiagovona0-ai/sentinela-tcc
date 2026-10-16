const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');
const net = require('node:net');
const crypto = require('node:crypto');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.VT_API_KEY;
const MAX_UPLOAD = Math.max(1,Math.min(Number(process.env.MAX_UPLOAD_MB)||32,32)) * 1024 * 1024;
const WINDOW_MS = 60_000;
const MAX_REQUESTS = Math.max(4,Math.min(Number(process.env.APP_RATE_LIMIT)||20,120));
const requests = new Map();
const vtRequestTimes=[];
const MIME = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.json':'application/json; charset=utf-8', '.svg':'image/svg+xml', '.png':'image/png', '.ico':'image/x-icon' };

function send(res, status, data, type='application/json; charset=utf-8', extra={}) {
  res.writeHead(status, { 'Content-Type':type, 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', 'X-Frame-Options':'DENY', 'Referrer-Policy':'strict-origin-when-cross-origin', 'Content-Security-Policy':"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'", ...extra });
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
  while(true){const now=Date.now();while(vtRequestTimes.length&&now-vtRequestTimes[0]>=60_000)vtRequestTimes.shift();if(vtRequestTimes.length<4){vtRequestTimes.push(now);break;}await new Promise(resolve=>setTimeout(resolve,Math.max(250,60_000-(now-vtRequestTimes[0])+50)));}
  let response;
  try { response = await fetch(`https://www.virustotal.com/api/v3${endpoint}`, { ...options, signal:AbortSignal.timeout(45_000), headers:{'x-apikey':API_KEY,...(options.headers||{})} }); }
  catch (e) { throw Object.assign(new Error('Não foi possível alcançar o VirusTotal agora. Tente novamente.'),{status:502}); }
  const raw=await response.text(); let data={}; try { data=raw?JSON.parse(raw):{}; } catch {}
  if (!response.ok) {
    const status=response.status;
    let message=data?.error?.message || 'A consulta não pôde ser concluída.';
    let code='UPSTREAM_ERROR';
    if(status===401) { message='A chave da API é inválida. Confira VT_API_KEY nas configurações do serviço.'; code='INVALID_API_KEY'; }
    if(status===403) { message='Sua chave não tem permissão para esta função da API.'; code='API_PERMISSION'; }
    if(status===404) { message='Este indicador ainda não possui relatório no VirusTotal.'; code='NOT_FOUND'; }
    if(status===429) { message='O limite da API foi atingido. A API pública permite até 4 consultas por minuto e 500 por dia. Aguarde e tente novamente.'; code='RATE_LIMIT'; }
    if(status===400) { message=data?.error?.message || 'O VirusTotal não aceitou os dados enviados. Confira o arquivo ou indicador.'; code='INVALID_REQUEST'; }
    throw Object.assign(new Error(message),{status,code});
  }
  return data;
}
function readBody(req, limit) {
  return new Promise((resolve,reject)=>{ const parts=[]; let size=0, exceeded=false, settled=false; req.on('data',chunk=>{ if(exceeded)return; size+=chunk.length; if(size>limit){ exceeded=true; parts.length=0; if(!settled){settled=true;reject(Object.assign(new Error('O arquivo excede o tamanho máximo permitido.'),{status:413}));} req.resume(); return; } parts.push(chunk); }); req.on('end',()=>{if(!settled){settled=true;resolve(Buffer.concat(parts));}}); req.on('error',e=>{if(!settled){settled=true;reject(e);}}); });
}
function getMultipartFile(body, contentType) {
  const boundaryMatch=/boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType||'');
  if(!boundaryMatch) throw Object.assign(new Error('Envie um arquivo em formato multipart.'),{status:400});
  const boundary=Buffer.from(`--${boundaryMatch[1]||boundaryMatch[2]}`);
  const first=body.indexOf(boundary); if(first<0) throw Object.assign(new Error('Formato de envio inválido.'),{status:400});
  const headerStart=first+boundary.length+2, headerEnd=body.indexOf(Buffer.from('\r\n\r\n'),headerStart); if(headerEnd<0) throw Object.assign(new Error('Formato de envio inválido.'),{status:400});
  const headers=body.subarray(headerStart,headerEnd).toString('utf8');
  const disposition=/content-disposition:\s*form-data;[^\r\n]*filename\*?=(?:UTF-8''([^;\r\n]+)|"([^"]*)"|([^;\r\n]*))/i.exec(headers);
  if(!disposition) throw Object.assign(new Error('Selecione um arquivo para enviar.'),{status:400});
  let rawName=disposition[2]||disposition[3]||disposition[1]||'';
  try { rawName=decodeURIComponent(rawName); } catch {}
  const contentStart=headerEnd+4; let contentEnd=body.indexOf(Buffer.concat([Buffer.from('\r\n'),boundary]),contentStart);
  if(contentEnd<0) throw Object.assign(new Error('O arquivo enviado está incompleto.'),{status:400});
  return { filename:path.basename(rawName.replace(/\\/g,'/')).slice(0,180)||'arquivo', bytes:body.subarray(contentStart,contentEnd) };
}
function parseError(e) { return { status:e.status||500, body:{error:e.message||'Erro interno.',code:e.code||(e.status===503?'API_KEY_MISSING':'INTERNAL_ERROR')} }; }

const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  if(req.method==='GET'&&url.pathname==='/health') return send(res,200,{ok:true});
  if(url.pathname.startsWith('/api/')&&!appLimit(req,res)) return;
  try {
    if(req.method==='GET'&&url.pathname==='/api/config') return send(res,200,{keyConfigured:Boolean(API_KEY),maxUploadMB:Math.min(MAX_UPLOAD,32*1024*1024)/1024/1024});
    if(req.method==='GET'&&url.pathname==='/api/lookup') {
      const kind=url.searchParams.get('kind'); const value=(url.searchParams.get('value')||'').trim();
      if(!value||value.length>2048) return send(res,400,{error:'Informe um indicador válido.'});
      let endpoint;
      if(kind==='url') { let normalized; try { normalized=new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value)?value:`https://${value}`).toString(); if(!['http:','https:'].includes(new URL(normalized).protocol)) throw new Error(); } catch { return send(res,400,{error:'Informe um endereço web válido, como https://exemplo.com.'}); } endpoint=`/urls/${Buffer.from(normalized).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')}`; }
      else if(kind==='hash') { if(!/^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64})$/i.test(value)) return send(res,400,{error:'Hash inválido. Use MD5, SHA-1 ou SHA-256.'}); endpoint=`/files/${encodeURIComponent(value)}`; }
      else if(kind==='domain') { let host; try { const parsed=new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value)?value:`https://${value}`); host=parsed.hostname.toLowerCase().replace(/\.$/,''); } catch { return send(res,400,{error:'Domínio inválido. Informe um nome como exemplo.com ou cole o endereço completo.'}); } if(net.isIP(host.replace(/^\[|\]$/g,''))||host.length>253||! /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?)(?:\.(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?))+$/.test(host)) return send(res,400,{error:'Domínio inválido. Informe um nome como exemplo.com ou cole o endereço completo de um site.'}); endpoint=`/domains/${encodeURIComponent(host)}`; }
      else if(kind==='ip') { let address=value; if(/^[a-z][a-z\d+.-]*:\/\//i.test(value)) { try { address=new URL(value).hostname.replace(/^\[|\]$/g,''); } catch { address=''; } } if(!net.isIP(address)) return send(res,400,{error:'Este campo aceita um endereço IP (por exemplo, 8.8.8.8). Para consultar um domínio, use a aba Domínio; para um site, use URL.'}); endpoint=`/ip_addresses/${encodeURIComponent(address)}`; }
      else return send(res,400,{error:'Tipo de consulta inválido.'});
      return send(res,200,await vt(endpoint));
    }
    if(req.method==='POST'&&url.pathname==='/api/urls') {
      let input=''; for await (const chunk of req) { input+=chunk; if(input.length>4096) throw Object.assign(new Error('A URL enviada é muito longa.'),{status:413}); }
      let body; try { body=JSON.parse(input); } catch { throw Object.assign(new Error('Dados da URL inválidos.'),{status:400}); }
      let normalized; try { normalized=new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(String(body.url||''))?String(body.url):`https://${String(body.url||'')}`); if(!['http:','https:'].includes(normalized.protocol)) throw new Error(); } catch { throw Object.assign(new Error('Informe um endereço web válido, como https://exemplo.com.'),{status:400}); }
      const form=new URLSearchParams({url:normalized.toString()});
      return send(res,200,await vt('/urls',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:form}));
    }
    if(req.method==='POST'&&url.pathname==='/api/files') {
      const length=Number(req.headers['content-length']||0); if(length>MAX_UPLOAD+65536) return send(res,413,{error:`O limite de envio é ${Math.floor(MAX_UPLOAD/1024/1024)} MB.`});
      const body=await readBody(req,MAX_UPLOAD+65536); const file=getMultipartFile(body,req.headers['content-type']);
      if(!file.bytes.length) return send(res,400,{error:'O arquivo está vazio.'});
      if(file.bytes.length>MAX_UPLOAD) return send(res,413,{error:`O limite de envio é ${Math.floor(MAX_UPLOAD/1024/1024)} MB.`});
      if(file.bytes.length>32*1024*1024) return send(res,413,{error:'A API configurada aceita envio direto até 32 MB. O envio acima desse tamanho exige obter um link especial da VirusTotal.'});
      const form=new FormData(); form.append('file',new Blob([file.bytes]),file.filename);
      const submitted=await vt('/files',{method:'POST',body:form});
      return send(res,200,{analysisId:submitted.data?.id,filename:file.filename,size:file.bytes.length,sha256:crypto.createHash('sha256').update(file.bytes).digest('hex')});
    }
    if(req.method==='GET'&&url.pathname.startsWith('/api/analyses/')) {
      let id; try { id=decodeURIComponent(url.pathname.slice('/api/analyses/'.length)); } catch { return send(res,400,{error:'Identificador da análise inválido.'}); }
      if(!/^[A-Za-z0-9_+/=:-]{8,200}$/.test(id)) return send(res,400,{error:'Identificador da análise inválido.'});
      return send(res,200,await vt(`/analyses/${encodeURIComponent(id)}`));
    }
    if(req.method==='GET') {
      const pathname=url.pathname==='/'?'/index.html':url.pathname;
      const filename=path.resolve(ROOT,`.${decodeURIComponent(pathname)}`);
      if(!filename.startsWith(ROOT+path.sep)) return send(res,403,{error:'Acesso negado.'});
      fs.readFile(filename,(err,data)=>err?send(res,404,{error:'Página não encontrada.'}):send(res,200,data,MIME[path.extname(filename)]||'application/octet-stream',{ 'Cache-Control':['.html','.css','.js'].includes(path.extname(filename))?'no-cache':'public, max-age=3600' }));
      return;
    }
    send(res,405,{error:'Método não permitido.'},'application/json; charset=utf-8',{'Allow':'GET, POST'});
  } catch(e) { const result=parseError(e); send(res,result.status,result.body); }
});
server.listen(PORT,'0.0.0.0',()=>console.log(`Sentinela disponível na porta ${PORT}`));

