/**
 * Hacktiba Labs: engine privada invocada exclusivamente por Service Binding.
 * Segurança adicional: autenticação HMAC interna e janela de tempo de 30s.
 * Nunca publicar em GitHub público; não possui rota pública workers.dev.
 */
const WP_API = 'https://api.wordpress.org/plugins/info/1.2/';
const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const OSV_API = 'https://api.osv.dev/v1';
const UPSTREAM_HOSTS = new Set(['api.wordpress.org', 'services.nvd.nist.gov', 'api.osv.dev', 'threatfox-api.abuse.ch', 'urlhaus-api.abuse.ch']);
const FEED_CANDIDATES = 30;
const FEED_CONCURRENCY = 5;
const FEED_BUDGET_MS = 18000;
const DOCUMENTED_ARTIFACTS = Object.freeze([
  {
    type: 'artifact', value: 'wp-content/plugins/wp-compat/wp-compat.php', plugin: 'wp-compat',
    description: 'Arquivo atribuído a plugin disfarçado que criava administrador oculto, documentado em investigação da Sucuri (29/07/2025).',
    source: 'Sucuri', sourceUrl: 'https://blog.sucuri.net/2025/07/unauthorized-admin-user-created-via-disguised-wordpress-plugin.html',
    observedAt: '2025-07-29', method: 'referencia-documental'
  },
  {
    type: 'artifact', value: 'wp-content/plugins/DebugMaster/DebugMaster.php', plugin: 'DebugMaster Pro',
    description: 'Arquivo de falso plugin utilizado como backdoor administrativo, documentado em investigação da Sucuri (23/09/2025).',
    source: 'Sucuri', sourceUrl: 'https://blog.sucuri.net/2025/09/hidden-wordpress-backdoors-creating-admin-accounts',
    observedAt: '2025-09-23', method: 'referencia-documental'
  }
]);

const SECURITY_RE = /\b(?:security\s+(?:fix|patch|update|issue|vulnerabilit(?:y|ies))|fix(?:ed|es|ing)?\s+(?:an?\s+)?(?:xss|csrf|sql\s*injection|security\s+(?:issue|bug|vulnerabilit(?:y|ies))|privilege\s+escalation|authentication\s+bypass)|(?:xss|csrf|sql\s*injection|remote\s+code\s+execution|privilege\s+escalation|authentication\s+bypass|CVE-\d{4}-\d{4,})|(?:correç(?:ão|ões)|corrigid[oa]s?)\s+(?:de\s+)?(?:segurança|vulnerabilidade)|falha\s+de\s+segurança)\b/i;
const MAX_LEN = { q: 64, slug: 110, name: 90, version: 35, kind: 15, ecosystem: 20, value: 250 };
const PARAMS = Object.freeze({
  '/api/feed': [], '/api/search': ['q'], '/api/plugin': ['slug'],
  '/api/cve': ['slug', 'name', 'version'], '/api/malware': ['name','ecosystem','version'],
  '/api/ioc': []
});
const utf8 = new TextEncoder();
function verifyParams(url) {
  if (url.search.length > 520) throw new HttpError(414, 'Consulta muito longa.');
  const valid = PARAMS[url.pathname];
  if (!valid) throw new HttpError(404, 'Rota não encontrada.');
  for (const [key, val] of url.searchParams) {
    if (!valid.includes(key)) throw new HttpError(400, 'Parâmetro não permitido.');
    if (url.searchParams.getAll(key).length > 1) throw new HttpError(400, 'Parâmetro duplicado.');
    if (/[\u0000-\u001f\u007f]/.test(val)) throw new HttpError(400, 'Entrada inválida.');
  }
}

// Autentica chamadas internas mesmo se o Worker for publicado erroneamente.
async function authenticateInternal(request, env, url, iocBody = null) {
  const ts = request.headers.get('X-Hacktiba-Timestamp') || '';
  const sig = request.headers.get('X-Hacktiba-Signature') || '';
  const value = Number(ts);
  if (!env.INTERNAL_KEY || env.INTERNAL_KEY.length < 32 || !/^\d{13}$/.test(ts) ||
      !Number.isSafeInteger(value) || Math.abs(Date.now() - value) > 30000 ||
      !/^[A-Za-z0-9_-]{43}$/.test(sig)) return false;
  if (request.method === 'POST' && url.pathname === '/api/ioc' && typeof iocBody !== 'string') return false;
  const key = await crypto.subtle.importKey('raw', utf8.encode(env.INTERNAL_KEY),
    {name: 'HMAC', hash: 'SHA-256'}, false, ['verify']);
  try {
    const canonical = request.method === 'POST' && url.pathname === '/api/ioc'
      ? `ioc-post-v1\n${ts}\nPOST\n${url.pathname}\n${base64urlDigest(await crypto.subtle.digest('SHA-256', utf8.encode(iocBody)))}`
      : `${ts}\n${url.pathname}\n${url.search}`;
    const bin = Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    return await crypto.subtle.verify('HMAC', key, bin, utf8.encode(canonical));
  } catch {return false;}
}
function base64urlDigest(raw) {
  const bytes = new Uint8Array(raw);
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function readIocBody(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('Content-Type') || '')) throw new HttpError(415, 'Envie JSON.');
  const length = Number(request.headers.get('Content-Length') || 0);
  if (!Number.isFinite(length) || length > 2048) throw new HttpError(413, 'Dados muito grandes.');
  const reader = request.body?.getReader();
  if (!reader) throw new HttpError(400, 'Corpo não informado.');
  const parts = [];
  let count = 0;
  while (true) {
    const {done, value} = await reader.read();
    if (done) break;
    count += value.byteLength;
    if (count > 2048) { await reader.cancel().catch(() => {}); throw new HttpError(413, 'Dados muito grandes.'); }
    parts.push(value);
  }
  const bytes = new Uint8Array(count);
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
  try { return new TextDecoder('utf-8', {fatal: true}).decode(bytes); }
  catch { throw new HttpError(400, 'Entrada inválida.'); }
}

// Cache público e documental da Cloudflare, sem dados de visitantes.
// Cache API é local ao datacenter: reduz carga, mas não garante deduplicação global.
async function publicCache(key, seconds, builder, ctx) {
  const cache = globalThis.caches?.default;
  if (cache) {
    try {
      const hit = await cache.match(key);
      if (hit && hit.ok) return await hit.json();
    } catch (_) { /* cache indisponível: não registrar dados */ }
  }
  const result = await builder();
  if (cache && ctx?.waitUntil) {
    const cacheResponse = new Response(JSON.stringify(result), {
      status: 200, headers: { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':`public, max-age=${seconds}` }
    });
    ctx.waitUntil(cache.put(key, cacheResponse).catch(() => {}));
  }
  return result;
}


function input(url, name, fallback = '') {
  const s = (url.searchParams.get(name) || fallback).trim();
  if (/[\u0000-\u001f\u007f]/.test(s)) throw new HttpError(400, 'Entrada inválida.');
  if (s.length > (MAX_LEN[name] || 120)) throw new HttpError(400, 'Entrada muito longa.');
  return s;
}
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
class UpstreamError extends Error {
  constructor(status) { super('Falha na fonte externa.'); this.status = status; }
}
function plain(value) {
  return String(value || '').replace(/<[^>]*>/g, ' ').replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"').replace(/&#0*39;/gi, "'").replace(/\s+/g, ' ').trim();
}
function wpURL(action, params) {
  const url = new URL(WP_API);
  url.searchParams.set('action', action);
  for (const [key, val] of Object.entries(params)) url.searchParams.set(key, String(val));
  return url.toString();
}
async function externalJSON(url, options = {}, ms = 10000, maxBytes = 1_600_000) {
  const target = new URL(url);
  if (target.protocol !== 'https:' || !UPSTREAM_HOSTS.has(target.hostname) || target.port || target.username || target.password) {
    throw new Error('Destino externo não autorizado.');
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    const res = await fetch(url, {
      ...options,
      redirect: 'manual', // não seguir redirecionamento para destinos não previstos
      signal: controller.signal,
      headers: { 'Accept': 'application/json', ...(options.headers || {}) }
    });
    if (!res.ok) throw new UpstreamError(res.status);
    const type = res.headers.get('Content-Type') || '';
    if (!/^application\/(?:json|[^;]+\+json)(?:\s*;|$)/i.test(type)) throw new Error('Resposta externa não é JSON.');
    const contentLength = Number(res.headers.get('Content-Length') || '0');
    if (contentLength > maxBytes) throw new Error('Resposta externa acima do limite permitido.');
    const reader = res.body?.getReader();
    if (!reader) throw new Error('Resposta externa sem corpo.');
    let total = 0;
    const chunks = [];
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error('Resposta externa acima do limite permitido.');
      }
      chunks.push(value);
    }
    const combined = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) { combined.set(c, offset); offset += c.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(combined));
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Tempo limite excedido em consulta externa.');
    throw error;
  } finally { clearTimeout(timer); }
}
function listVersions(info) {
  const raw = info?.versions;
  const list = Array.isArray(raw) ? raw : (raw && typeof raw === 'object' ? Object.keys(raw) : []);
  function cmp(a, b) {
    const x = a.split(/[.-]/), y = b.split(/[.-]/);
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const A = x[i] || '0', B = y[i] || '0';
      const d = /^\d+$/.test(A) && /^\d+$/.test(B) ? Number(B) - Number(A) : B.localeCompare(A);
      if (d) return d;
    }
    return 0;
  }
  return [...new Set(list.filter(v => /^\d+(?:\.\d+)*(?:[-.][a-z0-9]+)?$/i.test(v)))].sort(cmp).slice(0, 300);
}
async function searchPlugins(url) {
  const q = input(url, 'q');
  if (q.length < 2) throw new HttpError(400, 'Digite ao menos dois caracteres.');
  const data = await externalJSON(wpURL('query_plugins', {
    'request[search]': q, 'request[per_page]': 30, 'request[page]': 1
  }));
  return { items: (Array.isArray(data.plugins) ? data.plugins : []).slice(0, 30).filter(p => p.slug)
    .map(p => ({ name: plain(p.name).slice(0, 180), slug: String(p.slug).slice(0, 110) })) };
}
async function pluginInfo(url) {
  const slug = input(url, 'slug');
  if (!/^[a-z0-9][a-z0-9._-]{0,109}$/i.test(slug)) throw new HttpError(400, 'Plugin inválido.');
  const data = await externalJSON(wpURL('plugin_information', {
    'request[slug]': slug, 'request[fields][versions]': 1,
    'request[fields][sections]': 1
  }), {}, 11000, 2_000_000);
  return {
    slug, name: plain(data.name).slice(0, 160),
    description: plain(data.short_description || data.sections?.description || data.description).slice(0, 1800),
    version: String(data.version || '').slice(0, 35),
    updated: String(data.last_updated || '').slice(0, 50),
    versions: listVersions(data)
  };
}
function getSecurityNote(html) {
  const matches = String(html || '').slice(0, 80_000).match(/<(?:li|p)\b[^>]*>[\s\S]*?<\/(?:li|p)>/gi) || [];
  for (const raw of matches) {
    const text = plain(raw);
    if (SECURITY_RE.test(text)) return text.slice(0, 210);
  }
  const text = plain(String(html || '').slice(0, 80_000));
  const pos = text.search(SECURITY_RE);
  return pos === -1 ? '' : text.slice(Math.max(0, pos - 55), pos + 160);
}
async function feed() {
  const deadline = Date.now() + FEED_BUDGET_MS;
  const updated = await externalJSON(wpURL('query_plugins', {
    'request[browse]': 'updated', 'request[per_page]': FEED_CANDIDATES, 'request[page]': 1
  }), {}, 9000, 1_600_000);
  const candidates = (Array.isArray(updated.plugins) ? updated.plugins : [])
    .filter(p => typeof p.slug === 'string' && /^[a-z0-9][a-z0-9._-]{0,109}$/i.test(p.slug))
    .slice(0, FEED_CANDIDATES);
  const matches = [];
  let cursor = 0;
  let attempted = 0;
  let failed = 0;
  async function worker() {
    while (cursor < candidates.length && Date.now() < deadline - 500) {
      const item = candidates[cursor++];
      attempted++;
      try {
        const remaining = deadline - Date.now();
        if (remaining < 800) break;
        const info = await externalJSON(wpURL('plugin_information', {
          'request[slug]': item.slug, 'request[fields][sections]': 1
        }), {}, Math.min(6500, remaining), 1_500_000);
        const note = getSecurityNote(info.sections?.changelog);
        if (note) matches.push({
          slug: item.slug,
          name: plain(info.name || item.name || item.slug).slice(0, 140),
          version: String(info.version || '').slice(0, 30),
          updated: String(info.last_updated || item.last_updated || '').slice(0, 50),
          note
        });
      } catch (_) { failed++; }
    }
  }
  await Promise.all(Array.from({length: FEED_CONCURRENCY}, worker));
  matches.sort((a, b) => (Date.parse(b.updated) || 0) - (Date.parse(a.updated) || 0));
  const incomplete = attempted < candidates.length;
  return {
    items: matches.slice(0, 5),
    notice: `Amostra: ${attempted} de ${candidates.length} plugins recentes verificados no WordPress.org; até 5 menções a correções exibidas. ` +
      'Não representa lista completa de vulnerabilidades nem confirma CVEs.' +
      (incomplete ? ' Parte da amostra não foi examinada devido ao limite de tempo.' : '') +
      (failed ? ` ${failed} consulta(s) falharam.` : '')
  };
}

function matchesPlugin(cve, slug, name) {
  const haystack = ((cve.descriptions || []).map(d => d.value).join(' ') + ' ' + JSON.stringify(cve.configurations || [])).toLowerCase();
  const words = [slug.replace(/-/g, ' '), slug, name.toLowerCase()].filter(x => x.length >= 5);
  return words.some(w => haystack.includes(w));
}
// Correlação conservadora: NVD é pesquisa textual, não detector de versões afetadas.
function versionStatus(cve, version, slug) {
  if (!version || version === 'all') return 'Não avaliada';
  const nodes=[];
  function walk(x, depth=0) {
    if (!x || typeof x !== 'object' || depth > 15 || nodes.length > 120) return;
    if (Array.isArray(x)) {for (const v of x.slice(0,120)) walk(v,depth+1); return;}
    if (typeof x.criteria === 'string' && x.vulnerable === true) nodes.push(x);
    for (const v of Object.values(x)) walk(v,depth+1);
  }
  walk(cve.configurations || []);
  // Comparação numérica simples só quando ambas as versões são estritamente numéricas.
  const numeric = x => /^\d+(?:\.\d+)*$/.test(x);
  const compare = (a,b) => {
    const aa=a.split('.').map(Number), bb=b.split('.').map(Number);
    for(let i=0;i<Math.max(aa.length,bb.length);i++) if((aa[i]||0)!==(bb[i]||0)) return (aa[i]||0)-(bb[i]||0);
    return 0;
  };
  const normalize = x => String(x || '').toLowerCase().replace(/[^a-z0-9]/g,'');
  const target = normalize(slug);
  for (const n of nodes) {
    const fields=n.criteria.split(':');
    if (fields.length < 6 || !['a','o'].includes(fields[2])) continue;
    // Não atribuir versões de outros produtos a este plugin.
    if (normalize(fields[4]) !== target) continue;
    const exact = fields[5];
    if (numeric(version) && numeric(exact) && compare(version,exact)===0)
      return 'Possivelmente afetada (confirmar registro NVD)';
    if (!numeric(version)) continue;
    const starts=[['versionStartIncluding', x=>x>=0],['versionStartExcluding',x=>x>0]];
    const ends=[['versionEndIncluding',x=>x<=0],['versionEndExcluding',x=>x<0]];
    const bound=[...starts,...ends].filter(([key])=>n[key]);
    if (!bound.length || bound.some(([key])=>!numeric(n[key]))) continue;
    if (bound.every(([key, test])=>test(compare(version,n[key]))))
      return 'Possivelmente afetada (confirmar registro NVD)';
  }
  return 'Não determinada: confirme produto, CPE e intervalo na fonte original';
}
async function cveSearch(url) {
  const slug = input(url, 'slug'), name = input(url, 'name') || slug;
  const version = input(url, 'version', 'all');
  if (!/^[\p{L}\p{N} ._()'&+\/-]{2,90}$/u.test(name)) throw new HttpError(400, 'Nome de plugin inválido.');
  if (!/^(all|[0-9a-z][0-9a-z.+_-]{0,34})$/i.test(version)) throw new HttpError(400, 'Versão inválida.');
  if (!/^[a-z0-9][a-z0-9._-]{0,109}$/i.test(slug)) throw new HttpError(400, 'Plugin inválido.');
  const upstream = new URL(NVD_API);
  upstream.searchParams.set('keywordSearch', 'WordPress plugin ' + name);
  upstream.searchParams.set('resultsPerPage', '50');
  const data = await externalJSON(upstream.toString(), {}, 16000, 3_000_000);
  const related = (Array.isArray(data.vulnerabilities) ? data.vulnerabilities : []).slice(0, 50).map(v => v.cve).filter(Boolean).filter(v => matchesPlugin(v, slug, name));
  return {
    items: related.map(c => {
      const cvss = c.metrics?.cvssMetricV31?.[0]?.cvssData
        || c.metrics?.cvssMetricV30?.[0]?.cvssData || c.metrics?.cvssMetricV2?.[0]?.cvssData || {};
      const weaknesses = [...new Set((c.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(w => /^CWE-\d+$/.test(w)))];
      return {
        id: String(c.id || '').slice(0, 45),
        description: String(c.descriptions?.find(d => d.lang === 'en')?.value || c.descriptions?.[0]?.value || 'Sem descrição').slice(0, 1500),
        status: versionStatus(c, version, slug), severity: cvss.baseSeverity || '',
        score: cvss.baseScore ?? null, vector: cvss.vectorString || '',
        attack: cvss.attackVector || '', privileges: cvss.privilegesRequired || '', weaknesses
      };
    }),
    notice: `Busca textual em até 50 registros da NVD (total estimado pela fonte: ${Number.isSafeInteger(data.totalResults) ? data.totalResults : 'não informado'}). ` + 'Ocorrências candidatas, não confirmação de vulnerabilidade na versão. Resultados ausentes não comprovam segurança.'
  };
}
async function malware(url) {
  const name = input(url, 'name');
  const ecosystem = input(url, 'ecosystem');
  const version = input(url, 'version');
  if (!name) throw new HttpError(400, 'Informe pacote ou identificador.');
  if (!/^[\p{L}\p{N}@._+\/-]{1,90}$/u.test(name)) throw new HttpError(400, 'Nome de pacote inválido.');
  if (version && !/^[\p{L}\p{N}._+\/-]{1,35}$/u.test(version)) throw new HttpError(400, 'Versão inválida.');
  const byId = /^MAL-\d{4}-\d+$/i.test(name);
  let records;
  if (byId) {
    try {
      const data = await externalJSON(`${OSV_API}/vulns/${encodeURIComponent(name)}`, {}, 18000);
      records = /^MAL-/i.test(data.id || '') ? [data] : [];
    } catch (error) {
      if (error instanceof UpstreamError && error.status === 404) records = [];
      else throw error;
    }
  } else {
    if (!['npm', 'PyPI', 'Packagist'].includes(ecosystem)) throw new HttpError(400, 'Selecione um ecossistema válido.');
    const request = { package: { name, ecosystem } };
    if (version) request.version = version;
    const data = await externalJSON(`${OSV_API}/query`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request)
    }, 18000);
    records = (data.vulns || []).filter(v => /^MAL-/i.test(v.id || '')).filter(v =>
      (v.affected || []).some(a => a.package?.name === name && a.package?.ecosystem === ecosystem));
  }
  return {
    items: records.slice(0, 30).map(v => ({
      id: v.id, summary: String(v.summary || '').slice(0, 1000),
      details: String(v.details || '').slice(0, 2500),
      published: v.published || '', updated: v.modified || '',
      packages: [...new Set((v.affected || []).map(a => [a.package?.ecosystem, a.package?.name].filter(Boolean).join(' / ')).filter(Boolean))].slice(0, 10),
      affected: (v.affected || []).slice(0, 8).map(a => ({
        package: [a.package?.ecosystem, a.package?.name].filter(Boolean).join(' / '),
        versions: (a.versions || []).slice(0, 12),
        intervals: (a.ranges || []).flatMap(r => (r.events || []).map(e => Object.entries(e).map(([key, val]) => `${key}: ${val}`).join(', '))).slice(0, 12)
      }))
    })),
    notice: 'Pesquisa documental por registros publicados; não examina arquivos nem executa detecção no site. Pacotes de outros ecossistemas não são automaticamente plugins PHP.'
  };
}
function cleanText(value, max = 180) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
}
function validIPv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255 && String(Number(p)) === p);
}
function privateIPv4(value) {
  const [a, b] = value.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19));
}
function validDomain(value) {
  return value.length <= 253 && /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value) &&
    !/\.(?:local|internal|example|test|invalid)$/i.test(value);
}
function iocInput(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) ||
      Object.keys(payload).length !== 2 || !Object.hasOwn(payload, 'value') || !Object.hasOwn(payload, 'kind') ||
      typeof payload.value !== 'string' || typeof payload.kind !== 'string') {
    throw new HttpError(400, 'Formato de IOC inválido.');
  }
  const original = payload.value.trim();
  const selectedKind = payload.kind.trim();
  if (original.length > 250 || selectedKind.length > 15 ||
      /[\u0000-\u001f\u007f]/.test(original + selectedKind)) throw new HttpError(400, 'Entrada inválida.');
  if (!original) throw new HttpError(400, 'Informe um indicador.');
  if (!['auto', 'hash', 'ip', 'domain', 'url', 'artifact'].includes(selectedKind)) throw new HttpError(400, 'Tipo inválido.');
  let kind;
  if (/^[a-f0-9]{32}$|^[a-f0-9]{64}$/i.test(original)) kind = 'hash';
  else if (/^https?:\/\//i.test(original)) kind = 'url';
  else if (validIPv4(original)) kind = 'ip';
  else if (/^(?:\.\/|\/)?wp-content\/plugins\//i.test(original) || DOCUMENTED_ARTIFACTS.some(e => e.plugin.toLowerCase() === original.toLowerCase() || e.plugin.toLowerCase().split(' ')[0] === original.toLowerCase())) kind = 'artifact';
  else if (validDomain(original)) kind = 'domain';
  else throw new HttpError(400, 'Indicador não reconhecido. Informe MD5/SHA-256, IPv4 público, domínio, URL HTTP(S) ou caminho de plugin WordPress.');
  if (selectedKind !== 'auto' && selectedKind !== kind) throw new HttpError(400, 'Tipo selecionado incompatível com o indicador.');
  let value = original;
  if (kind === 'hash' || kind === 'domain') value = original.toLowerCase();
  if (kind === 'artifact') {
    value = original.replace(/^(?:\.\/|\/)+/, '').replace(/\\/g, '/');
    if (!/^wp-content\/plugins\/[a-z0-9._-]+\/[a-z0-9._/-]+$/i.test(value) && !DOCUMENTED_ARTIFACTS.some(e => e.plugin.toLowerCase() === value.toLowerCase() || e.plugin.toLowerCase().split(' ')[0] === value.toLowerCase())) throw new HttpError(400, 'Caminho de artefato inválido.');
  }
  if (kind === 'ip' && privateIPv4(value)) throw new HttpError(400, 'Endereço privado ou reservado: não enviar a bases externas.');
  if (kind === 'url') {
    let parsed;
    try { parsed = new URL(original); } catch { throw new HttpError(400, 'URL inválida.'); }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash ||
        (!validDomain(parsed.hostname) && !validIPv4(parsed.hostname))) throw new HttpError(400, 'URL inválida ou contendo credenciais/fragmento.');
    if (validIPv4(parsed.hostname) && privateIPv4(parsed.hostname)) throw new HttpError(400, 'Não enviar URLs locais a fontes externas.');
    value = original;
  }
  return { kind, value };
}
function trustedReference(value, host) {
  try {
    const parsed = new URL(String(value || ''));
    return parsed.protocol === 'https:' && parsed.hostname === host && !parsed.username && !parsed.password
      ? parsed.toString().slice(0, 350) : '';
  } catch { return ''; }
}
function tfRecord(entry, originalValue, kind) {
  const ioc = cleanText(entry.ioc, 250);
  const id = String(entry.id ?? '');
  const sourceUrl = /^\d{1,12}$/.test(id) ? `https://threatfox.abuse.ch/ioc/${id}/` : 'https://threatfox.abuse.ch/';
  return {
    type: kind, value: originalValue, source: 'ThreatFox', sourceUrl,
    description: `IOC associado: ${ioc || 'não informado'}. Ameaça: ${cleanText(entry.threat_type_desc || entry.threat_type, 160) || 'não especificada'}. Malware: ${cleanText(entry.malware_printable || entry.malware, 80) || 'não identificado'}.`,
    observedAt: cleanText(entry.last_seen || entry.first_seen, 40), method: 'consulta-api',
    confidence: Number.isFinite(Number(entry.confidence_level)) ? Math.min(100, Math.max(0, Number(entry.confidence_level))) : null
  };
}
async function threatFoxSearch(value, kind, key) {
  const payload = kind === 'hash'
    ? { query: 'search_hash', hash: value }
    : { query: 'search_ioc', search_term: value, exact_match: kind === 'url' };
  const data = await externalJSON('https://threatfox-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Auth-Key': key },
    body: JSON.stringify(payload)
  }, 9000, 500_000);
  if (data?.query_status === 'no_result' || data?.query_status === 'no_results') return [];
  if (data?.query_status !== 'ok' || !Array.isArray(data.data)) throw new Error('ThreatFox não retornou resultado válido.');
  const raw = data.data.slice(0, 50);
  const matches = raw.filter(entry => {
    if (!entry || typeof entry !== 'object') return false;
    if (kind === 'hash') return true;
    const found = String(entry.ioc || '').toLowerCase();
    const target = value.toLowerCase();
    return found === target || ((kind === 'ip' || kind === 'domain') && found.startsWith(target + ':'));
  });
  return matches.slice(0, 8).map(entry => tfRecord(entry, value, kind));
}
async function urlhausSearch(value, kind, key) {
  const endpoint = kind === 'hash' ? 'payload' : kind === 'url' ? 'url' : 'host';
  const param = kind === 'hash' ? (value.length === 64 ? 'sha256_hash' : 'md5_hash') : kind === 'url' ? 'url' : 'host';
  const data = await externalJSON(`https://urlhaus-api.abuse.ch/v1/${endpoint}/`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Auth-Key': key },
    body: new URLSearchParams({ [param]: value })
  }, 9000, 600_000);
  if (data?.query_status === 'no_results') return [];
  if (data?.query_status !== 'ok') throw new Error('URLhaus não retornou resultado válido.');
  let summary, sourceUrl;
  if (kind === 'hash') {
    if (String(data[value.length === 64 ? 'sha256_hash' : 'md5_hash'] || '').toLowerCase() !== value.toLowerCase()) throw new Error('Hash da resposta não corresponde ao solicitado.');
    summary = `Payload observado pela URLhaus. Família/assinatura: ${cleanText(data.signature, 70) || 'não informada'}. URLs associadas: ${Number(data.url_count) || 0}.`;
    sourceUrl = 'https://urlhaus.abuse.ch/';
  } else if (kind === 'url') {
    if (String(data.url || '').toLowerCase() !== value.toLowerCase()) throw new Error('URL da resposta não corresponde à solicitada.');
    summary = `URL registrada para distribuição de malware. Estado informado: ${cleanText(data.url_status, 30) || 'desconhecido'}.`;
    sourceUrl = trustedReference(data.urlhaus_reference, 'urlhaus.abuse.ch');
  } else {
    if (String(data.host || '').toLowerCase() !== value.toLowerCase()) throw new Error('Host da resposta não corresponde ao solicitado.');
    summary = `Host com ${Number(data.url_count) || 0} URL(s) de distribuição de malware registradas pela URLhaus. Isso não implica comprometimento de todos os sites do domínio.`;
    sourceUrl = trustedReference(data.urlhaus_reference, 'urlhaus.abuse.ch');
  }
  return [{
    type: kind, value, source: 'URLhaus', sourceUrl: sourceUrl || 'https://urlhaus.abuse.ch/',
    description: summary,
    observedAt: cleanText(data.date_added || data.firstseen || data.lastseen, 40), method: 'consulta-api'
  }];
}
async function ioc(payload, env) {
  const { kind, value } = iocInput(payload);
  if (kind === 'artifact') {
    const items = DOCUMENTED_ARTIFACTS.filter(e => e.value.toLowerCase() === value.toLowerCase() || e.plugin.toLowerCase() === value.toLowerCase() || e.plugin.toLowerCase().split(' ')[0] === value.toLowerCase());
    return {
      items,
      sources: [{name:'Sucuri', status:'documental'}],
      notice: 'Busca de correspondência exata em referências públicas documentadas da Sucuri. Não verifica os arquivos de nenhum site; ausência de referência não comprova segurança.'
    };
  }
  const key = env.ABUSECH_AUTH_KEY;
  if (typeof key !== 'string' || key.length < 12) {
    throw new HttpError(503, 'Pesquisa IOC externa ainda não configurada. Cadastre ABUSECH_AUTH_KEY como Secret nas Engines.');
  }
  const results = await Promise.allSettled([
    threatFoxSearch(value, kind, key),
    urlhausSearch(value, kind, key)
  ]);
  const sources = results.map((result, i) => ({
    name: i ? 'URLhaus' : 'ThreatFox',
    status: result.status === 'fulfilled' ? (result.value.length ? 'encontrado' : 'sem_registro') : 'indisponivel'
  }));
  if (results.every(r => r.status === 'rejected')) {
    throw new HttpError(502, 'Fontes de inteligência temporariamente indisponíveis. Nenhuma conclusão foi obtida.');
  }
  const items = results.flatMap(r => r.status === 'fulfilled' ? r.value : []).slice(0, 12);
  const incomplete = sources.some(source => source.status === 'indisponivel');
  return {
    items, sources,
    notice: `Consulta a ThreatFox e URLhaus por indicador exato, usando dados publicados pelas fontes. ${incomplete ? 'Cobertura parcial: uma fonte falhou. ' : ''}Ausência de registros não comprova segurança nem comprometimento. Os indicadores não são exclusivos do WordPress; a correspondência não verifica nenhum site.`
  };
}
function response(data, status = 200) {
  return new Response(JSON.stringify(data), {status, headers: {
    'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff', 'X-Robots-Tag': 'noindex, nofollow'
  }});
}
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const isIoc = url.pathname === '/api/ioc';
    if (request.method !== (isIoc ? 'POST' : 'GET')) return response({error: 'Método inválido.'}, 405);
    let iocBody = null;
    try {
      if (isIoc) iocBody = await readIocBody(request);
      if (!await authenticateInternal(request, env, url, iocBody)) return response({error: 'Acesso negado.'}, 403);
      verifyParams(url);
      let data;
      const cacheKey = new Request(new URL('/_cache_v3' + url.pathname + url.search, request.url), { method: 'GET' });
      switch (url.pathname) {
        case '/api/search': data = await searchPlugins(url); break;
        case '/api/plugin': data = await publicCache(cacheKey, 600, () => pluginInfo(url), ctx); break;
        case '/api/feed': data = await publicCache(cacheKey, 900, feed, ctx); break;
        case '/api/cve': data = await publicCache(cacheKey, 1200, () => cveSearch(url), ctx); break;
        case '/api/malware': data = await malware(url); break;
        case '/api/ioc': {
          let payload;
          try { payload = JSON.parse(iocBody); } catch { throw new HttpError(400, 'JSON inválido.'); }
          data = await ioc(payload, env);
          break;
        }
        default: throw new HttpError(404, 'Rota não encontrada.');
      }
      return response(data);
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 502;
      return response({error: error instanceof HttpError ? error.message : 'Consulta temporariamente indisponível.'}, status);
    }
  }
};
