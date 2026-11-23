
const encoder = new TextEncoder();

const ROUTES = Object.freeze({
  '/api/feed': 7,
  '/api/search': 1,
  '/api/plugin': 2,
  '/api/cve': 4,
  '/api/malware': 3,
  '/api/ioc': 1
});

const TTL_MS = 10 * 60 * 1000;
const MAX_QUERY = 520;
const MAX_PRIVATE_BYTES = 280_000;
const MAX_VERIFY_BYTES = 12_000;

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function json(body, status = 200, origin = '') {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Robots-Tag': 'noindex, nofollow',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'Vary': 'Origin'
  });

  if (origin) {
    headers.set('Access-Control-Allow-Origin', origin);
  }

  if (status === 429) {
    headers.set('Retry-After', '60');
  }

  headers.set('X-Frame-Options', 'DENY');

  headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()'
  );

  return new Response(JSON.stringify(body), {
    status,
    headers
  });
}

function base64url(raw) {
  const bytes = new Uint8Array(raw);
  let str = '';

  for (const b of bytes) {
    str += String.fromCharCode(b);
  }

  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function decodeBase64url(s) {
  return Uint8Array.from(
    atob(s.replace(/-/g, '+').replace(/_/g, '/')),
    c => c.charCodeAt(0)
  );
}

async function keyMaterial(secret, purposes = ['sign', 'verify']) {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    purposes
  );
}

async function sign(secret, text) {
  const key = await keyMaterial(secret, ['sign']);

  return base64url(
    await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(text)
    )
  );
}

async function verify(secret, text, b64) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(b64)) {
    return false;
  }

  const key = await keyMaterial(secret, ['verify']);

  return crypto.subtle.verify(
    'HMAC',
    key,
    decodeBase64url(b64),
    encoder.encode(text)
  );
}

function clientIp(request) {
  const ip = request.headers.get('CF-Connecting-IP');

  if (
    !ip ||
    ip.length > 55 ||
    !/^[0-9A-Fa-f:.]+$/.test(ip)
  ) {
    throw new ApiError(
      503,
      'Proteção de acesso indisponível.'
    );
  }

  return ip;
}

function requireSecrets(env) {
  const checks = [
    [
      'C01',
      typeof env.SESSION_SIGNING_KEY === 'string' &&
      env.SESSION_SIGNING_KEY.length >= 32
    ],
    [
      'C02',
      typeof env.RATE_KEY_SECRET === 'string' &&
      env.RATE_KEY_SECRET.length >= 32
    ],
    [
      'C03',
      typeof env.INTERNAL_KEY === 'string' &&
      env.INTERNAL_KEY.length >= 32
    ],
    [
      'C04',
      typeof env.TURNSTILE_SECRET === 'string' &&
      env.TURNSTILE_SECRET.length >= 16
    ],
    [
      'C05',
      typeof env.ENGINES?.fetch === 'function'
    ],
    [
      'C06',
      typeof env.GENERAL_RATE?.limit === 'function'
    ],
    [
      'C07',
      typeof env.HEAVY_RATE?.limit === 'function'
    ],
    [
      'C08',
      typeof env.AUTH_RATE?.limit === 'function'
    ]
  ];

  const missing = checks
    .filter(([, valid]) => !valid)
    .map(([code]) => code);

  if (missing.length) {
    throw new ApiError(
      503,
      'Serviço ainda não configurado. Diagnóstico: ' +
      missing.join(',')
    );
  }
}

async function rateKey(ip, env) {
  const epoch = Math.floor(Date.now() / 86400000);

  const digest = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(
      `${env.RATE_KEY_SECRET}|${epoch}|${ip}`
    )
  );

  return base64url(
    new Uint8Array(digest).slice(0, 18)
  );
}

async function limit(env, key, binding, delta = 1) {
  const res = await env[binding].limit({
    key,
    delta
  });

  if (!res?.success) {
    throw new ApiError(
      429,
      'Limite temporário de consultas. Aguarde um minuto.'
    );
  }
}

async function readBoundedJSON(request, maxBytes) {
  if (
    !/^application\/json(?:\s*;|$)/i.test(
      request.headers.get('Content-Type') || ''
    )
  ) {
    throw new ApiError(415, 'Envie JSON.');
  }

  if (
    Number(request.headers.get('Content-Length') || 0) >
    maxBytes
  ) {
    throw new ApiError(413, 'Dados muito grandes.');
  }

  const reader = request.body?.getReader();

  if (!reader) {
    throw new ApiError(400, 'Corpo não informado.');
  }

  let count = 0;
  const chunks = [];

  while (true) {
    const { done, value } = await reader.read();

    if (done) {
      break;
    }

    count += value.byteLength;

    if (count > maxBytes) {
      await reader.cancel().catch(() => {});

      throw new ApiError(413, 'Dados muito grandes.');
    }

    chunks.push(value);
  }

  const bytes = new Uint8Array(count);
  let offset = 0;

  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return JSON.parse(
      new TextDecoder('utf-8', { fatal: true })
        .decode(bytes)
    );
  } catch {
    throw new ApiError(400, 'JSON inválido.');
  }
}

async function boundedResponseJSON(res, maxBytes) {
  const declared = Number(
    res.headers.get('Content-Length') || '0'
  );

  if (declared > maxBytes) {
    throw new ApiError(
      502,
      'Resposta externa acima do limite.'
    );
  }

  const reader = res.body?.getReader();

  if (!reader) {
    throw new ApiError(
      502,
      'Resposta externa sem corpo.'
    );
  }

  let count = 0;
  const parts = [];

  while (true) {
    const { done, value } = await reader.read();

    if (done) {
      break;
    }

    count += value.byteLength;

    if (count > maxBytes) {
      await reader.cancel().catch(() => {});

      throw new ApiError(
        502,
        'Resposta externa acima do limite.'
      );
    }

    parts.push(value);
  }

  const joined = new Uint8Array(count);
  let offset = 0;

  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }

  try {
    return JSON.parse(
      new TextDecoder('utf-8', { fatal: true })
        .decode(joined)
    );
  } catch {
    throw new ApiError(
      502,
      'Resposta externa inválida.'
    );
  }
}

async function turnstileValidate(token, env) {
  if (
    typeof token !== 'string' ||
    token.length < 5 ||
    token.length > 2048
  ) {
    throw new ApiError(
      403,
      'Verificação humana necessária.'
    );
  }

  const ctrl = new AbortController();

  const timeout = setTimeout(
    () => ctrl.abort(),
    7000
  );

  try {
    const payload = new URLSearchParams({
      secret: env.TURNSTILE_SECRET,
      response: token
    });

    const response = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'POST',
        body: payload,
        redirect: 'manual',
        signal: ctrl.signal
      }
    );

    if (!response.ok) {
      throw new ApiError(
        503,
        `Siteverify HTTP ${response.status}`
      );
    }

    const data = await boundedResponseJSON(
      response,
      MAX_VERIFY_BYTES
    );

    const hostname = new URL(
      env.SITE_ORIGIN
    ).hostname;

    if (
      !data.success ||
      data.hostname !== hostname ||
      data.action !== 'hacktiba_access'
    ) {
      throw new ApiError(
        403,
        'Verificação não autorizada. Tente novamente.'
      );
    }

  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }

    throw new ApiError(
      503,
      ctrl.signal.aborted
        ? 'Serviço de verificação indisponível. Diagnóstico: T01'
        : 'Serviço de verificação indisponível. Diagnóstico: T02'
    );

  } finally {
    clearTimeout(timeout);
  }
}

async function issueSession(ip, env) {
  const expiry = (
    Date.now() + TTL_MS
  ).toString(36);

  const nonce = base64url(
    crypto.getRandomValues(new Uint8Array(16))
  );

  const payload = `v1.${expiry}.${nonce}`;

  const signature = await sign(
    env.SESSION_SIGNING_KEY,
    `${payload}|${ip}`
  );

  return `${payload}.${signature}`;
}

async function sessionValid(request, env, ip) {
  const auth = request.headers.get('Authorization') || '';

  const match =
    /^Bearer (v1\.([0-9a-z]+)\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43}))$/
      .exec(auth);

  if (!match) {
    return false;
  }

  const exp = parseInt(match[2], 36);

  if (
    !Number.isSafeInteger(exp) ||
    exp < Date.now() ||
    exp > Date.now() + TTL_MS + 5000
  ) {
    return false;
  }

  return verify(
    env.SESSION_SIGNING_KEY,
    `v1.${match[2]}.${match[3]}|${ip}`,
    match[4]
  );
}

async function privateRequest(url, env) {
  const ts = Date.now().toString();

  const signature = await sign(
    env.INTERNAL_KEY,
    `${ts}\n${url.pathname}\n${url.search}`
  );

  const upstream = new URL(
    url.pathname + url.search,
    'https://hacktiba.internal'
  );

  const ctrl = new AbortController();

  const timeout = setTimeout(
    () => ctrl.abort(),
    26000
  );

  try {
    const response = await env.ENGINES.fetch(
      new Request(upstream.toString(), {
        method: 'GET',
        headers: {
          'X-Hacktiba-Timestamp': ts,
          'X-Hacktiba-Signature': signature
        },
        signal: ctrl.signal
      })
    );

    if (
      response.status !== 200 &&
      ![
        400, 404, 405, 413,
        414, 429, 502, 503
      ].includes(response.status)
    ) {
      throw new ApiError(
        502,
        'Resposta interna inesperada.'
      );
    }

    if (
      !/^application\/json(?:\s*;|$)/i.test(
        response.headers.get('Content-Type') || ''
      )
    ) {
      throw new ApiError(
        502,
        'Resposta interna não é JSON.'
      );
    }

    const value = await boundedResponseJSON(
      response,
      MAX_PRIVATE_BYTES
    );

    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value)
    ) {
      throw new ApiError(
        502,
        'Resposta interna inválida.'
      );
    }

    return {
      status: response.status,
      value
    };

  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }

    throw new ApiError(
      502,
      'Pesquisa temporariamente indisponível.'
    );

  } finally {
    clearTimeout(timeout);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const allowedOrigin = String(
      env.SITE_ORIGIN || ''
    ).replace(/\/$/, '');

    const origin = request.headers.get('Origin') || '';

    const permitted =
      allowedOrigin && origin === allowedOrigin;

    if (
      url.pathname === '/api/health' &&
      request.method === 'GET'
    ) {
      return json({
        ok: true,
        component: 'gateway'
      });
    }

    if (!permitted) {
      return json(
        { error: 'Origem não autorizada.' },
        403
      );
    }

    if (request.method === 'OPTIONS') {
      if (
        url.pathname !== '/api/session' &&
        !Object.hasOwn(ROUTES, url.pathname)
      ) {
        return json(
          { error: 'Rota inexistente.' },
          404,
          origin
        );
      }

      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods':
            url.pathname === '/api/session'
              ? 'POST, OPTIONS'
              : 'GET, OPTIONS',
          'Access-Control-Allow-Headers':
            'Authorization, Content-Type',
          'Access-Control-Max-Age': '600',
          'Vary': 'Origin'
        }
      });
    }

    try {
      requireSecrets(env);

      if (url.search.length > MAX_QUERY) {
        throw new ApiError(
          414,
          'Consulta muito longa.'
        );
      }

      const ip = clientIp(request);

      const key = await rateKey(ip, env);

      await limit(
        env,
        key,
        'GENERAL_RATE'
      );

      if (url.pathname === '/api/session') {
        if (
          request.method !== 'POST' ||
          url.search
        ) {
          throw new ApiError(
            405,
            'Método inválido.'
          );
        }

        await limit(
          env,
          key,
          'AUTH_RATE'
        );

        const body = await readBoundedJSON(
          request,
          4096
        );

        if (
          !body ||
          typeof body !== 'object' ||
          Array.isArray(body) ||
          Object.keys(body).some(
            k => k !== 'token'
          )
        ) {
          throw new ApiError(
            400,
            'Formato de sessão inválido.'
          );
        }

        await turnstileValidate(
          body.token,
          env
        );

        return json(
          {
            session: await issueSession(ip, env),
            expiresIn: TTL_MS / 1000
          },
          200,
          origin
        );
      }

      if (!Object.hasOwn(ROUTES, url.pathname)) {
        throw new ApiError(
          404,
          'Rota inexistente.'
        );
      }

      if (request.method !== 'GET') {
        throw new ApiError(
          405,
          'Método inválido.'
        );
      }

      if (!await sessionValid(request, env, ip)) {
        throw new ApiError(
          401,
          'Sessão expirada. Confirme seu acesso novamente.'
        );
      }

      await limit(
        env,
        key,
        'HEAVY_RATE',
        ROUTES[url.pathname]
      );

      const response = await privateRequest(
        url,
        env
      );

      return json(
        response.value,
        response.status,
        origin
      );

    } catch (err) {
      const code = err instanceof ApiError
        ? err.status
        : 502;

      return json(
        {
          error: err instanceof ApiError
            ? err.message
            : 'Falha temporária.'
        },
        code,
        origin
      );
    }
  }
};
