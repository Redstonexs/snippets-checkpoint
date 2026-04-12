// Fill these keys before production rollout.
const SECRET_KEY = '';
const TURNSTILE_SITE_KEY = '';
const TURNSTILE_SECRET_KEY = '';

const TOKEN_COOKIE = 'cf_token';
const COOKIE_MAX_AGE = 300;
const FAIL_OPEN_ON_MISCONFIG = true;

const TURNSTILE_VERIFY_PATH = '/__cf-turnstile/verify';
const TURNSTILE_VERIFY_API = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

const POW_VERIFY_PATH = '/__cf-pow/verify';
const POW_DIFFICULTY = 4;
const POW_MAX_DIFFICULTY = 6;
const POW_CHALLENGE_TTL = 120;

const HIGH_BOT_SCORE_THRESHOLD = 15;
const LOW_BOT_SCORE_THRESHOLD = 35;
const HIGH_THREAT_SCORE_THRESHOLD = 20;
const LOW_THREAT_SCORE_THRESHOLD = 5;
const HIGH_RISK_SCORE_THRESHOLD = 7;
const LOW_RISK_SCORE_THRESHOLD = 3;

const AUTOMATION_UA_PATTERN = /(curl|wget|python-requests|aiohttp|httpclient|okhttp|go-http-client|powershell|java\/|libwww-perl|scrapy|postmanruntime|insomnia|node-fetch|axios)/i;

const RISK_LEVEL = Object.freeze({
  CLEAN: 'clean',
  LOW: 'low',
  HIGH: 'high'
});

const PASS_LEVEL = Object.freeze({
  POW: 'pow',
  TURNSTILE: 'turnstile'
});

const encoder = new TextEncoder();

let cachedKey = null;
async function getCachedKey() {
  if (cachedKey) return cachedKey;
  cachedKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(SECRET_KEY),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  return cachedKey;
}

function bufToHex(buf) {
  const bytes = new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

function hexToUint8Array(hex) {
  if (!hex || hex.length % 2 !== 0) return new Uint8Array();
  const len = hex.length / 2;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function isHexString(value) {
  return typeof value === 'string' && /^[0-9a-f]+$/i.test(value);
}

function getCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(';');
  for (let i = 0; i < parts.length; i++) {
    const item = parts[i];
    const idx = item.indexOf('=');
    if (idx === -1) continue;
    const key = item.slice(0, idx).trim();
    const value = item.slice(idx + 1).trim();
    if (key === name) return decodeURIComponent(value);
  }
  return null;
}

function nowInSeconds() {
  return Math.floor(Date.now() / 1000);
}

function safeReturnPath(rawValue) {
  if (typeof rawValue !== 'string' || rawValue.length === 0) return '/';
  if (!rawValue.startsWith('/') || rawValue.startsWith('//')) return '/';
  return rawValue;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function noStoreHeaders(extraHeaders = {}) {
  return {
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    ...extraHeaders
  };
}

function isChallengeEligibleRequest(request) {
  const method = (request.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') return false;

  const accept = (request.headers.get('Accept') || '').toLowerCase();
  if (!accept.includes('text/html')) return false;

  const secFetchDest = (request.headers.get('Sec-Fetch-Dest') || '').toLowerCase();
  if (secFetchDest && secFetchDest !== 'document' && secFetchDest !== 'empty') return false;

  const secFetchMode = (request.headers.get('Sec-Fetch-Mode') || '').toLowerCase();
  if (secFetchMode && secFetchMode !== 'navigate') return false;

  return true;
}

function buildCookie(token) {
  return `${TOKEN_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`;
}

function isTurnstileConfigured() {
  return Boolean(TURNSTILE_SITE_KEY && TURNSTILE_SECRET_KEY);
}

function getHttpProtocol(request) {
  const cf = request.cf || {};
  if (typeof cf.httpProtocol === 'string' && cf.httpProtocol) {
    return cf.httpProtocol.toUpperCase();
  }
  return '';
}

function getRiskLevel(request) {
  const headers = request.headers;
  const cf = request.cf || {};
  const threatScore = Number.isFinite(cf.threatScore) ? cf.threatScore : null;
  const botScore = cf.botManagement && Number.isFinite(cf.botManagement.score)
    ? cf.botManagement.score
    : null;
  const ua = (headers.get('User-Agent') || '').trim();
  const accept = (headers.get('Accept') || '').trim().toLowerCase();

  let score = 0;

  if (threatScore !== null && threatScore >= HIGH_THREAT_SCORE_THRESHOLD) {
    return RISK_LEVEL.HIGH;
  }

  if (botScore !== null && botScore <= HIGH_BOT_SCORE_THRESHOLD) {
    return RISK_LEVEL.HIGH;
  }

  if (threatScore !== null && threatScore >= LOW_THREAT_SCORE_THRESHOLD) score += 2;
  if (botScore !== null && botScore <= LOW_BOT_SCORE_THRESHOLD) score += 2;

  if (!ua) {
    score += 3;
  } else {
    if (ua.length < 18) score += 2;
    if (AUTOMATION_UA_PATTERN.test(ua)) score += 4;
  }

  if (!accept) {
    score += 2;
  } else if (accept === '*/*') {
    score += 1;
  }

  const acceptLanguage = (headers.get('Accept-Language') || '').trim();
  if (!acceptLanguage) score += 1;

  const secFetchSite = (headers.get('Sec-Fetch-Site') || '').trim();
  const secFetchMode = (headers.get('Sec-Fetch-Mode') || '').trim();
  const secFetchDest = (headers.get('Sec-Fetch-Dest') || '').trim();
  if (!secFetchSite) score += 1;
  if (!secFetchMode) score += 1;
  if (!secFetchDest) score += 1;

  const secChUa = (headers.get('Sec-CH-UA') || '').trim();
  if (!secChUa && ua) score += 1;

  const httpProtocol = getHttpProtocol(request);
  if (httpProtocol === 'HTTP/1.0') {
    score += 4;
  } else if (httpProtocol === 'HTTP/1.1') {
    score += 1;
  }

  const connection = (headers.get('Connection') || '').trim().toLowerCase();
  if ((httpProtocol === 'HTTP/2' || httpProtocol === 'HTTP/3') && connection) {
    score += 2;
  }
  if (httpProtocol === 'HTTP/1.1' && connection === 'close') {
    score += 1;
  }

  const tlsVersion = typeof cf.tlsVersion === 'string' ? cf.tlsVersion.toUpperCase() : '';
  if (tlsVersion === 'TLSV1' || tlsVersion === 'TLSV1.1') {
    score += 2;
  }

  if (score >= HIGH_RISK_SCORE_THRESHOLD) return RISK_LEVEL.HIGH;
  if (score >= LOW_RISK_SCORE_THRESHOLD) return RISK_LEVEL.LOW;
  return RISK_LEVEL.CLEAN;
}

async function issuePassToken(clientIP, key, passLevel) {
  if (passLevel !== PASS_LEVEL.POW && passLevel !== PASS_LEVEL.TURNSTILE) {
    return null;
  }

  const expiry = nowInSeconds() + COOKIE_MAX_AGE;
  const payload = `${clientIP}:${passLevel}:${expiry}`;
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return `${passLevel}:${expiry}:${bufToHex(signature)}`;
}

async function parseAndValidatePassToken(token, clientIP, key) {
  if (!token) return { valid: false, level: null };

  const parts = token.split(':');
  if (parts.length !== 3) return { valid: false, level: null };

  const level = parts[0];
  const expiry = Number.parseInt(parts[1], 10);
  const signatureHex = parts[2];

  if (level !== PASS_LEVEL.POW && level !== PASS_LEVEL.TURNSTILE) {
    return { valid: false, level: null };
  }

  if (!Number.isFinite(expiry) || nowInSeconds() > expiry) {
    return { valid: false, level: null };
  }

  const signatureBytes = hexToUint8Array(signatureHex);
  if (signatureBytes.length === 0) return { valid: false, level: null };

  try {
    const payload = `${clientIP}:${level}:${expiry}`;
    const ok = await crypto.subtle.verify('HMAC', key, signatureBytes, encoder.encode(payload));
    if (!ok) return { valid: false, level: null };
    return { valid: true, level };
  } catch (_err) {
    return { valid: false, level: null };
  }
}

function renderTurnstilePage(returnTo, errorText) {
  const safeReturnTo = escapeHtml(returnTo);
  const message = errorText
    ? `<p class="error">${escapeHtml(errorText)}</p>`
    : '<p class="hint">High-risk traffic requires a human verification.</p>';

  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Security Verification</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
      :root { color-scheme: light; }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        font-family: ui-sans-serif, -apple-system, Segoe UI, Arial, sans-serif;
        background: radial-gradient(circle at 15% 20%, #fff2f2 0%, #fff8f7 40%, #f8f8fb 100%);
        color: #172235;
      }
      .card {
        width: min(92vw, 430px);
        box-sizing: border-box;
        padding: 24px;
        border-radius: 14px;
        background: #ffffff;
        border: 1px solid #f0dada;
        box-shadow: 0 12px 30px rgba(67, 16, 16, 0.08);
      }
      h1 {
        margin: 0 0 10px;
        font-size: 20px;
        line-height: 1.3;
      }
      .hint {
        margin: 0 0 18px;
        color: #5d6779;
      }
      .error {
        margin: 0 0 18px;
        color: #b3261e;
        font-weight: 600;
      }
      .submit {
        margin-top: 16px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 100%;
        height: 42px;
        border: 0;
        border-radius: 10px;
        background: #cc2936;
        color: #fff;
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
      }
      .submit:hover { background: #ad2230; }
      .submit:active { transform: translateY(1px); }
    </style>
  </head>
  <body>
    <main class="card">
      <h1>Security Check</h1>
      ${message}
      <form method="POST" action="${TURNSTILE_VERIFY_PATH}">
        <input type="hidden" name="return_to" value="${safeReturnTo}" />
        <div class="cf-turnstile" data-sitekey="${escapeHtml(TURNSTILE_SITE_KEY)}"></div>
        <button class="submit" type="submit">Continue</button>
      </form>
    </main>
  </body>
</html>`;
}

function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bufToHex(bytes.buffer);
}

async function issuePowChallenge(clientIP, key) {
  const nonce = randomHex(16);
  const expiry = nowInSeconds() + POW_CHALLENGE_TTL;
  const difficulty = POW_DIFFICULTY;
  const payload = `pow:${clientIP}:${nonce}:${expiry}:${difficulty}`;
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));

  return {
    nonce,
    expiry,
    difficulty,
    signature: bufToHex(signature)
  };
}

function renderPowPage(challenge, returnTo, errorText) {
  const safeReturnTo = escapeHtml(returnTo);
  const message = errorText
    ? `<p class="error">${escapeHtml(errorText)}</p>`
    : '<p class="hint">Low-risk suspicious traffic must complete a PoW check.</p>';

  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Proof of Work</title>
    <style>
      :root { color-scheme: light; }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        font-family: ui-sans-serif, -apple-system, Segoe UI, Arial, sans-serif;
        background: radial-gradient(circle at 10% 10%, #f2fff8 0%, #f6fffb 35%, #f3f7ff 100%);
        color: #172235;
      }
      .card {
        width: min(92vw, 500px);
        box-sizing: border-box;
        padding: 24px;
        border-radius: 14px;
        background: #ffffff;
        border: 1px solid #d5eee2;
        box-shadow: 0 12px 30px rgba(16, 67, 42, 0.10);
      }
      h1 {
        margin: 0 0 10px;
        font-size: 20px;
        line-height: 1.3;
      }
      .hint {
        margin: 0 0 12px;
        color: #4f5f76;
      }
      .error {
        margin: 0 0 12px;
        color: #b3261e;
        font-weight: 600;
      }
      .meta {
        margin: 0 0 12px;
        color: #6f7a8f;
        font-size: 13px;
      }
      .status {
        margin: 8px 0 0;
        color: #1e3a8a;
        font-weight: 600;
      }
      .noscript {
        margin-top: 12px;
        color: #9a3412;
        font-size: 14px;
      }
    </style>
  </head>
  <body>
    <main class="card">
      <h1>Proof of Work</h1>
      ${message}
      <p class="meta">Difficulty: ${challenge.difficulty} leading zeroes, expires in ${POW_CHALLENGE_TTL}s.</p>
      <p id="pow-status" class="status">Preparing challenge...</p>

      <form id="pow-form" method="POST" action="${POW_VERIFY_PATH}"
        data-nonce="${escapeHtml(challenge.nonce)}"
        data-difficulty="${challenge.difficulty}">
        <input type="hidden" name="return_to" value="${safeReturnTo}" />
        <input type="hidden" name="nonce" value="${escapeHtml(challenge.nonce)}" />
        <input type="hidden" name="expiry" value="${challenge.expiry}" />
        <input type="hidden" name="difficulty" value="${challenge.difficulty}" />
        <input type="hidden" name="signature" value="${escapeHtml(challenge.signature)}" />
        <input id="pow-answer" type="hidden" name="pow_answer" value="" />
      </form>

      <noscript>
        <p class="noscript">JavaScript is required to complete proof of work.</p>
      </noscript>
    </main>

    <script>
      (async function () {
        const statusNode = document.getElementById('pow-status');
        const form = document.getElementById('pow-form');
        const answerInput = document.getElementById('pow-answer');
        const nonce = String(form.dataset.nonce || '');
        const difficulty = Number(form.dataset.difficulty || 0);
        const targetPrefix = '0'.repeat(difficulty);

        const localEncoder = new TextEncoder();
        function toHex(buffer) {
          const bytes = new Uint8Array(buffer);
          let out = '';
          for (let i = 0; i < bytes.length; i++) {
            out += bytes[i].toString(16).padStart(2, '0');
          }
          return out;
        }

        async function digestHex(text) {
          const hash = await crypto.subtle.digest('SHA-256', localEncoder.encode(text));
          return toHex(hash);
        }

        let attempt = 0;
        const startedAt = Date.now();
        statusNode.textContent = 'Computing proof of work...';

        while (true) {
          const hashHex = await digestHex(nonce + ':' + attempt);
          if (hashHex.slice(0, difficulty) === targetPrefix) {
            answerInput.value = String(attempt);
            statusNode.textContent = 'Solved. Redirecting...';
            form.submit();
            return;
          }

          attempt += 1;
          if (attempt % 250 === 0) {
            const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
            statusNode.textContent = 'Computing proof of work... attempts: ' + attempt + ', ' + elapsed + 's';
            await new Promise(function (resolve) { setTimeout(resolve, 0); });
          }
        }
      })();
    </script>
  </body>
</html>`;
}

async function verifyPowSubmission(form, clientIP, key) {
  const nonce = form.get('nonce');
  const expiryRaw = form.get('expiry');
  const difficultyRaw = form.get('difficulty');
  const signatureHex = form.get('signature');
  const answer = form.get('pow_answer');

  if (typeof nonce !== 'string' || !isHexString(nonce) || nonce.length < 16 || nonce.length > 64) {
    return { success: false, message: 'Invalid challenge nonce.' };
  }

  if (typeof expiryRaw !== 'string' || typeof difficultyRaw !== 'string') {
    return { success: false, message: 'Invalid challenge metadata.' };
  }

  const expiry = Number.parseInt(expiryRaw, 10);
  const difficulty = Number.parseInt(difficultyRaw, 10);
  if (!Number.isFinite(expiry) || !Number.isFinite(difficulty)) {
    return { success: false, message: 'Invalid challenge parameters.' };
  }

  if (difficulty < 1 || difficulty > POW_MAX_DIFFICULTY) {
    return { success: false, message: 'Unsupported challenge difficulty.' };
  }

  if (nowInSeconds() > expiry) {
    return { success: false, message: 'PoW challenge expired. Please retry.' };
  }

  if (typeof signatureHex !== 'string' || !isHexString(signatureHex) || signatureHex.length !== 64) {
    return { success: false, message: 'Invalid challenge signature.' };
  }

  const signatureBytes = hexToUint8Array(signatureHex);
  const signedPayload = `pow:${clientIP}:${nonce}:${expiry}:${difficulty}`;

  let signatureOK = false;
  try {
    signatureOK = await crypto.subtle.verify('HMAC', key, signatureBytes, encoder.encode(signedPayload));
  } catch (_err) {
    signatureOK = false;
  }

  if (!signatureOK) {
    return { success: false, message: 'Challenge signature mismatch.' };
  }

  if (typeof answer !== 'string' || !/^[0-9]{1,15}$/.test(answer)) {
    return { success: false, message: 'PoW answer is missing.' };
  }

  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(`${nonce}:${answer}`));
  const digestHex = bufToHex(digest);
  if (!digestHex.startsWith('0'.repeat(difficulty))) {
    return { success: false, message: 'PoW answer is invalid.' };
  }

  return { success: true };
}

async function buildPowChallengeResponse(returnTo, clientIP, key, errorText, statusCode = 403) {
  const challenge = await issuePowChallenge(clientIP, key);
  return new Response(renderPowPage(challenge, returnTo, errorText), {
    status: statusCode,
    headers: noStoreHeaders({ 'Content-Type': 'text/html; charset=utf-8' })
  });
}

async function verifyTurnstileToken(turnstileToken, clientIP) {
  const body = new URLSearchParams();
  body.set('secret', TURNSTILE_SECRET_KEY);
  body.set('response', turnstileToken);
  if (clientIP) body.set('remoteip', clientIP);

  const resp = await fetch(TURNSTILE_VERIFY_API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });

  if (!resp.ok) {
    return { success: false, errors: [`http_${resp.status}`] };
  }

  const json = await resp.json();
  const errors = Array.isArray(json['error-codes']) ? json['error-codes'] : [];
  return { success: json.success === true, errors };
}

function misconfiguredSecretResponse() {
  return new Response('SECRET_KEY is not configured.', {
    status: 503,
    headers: noStoreHeaders({ 'Content-Type': 'text/plain; charset=utf-8' })
  });
}

function misconfiguredTurnstileResponse() {
  return new Response('Turnstile is not configured.', {
    status: 503,
    headers: noStoreHeaders({ 'Content-Type': 'text/plain; charset=utf-8' })
  });
}

async function handlePowVerification(request, key) {
  const clientIP = request.headers.get('CF-Connecting-IP') || '';

  let form;
  try {
    form = await request.formData();
  } catch (_err) {
    return new Response('Bad Request', { status: 400 });
  }

  const returnTo = safeReturnPath(form.get('return_to'));
  const verifyResult = await verifyPowSubmission(form, clientIP, key);

  if (!verifyResult.success) {
    return buildPowChallengeResponse(returnTo, clientIP, key, verifyResult.message);
  }

  const token = await issuePassToken(clientIP, key, PASS_LEVEL.POW);
  return new Response(null, {
    status: 303,
    headers: noStoreHeaders({
      Location: returnTo,
      'Set-Cookie': buildCookie(token)
    })
  });
}

async function handleTurnstileVerification(request, key) {
  const clientIP = request.headers.get('CF-Connecting-IP') || '';

  let form;
  try {
    form = await request.formData();
  } catch (_err) {
    return new Response('Bad Request', { status: 400 });
  }

  const returnTo = safeReturnPath(form.get('return_to'));
  const turnstileToken = form.get('cf-turnstile-response');

  if (typeof turnstileToken !== 'string' || !turnstileToken) {
    return new Response(renderTurnstilePage(returnTo, 'Turnstile token is missing.'), {
      status: 403,
      headers: noStoreHeaders({ 'Content-Type': 'text/html; charset=utf-8' })
    });
  }

  let verifyResult;
  try {
    verifyResult = await verifyTurnstileToken(turnstileToken, clientIP);
  } catch (_err) {
    return new Response(renderTurnstilePage(returnTo, 'Verification service is unavailable.'), {
      status: 503,
      headers: noStoreHeaders({ 'Content-Type': 'text/html; charset=utf-8' })
    });
  }

  if (!verifyResult.success) {
    const firstError = verifyResult.errors.length > 0
      ? `Verification failed: ${verifyResult.errors[0]}`
      : 'Verification failed, please try again.';

    return new Response(renderTurnstilePage(returnTo, firstError), {
      status: 403,
      headers: noStoreHeaders({ 'Content-Type': 'text/html; charset=utf-8' })
    });
  }

  const token = await issuePassToken(clientIP, key, PASS_LEVEL.TURNSTILE);
  return new Response(null, {
    status: 303,
    headers: noStoreHeaders({
      Location: returnTo,
      'Set-Cookie': buildCookie(token)
    })
  });
}

export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);

      if (url.pathname === POW_VERIFY_PATH && request.method === 'POST') {
        if (!SECRET_KEY) {
          if (FAIL_OPEN_ON_MISCONFIG) {
            return new Response(null, {
              status: 303,
              headers: noStoreHeaders({ Location: safeReturnPath(url.searchParams.get('return_to') || '/') })
            });
          }
          return misconfiguredSecretResponse();
        }

        const key = await getCachedKey();
        return handlePowVerification(request, key);
      }

      if (url.pathname === TURNSTILE_VERIFY_PATH && request.method === 'POST') {
        if (!SECRET_KEY) {
          if (FAIL_OPEN_ON_MISCONFIG) {
            return new Response(null, {
              status: 303,
              headers: noStoreHeaders({ Location: safeReturnPath(url.searchParams.get('return_to') || '/') })
            });
          }
          return misconfiguredSecretResponse();
        }

        const key = await getCachedKey();
        if (!isTurnstileConfigured()) {
          if (FAIL_OPEN_ON_MISCONFIG) {
            return handlePowVerification(request, key);
          }
          return misconfiguredTurnstileResponse();
        }

        return handleTurnstileVerification(request, key);
      }

      if (!SECRET_KEY) {
        if (FAIL_OPEN_ON_MISCONFIG) return fetch(request);
        return misconfiguredSecretResponse();
      }
      const key = await getCachedKey();

      // Never return HTML challenges to API/subresource calls.
      const canChallenge = isChallengeEligibleRequest(request);

      const riskLevel = getRiskLevel(request);
      if (riskLevel === RISK_LEVEL.CLEAN) {
        return fetch(request);
      }

      const clientIP = request.headers.get('CF-Connecting-IP') || '';
      const cookieHeader = request.headers.get('Cookie') || '';
      const passToken = getCookie(cookieHeader, TOKEN_COOKIE);
      const passState = await parseAndValidatePassToken(passToken, clientIP, key);
      const canBypassLowRisk = passState.valid;
      const canBypassHighRisk = passState.valid && passState.level === PASS_LEVEL.TURNSTILE;
      if ((riskLevel === RISK_LEVEL.LOW && canBypassLowRisk) || (riskLevel === RISK_LEVEL.HIGH && canBypassHighRisk)) {
        return fetch(request);
      }

      if (!canChallenge) {
        return fetch(request);
      }

      const returnTo = safeReturnPath(`${url.pathname}${url.search}`);

      if (riskLevel === RISK_LEVEL.HIGH) {
        if (!isTurnstileConfigured()) {
          if (FAIL_OPEN_ON_MISCONFIG) {
            return buildPowChallengeResponse(returnTo, clientIP, key, 'Turnstile unavailable, using PoW fallback.');
          }
          return misconfiguredTurnstileResponse();
        }

        return new Response(renderTurnstilePage(returnTo), {
          status: 403,
          headers: noStoreHeaders({ 'Content-Type': 'text/html; charset=utf-8' })
        });
      }

      return buildPowChallengeResponse(returnTo, clientIP, key);
    } catch (err) {
      console.error('Snippet error:', err && err.stack ? err.stack : err);
      return new Response('Error', { status: 500 });
    }
  }
};
