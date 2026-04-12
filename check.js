// 可直接放到 Cloudflare Snippets 中（注意：生产环境请替换 SECRET_KEY）
const SECRET_KEY = '';
const TOKEN_COOKIE = 'cf_token';
const COOKIE_MAX_AGE = 300; // token 有效期（秒）
const encoder = new TextEncoder();

// 缓存导入的 CryptoKey
let _cachedKey = null;
async function getCachedKey() {
  if (_cachedKey) return _cachedKey;
  _cachedKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(SECRET_KEY),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  return _cachedKey;
}

// ArrayBuffer -> hex
function bufToHex(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += ('0' + bytes[i].toString(16)).slice(-2);
  }
  return s;
}
// hex -> Uint8Array
function hexToUint8Array(hex) {
  if (!hex) return new Uint8Array();
  const len = hex.length / 2;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

// 解析 Cookie（更稳健，处理 value 中可能含 '=' 的情况）
function getCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(';');
  for (let p of parts) {
    const idx = p.indexOf('=');
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return null;
}

// 生成 challenge 响应（含 Set-Cookie + 可见的 HTML + meta content）
async function challengeResponse(clientIP, key) {
  const now = Math.floor(Date.now() / 1000);
  const expiry = now + COOKIE_MAX_AGE;
  const payload = `${clientIP}:${expiry}`;
  const macBuf = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  const macHex = bufToHex(macBuf);
  const newToken = `${expiry}:${macHex}`;

  const cookieVal = encodeURIComponent(newToken);
  const cookieStr = `${TOKEN_COOKIE}=${cookieVal}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${COOKIE_MAX_AGE}`;

  // 可见的 challenge 页面：显示“正在验证”，并在 800ms 后自动刷新（让浏览器带上 Set-Cookie 重试）
  const body = `<!doctype html>
<html>
  <head>
    <meta name="check" content="${newToken}">
    <meta charset="utf-8"/>
    <title>Verifying...</title>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <style>
      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f7f7f8;color:#222}
      .card{padding:24px 28px;border-radius:10px;background:#fff;box-shadow:0 6px 20px rgba(0,0,0,0.08);text-align:center}
    </style>
  </head>
  <body>
    <div class="card">
      <h3>正在验证浏览器…</h3>
      <p>请稍候，验证成功后会自动继续。</p>
      <small>If this screen persists, enable JavaScript or contact the site owner.</small>
    </div>
    <script>
      // 等待浏览器接收 Set-Cookie（HttpOnly cookie 由响应头设置），然后重载页面以带上 cookie。
      // 800ms 是经验值，避免立刻重试导致 cookie 尚未生效。若你的环境需要可调整或用更复杂的 handshake。
      setTimeout(function(){ try { location.reload(); } catch(e) {} }, 800);
    </script>
    <noscript>
      <div style="position:fixed;left:0;right:0;bottom:8px;background:#fff;padding:8px;text-align:center;">
        JavaScript 被禁用 — 请启用后重试。
      </div>
    </noscript>
  </body>
</html>`;

  return new Response(body, {
    status: 403,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Set-Cookie': cookieStr
    }
  });
}

export default {
  async fetch(request) {
    try {
      const key = await getCachedKey();
      const clientIP = request.headers.get('CF-Connecting-IP') || '';
      const cookieHeader = request.headers.get('Cookie') || '';
      const token = getCookie(cookieHeader, TOKEN_COOKIE);

      // 若无 token 或格式不对 => challenge
      if (!token || token.indexOf(':') === -1) {
        return challengeResponse(clientIP, key);
      }

      // token = expiry:hexsig
      const [tsStr, sigHex] = token.split(':');
      const expiry = parseInt(tsStr, 10);
      if (isNaN(expiry)) return challengeResponse(clientIP, key);

      const now = Math.floor(Date.now() / 1000);
      if (now > expiry) return challengeResponse(clientIP, key); // 过期

      // 验证签名（使用 verify）
      const payload = `${clientIP}:${expiry}`;
      const sigBytes = hexToUint8Array(sigHex);
      let ok = false;
      try {
        ok = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(payload));
      } catch (e) {
        // 若 verify 抛错则视为不合法
        ok = false;
      }
      if (!ok) return challengeResponse(clientIP, key);

      // 通过验证，放行到 origin
      return fetch(request);
    } catch (err) {
      // 在生产可减少日志细节
      console.error('Worker error:', err && err.stack ? err.stack : err);
      return new Response('Error', { status: 500 });
    }
  }
};
