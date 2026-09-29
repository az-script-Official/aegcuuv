// ============================================
// FlowAuth Shield v3.0 - Strong Protected Loader
// Multi-layer bot & browser detection
// ============================================

const CONFIG = {
  blockedStatus: 403,
  blockMessage: "Script source protected. Use Roblox executor only.",
  allowedContentType: "text/plain; charset=utf-8",
  maxFetchSize: 524288,
};

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      return new Response("-- FlowAuth: Internal error", {
        status: 500,
        headers: { "Content-Type": CONFIG.allowedContentType },
      });
    }
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/" || path === "") {
    return new Response("FlowAuth Shield v3.0 - Active", {
      status: 200,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  if (!path.startsWith("/l/")) {
    return new Response("Not found", { status: 404 });
  }

  const rawId = path.slice(3).replace(/\.lua$/i, "").trim();
  if (!rawId || rawId.length < 10) {
    return new Response("-- Invalid loader ID", {
      status: 400,
      headers: { "Content-Type": CONFIG.allowedContentType },
    });
  }

  const score = getTrustScore(request);

  if (score < 40) {
    return blockResponse();
  }

  let targetUrl = "";
  try {
    targetUrl = decodeTargetUrl(rawId);
  } catch (e) {
    return new Response("-- Invalid encoding", {
      status: 400,
      headers: { "Content-Type": CONFIG.allowedContentType },
    });
  }

  if (!isValidUrl(targetUrl)) {
    return new Response("-- Invalid target", {
      status: 400,
      headers: { "Content-Type": CONFIG.allowedContentType },
    });
  }

  if (env && env.LOADERS_KV) {
    try {
      const stored = await env.LOADERS_KV.get(rawId);
      if (stored) {
        const data = JSON.parse(stored);
        if (data.targetUrl) targetUrl = data.targetUrl;
      }
    } catch (e) {}
  }

  let src = "";
  try {
    const resp = await fetch(targetUrl, {
      headers: { "User-Agent": "FlowAuth-Proxy/3.0" },
      cf: { cacheTtl: 30, cacheEverything: true },
    });
    if (resp.ok) {
      const text = await resp.text();
      src = text.length > CONFIG.maxFetchSize ? text.slice(0, CONFIG.maxFetchSize) : text;
    } else {
      src = '-- FlowAuth: Fetch failed (' + resp.status + ')';
    }
  } catch (e) {
    src = "-- FlowAuth: Network error";
  }

  const lua = buildProtectedLoader(src);

  return new Response(lua, {
    status: 200,
    headers: {
      "Content-Type": CONFIG.allowedContentType,
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "X-Content-Type-Options": "nosniff",
      "X-FlowAuth": "v3.0",
    },
  });
}

function getTrustScore(request) {
  const headers = request.headers;
  const ua = (headers.get("user-agent") || "").toLowerCase();
  const accept = (headers.get("accept") || "").toLowerCase();
  const secFetch = (headers.get("sec-fetch-mode") || "").toLowerCase();
  const secDest = (headers.get("sec-fetch-dest") || "").toLowerCase();
  const purpose = (headers.get("purpose") || headers.get("x-purpose") || "").toLowerCase();
  const method = request.method.toUpperCase();

  let score = 0;

  const executorSigns = [
    "roblox", "delta", "hydrogen", "codex", "arceus",
    "fluxus", "solara", "wave", "vegax", "cryptic",
    "libcurl", "wininet", "httpservice", "evon", "krnl",
    "swift", "trigon", "valyse", "sirhurt", "synapse",
  ];
  for (let i = 0; i < executorSigns.length; i++) {
    if (ua.indexOf(executorSigns[i]) !== -1) {
      score += 60;
      break;
    }
  }

  if (ua.indexOf("mozilla") !== -1) score -= 30;
  if (ua.indexOf("chrome") !== -1) score -= 10;
  if (ua.indexOf("firefox") !== -1) score -= 10;
  if (ua.indexOf("safari") !== -1) score -= 10;
  if (ua.indexOf("edge") !== -1) score -= 10;

  if (accept.indexOf("text/html") !== -1) score -= 25;
  if (accept.indexOf("*/*") !== -1) score += 15;
  if (accept.indexOf("text/plain") !== -1) score += 20;

  if (secFetch === "navigate") score -= 30;
  if (secDest === "document") score -= 30;
  if (secFetch === "no-cors" && secDest === "empty") score += 15;

  if (purpose === "prefetch" || purpose === "preview") score -= 20;

  if (method !== "GET") score -= 40;

  if (!ua || ua.length < 3) score -= 20;

  return score;
}

function blockResponse() {
  const html = '<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>403 - FlowAuth Shield</title><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#030712;color:#f3f4f6;font-family:system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;overflow:hidden}.bg{position:absolute;inset:0;background-image:radial-gradient(rgba(14,165,233,0.08) 1px,transparent 1px);background-size:24px 24px;z-index:0}.card{position:relative;z-index:10;background:#0f172a;border:1px solid #1e293b;border-radius:20px;padding:40px 32px;max-width:520px;width:100%;text-align:center;box-shadow:0 25px 50px -12px rgba(0,0,0,0.7),0 0 40px rgba(14,165,233,0.1)}.icon{width:72px;height:72px;background:rgba(244,63,94,0.1);border:1px solid rgba(244,63,94,0.3);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;color:#f43f5e;font-size:32px}h1{font-size:22px;font-weight:700;color:#fff;margin-bottom:12px}p{color:#94a3b8;font-size:14px;line-height:1.6;margin-bottom:20px}.alert{background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);border-radius:12px;padding:14px;color:#fca5a5;font-size:13px;text-align:right;line-height:1.5}.tag{margin-top:20px;font-size:11px;color:#475569;font-family:monospace}</style></head><body><div class="bg"></div><div class="card"><div class="icon">&#128274;</div><h1>403 - Source Protected</h1><p>This script is protected by <strong>FlowAuth Shield v3.0</strong>. Direct browser access is blocked.</p><div class="alert"><strong>To run this script:</strong><br>Use <code>game:HttpGet</code> inside a Roblox executor (Delta, Solara, Codex, Hydrogen...)</div><div class="tag">FlowAuth Shield v3.0 &middot; Multi-Layer Protection</div></div></body></html>';
  return new Response(html, {
    status: 403,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "X-Robots-Tag": "noindex, nofollow",
      "Cache-Control": "no-store",
    },
  });
}

function decodeTargetUrl(id) {
  let fixed = id.replace(/-/g, "+").replace(/_/g, "/");
  while (fixed.length % 4) fixed += "=";
  const binary = atob(fixed);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder("utf-8").decode(bytes);
}

function isValidUrl(url) {
  if (typeof url !== "string" || url.length < 10) return false;
  if (url.indexOf("http://") !== 0 && url.indexOf("https://") !== 0) return false;
  if (url.length > 2048) return false;
  try {
    const parsed = new URL(url);
    if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") return false;
    return true;
  } catch (e) {
    return false;
  }
}

function buildProtectedLoader(source) {
  const bytes = new TextEncoder().encode(source);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  const b64 = btoa(binary);
  const key = Math.floor(Math.random() * 200) + 50;
  const keyHex = key.toString(16);
  const xoredB64 = xorBase64(b64, key);

  const lines = [];
  lines.push("--[[ FlowAuth Shield v3.0 - Protected Loader ]]--");
  lines.push("-- Unauthorized decompilation is prohibited");
  lines.push("local _k = 0x" + keyHex);
  lines.push("local _d = [==[" + xoredB64 + "]==]");
  lines.push("local _b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'");
  lines.push("local function _xor(s, k)");
  lines.push("  local r = {}");
  lines.push("  for i = 1, #s do");
  lines.push("    r[i] = string.char(bit32.bxor(string.byte(s, i), k % 256))");
  lines.push("  end");
  lines.push("  return table.concat(r)");
  lines.push("end");
  lines.push("local function _dec(d)");
  lines.push("  d = string.gsub(d, '[^' .. _b .. '=]', '')");
  lines.push("  return (d:gsub('.', function(x)");
  lines.push("    if x == '=' then return '' end");
  lines.push("    local r, f = '', (b_find(_b, x) or 1) - 1");
  lines.push("    for i = 6, 1, -1 do");
  lines.push("      r = r .. (f % 2^i - f % 2^(i-1) >= 1 and '1' or '0')");
  lines.push("    end");
  lines.push("    return r");
  lines.push("  end):gsub('%d%d%d%d%d%d%d%d', function(x)");
  lines.push("    if #x ~= 8 then return '' end");
  lines.push("    local c = 0");
  lines.push("    for i = 1, 8 do");
  lines.push("      c = c + (x:sub(i, i) == '1' and 2^(8 - i) or 0)");
  lines.push("    end");
  lines.push("    return string.char(c)");
  lines.push("  end))");
  lines.push("end");
  lines.push("local b_find = string.find");
  lines.push("local function _run()");
  lines.push("  local raw = _xor(_d, _k)");
  lines.push("  local src = _dec(raw)");
  lines.push("  local fn = loadstring or load");
  lines.push("  if not fn then");
  lines.push("    warn('[FlowAuth] loadstring not available')");
  lines.push("    return");
  lines.push("  end");
  lines.push("  local compiled, err = fn(src)");
  lines.push("  if compiled then");
  lines.push("    local ok, runErr = pcall(compiled)");
  lines.push("    if not ok then");
  lines.push("      warn('[FlowAuth] Runtime: ' .. tostring(runErr))");
  lines.push("    end");
  lines.push("  else");
  lines.push("    warn('[FlowAuth] Compile: ' .. tostring(err))");
  lines.push("  end");
  lines.push("end");
  lines.push("_run()");

  return lines.join("\n");
}

function xorBase64(b64, key) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  let result = "";
  for (let i = 0; i < b64.length; i++) {
    const c = b64.charCodeAt(i);
    const x = c ^ (key % 256);
    result += String.fromCharCode(x >= 32 && x < 127 ? x : c);
  }
  let safe = "";
  for (let i = 0; i < result.length; i++) {
    const code = result.charCodeAt(i);
    if (code >= 32 && code < 127) {
      safe += String.fromCharCode(code);
    } else {
      safe += chars[code % chars.length];
    }
  }
  return safe;
}
