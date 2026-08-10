const KV_CONFIG_KEY = "config";
const KV_LOG_KEY = "logs";
const SESSION_COOKIE = "sw_admin";
const SESSION_TTL_MS = 1000 * 60 * 60 * 8; // 8 jam

export const DEFAULT_CONFIG = {
  site: {
    name: "RODA KEBERUNTUNGAN",
    title: "Lucky Wheel",
    subtitle: "Masukkan kode tiket untuk memulai putaran.",
    welcomeTitle: "Selamat Datang!",
    welcomeText: "Masukkan kode tiket Anda untuk memulai putaran.",
    logoUrl: "",
    backgroundUrl: "",
    primaryColor: "#e20a16",
    secondaryColor: "#ffd700",
    accentColor: "#ffd700",
    footerText: "",
    showWelcome: true,
    wheelLogoUrl: "",
    wheelHubColor: "#0a0a0a",
    faviconUrl: ""
  },
  wheel: {
    duration: 4,
    spins: 10,
    outerRadius: 185,
    innerRadius: 75,
    textFontSize: 18,
    segments: [
      { id: "p1", label: "COBA LAGI", color: "#e20a16", textColor: "#ffffff", weight: 5, enabled: true },
      { id: "p2", label: "HADIAH KECIL", color: "#ffd700", textColor: "#000000", weight: 3, enabled: true }
    ]
  },
  claim: {
    whatsapp: "",
    claimLabel: "Klaim Melalui WhatsApp",
    whatsappMessage: "Halo, saya menang {PRIZE} dengan kode {CODE}",
    instagram: "",
    facebook: "",
    twitter: ""
  },
  messages: {
    winTitle: "SELAMAT!",
    winText: "Anda memenangkan {PRIZE}!",
    lossText: "",
    invalidCode: "Kode tiket tidak valid.",
    expiredCode: "Kode tiket sudah digunakan atau kedaluwarsa.",
    systemError: "Terjadi kesalahan sistem, silakan coba lagi."
  },
  tickets: []
};

export async function loadConfig(kv) {
  const raw = await kv.get(KV_CONFIG_KEY, { type: "json" });
  if (!raw) {
    await kv.put(KV_CONFIG_KEY, JSON.stringify(DEFAULT_CONFIG));
    return structuredClone(DEFAULT_CONFIG);
  }
  return raw;
}

export async function saveConfig(kv, cfg) {
  await kv.put(KV_CONFIG_KEY, JSON.stringify(cfg));
  return cfg;
}

export async function loadLogs(kv) {
  const raw = await kv.get(KV_LOG_KEY, { type: "json" });
  return Array.isArray(raw) ? raw : [];
}

export async function addAudit(kv, entry) {
  const logs = await loadLogs(kv);
  logs.unshift({ at: new Date().toISOString(), ...entry });
  const trimmed = logs.slice(0, 300);
  await kv.put(KV_LOG_KEY, JSON.stringify(trimmed));
  return trimmed;
}

export async function clearLogs(kv) {
  await kv.put(KV_LOG_KEY, JSON.stringify([]));
}

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders }
  });
}

// Cloudflare Workers memakai Web Crypto API (bukan modul "crypto" Node.js
// seperti di Netlify Functions), jadi fungsi tanda-tangan sesi ditulis ulang.
async function hmacHex(value, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(value));
  return [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function createSessionCookie(username, secret) {
  const expires = Date.now() + SESSION_TTL_MS;
  const payload = `${username}.${expires}`;
  const sig = await hmacHex(payload, secret);
  const value = encodeURIComponent(`${payload}.${sig}`);
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(";").forEach(part => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  });
  return out;
}

export async function requireAdmin(request, secret) {
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const raw = cookies["sw_admin"];
  if (!raw) return null;
  let decoded;
  try { decoded = decodeURIComponent(raw); } catch { return null; }
  const parts = decoded.split(".");
  if (parts.length !== 3) return null;
  const [username, expiresStr, sig] = parts;
  const expected = await hmacHex(`${username}.${expiresStr}`, secret);
  if (sig !== expected) return null;
  if (Date.now() > Number(expiresStr)) return null;
  return { username };
}
