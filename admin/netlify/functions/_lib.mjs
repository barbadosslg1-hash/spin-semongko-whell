import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const STORE_NAME = "luckywheel";
const CONFIG_KEY = "config";
const LOG_KEY = "logs";
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
    showWelcome: true
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

export function store() {
  return getStore(STORE_NAME);
}

export async function loadConfig() {
  const s = store();
  const raw = await s.get(CONFIG_KEY, { type: "json" });
  if (!raw) {
    await s.setJSON(CONFIG_KEY, DEFAULT_CONFIG);
    return structuredClone(DEFAULT_CONFIG);
  }
  return raw;
}

export async function saveConfig(cfg) {
  const s = store();
  await s.setJSON(CONFIG_KEY, cfg);
  return cfg;
}

export async function loadLogs() {
  const s = store();
  const raw = await s.get(LOG_KEY, { type: "json" });
  return Array.isArray(raw) ? raw : [];
}

export async function addAudit(entry) {
  const s = store();
  const logs = await loadLogs();
  logs.unshift({ at: new Date().toISOString(), ...entry });
  const trimmed = logs.slice(0, 300);
  await s.setJSON(LOG_KEY, trimmed);
  return trimmed;
}

export async function clearLogs() {
  const s = store();
  await s.setJSON(LOG_KEY, []);
}

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders }
  });
}

function sign(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}

export function createSessionCookie(username) {
  const secret = process.env.ADMIN_SESSION_SECRET || "insecure-dev-secret";
  const expires = Date.now() + SESSION_TTL_MS;
  const payload = `${username}.${expires}`;
  const sig = sign(payload, secret);
  const value = Buffer.from(`${payload}.${sig}`).toString("base64url");
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
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = v;
  });
  return out;
}

export function requireAdmin(req) {
  const secret = process.env.ADMIN_SESSION_SECRET || "insecure-dev-secret";
  const cookies = parseCookies(req.headers.get("cookie") || "");
  const raw = cookies[SESSION_COOKIE];
  if (!raw) return null;
  let decoded;
  try {
    decoded = Buffer.from(raw, "base64url").toString("utf8");
  } catch {
    return null;
  }
  const parts = decoded.split(".");
  if (parts.length !== 3) return null;
  const [username, expiresStr, sig] = parts;
  const expected = sign(`${username}.${expiresStr}`, secret);
  if (sig !== expected) return null;
  if (Date.now() > Number(expiresStr)) return null;
  return { username };
}
