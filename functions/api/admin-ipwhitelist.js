import { requireAdmin, loadIpWhitelist, saveIpWhitelist, addAudit, getClientIp, json } from "../_lib.js";

// Whitelist IP untuk login panel — HANYA berlaku untuk akun admin/manager
// tambahan (KV), TIDAK berlaku untuk superadmin (env vars), supaya
// superadmin selalu punya jalan masuk untuk memperbaiki whitelist ini
// sendiri kalau ada salah konfigurasi atau IP berubah.
//
// Hanya owner (superadmin) atau akun dengan role "manager" yang boleh
// menambah/menghapus entri whitelist — sama seperti izin kelola akun admin.

function canManage(session) {
  return session.role === "owner" || session.role === "manager";
}

export async function onRequestGet({ request, env }) {
  const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
  if (!session) return json({ error: "Unauthorized" }, 401);

  const list = await loadIpWhitelist(env.LUCKYWHEEL_KV);
  return json({
    canManage: canManage(session),
    yourIp: getClientIp(request),
    whitelist: list
  });
}

export async function onRequestPost({ request, env }) {
  const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
  if (!session) return json({ error: "Unauthorized" }, 401);
  if (!canManage(session)) {
    return json({ error: "Akun kamu tidak punya izin mengelola Whitelist IP. Hanya owner/manager yang bisa." }, 403);
  }

  let body = {};
  try { body = await request.json(); } catch {}
  const { action } = body;

  if (action === "add") {
    const ip = String(body.ip || "").trim();
    const label = String(body.label || "").trim();
    if (!ip) return json({ error: "Alamat IP wajib diisi." }, 400);

    const list = await loadIpWhitelist(env.LUCKYWHEEL_KV);
    if (list.some(e => e.ip === ip)) {
      return json({ error: "IP tersebut sudah ada di whitelist." }, 409);
    }
    list.unshift({ ip, label, addedAt: new Date().toISOString(), addedBy: session.username });
    await saveIpWhitelist(env.LUCKYWHEEL_KV, list);
    await addAudit(env.LUCKYWHEEL_KV, { action: "ip_whitelist_added", username: session.username, target: ip });

    return json({ ok: true, whitelist: list });
  }

  if (action === "delete") {
    const ip = String(body.ip || "").trim();
    if (!ip) return json({ error: "Alamat IP wajib diisi." }, 400);

    const list = await loadIpWhitelist(env.LUCKYWHEEL_KV);
    const next = list.filter(e => e.ip !== ip);
    if (next.length === list.length) {
      return json({ error: "IP tidak ditemukan di whitelist." }, 404);
    }
    await saveIpWhitelist(env.LUCKYWHEEL_KV, next);
    await addAudit(env.LUCKYWHEEL_KV, { action: "ip_whitelist_removed", username: session.username, target: ip });

    return json({ ok: true, whitelist: next });
  }

  return json({ error: "Aksi tidak dikenal." }, 400);
}
