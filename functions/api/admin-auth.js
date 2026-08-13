import { addAudit, createSessionCookie, clearSessionCookie, json, requireAdmin, loadAdmins, verifyPassword, isIpWhitelisted, getClientIp } from "../_lib.js";

export async function onRequestGet({ request, env }) {
  const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
  return json({ authenticated: Boolean(session), username: session?.username || null, role: session?.role || null });
}

export async function onRequestPost({ request, env }) {
  let body = {};
  try { body = await request.json(); } catch {}
  const { action } = body;

  if (action === "login") {
    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    const validUser = env.ADMIN_USERNAME || "";
    const validPass = env.ADMIN_PASSWORD || "";

    if (!validUser || !validPass) {
      return json({ error: "ADMIN_USERNAME/ADMIN_PASSWORD belum diset di Cloudflare Environment Variables." }, 500);
    }

    // 1) Superadmin bootstrap dari Cloudflare Environment Variables (akun lama).
    const isSuperadmin = username === validUser && password === validPass;

    // 2) Akun admin tambahan yang dibuat lewat panel, disimpan di KV dengan
    //    password sudah di-hash (PBKDF2) — tidak pernah disimpan plain text.
    let matchedAdmin = null;
    if (!isSuperadmin) {
      const admins = await loadAdmins(env.LUCKYWHEEL_KV);
      const found = admins.find(a => a.username === username);
      if (found && await verifyPassword(password, found.salt, found.hash)) {
        matchedAdmin = found;
      }
    }

    if (!isSuperadmin && !matchedAdmin) {
      await addAudit(env.LUCKYWHEEL_KV, { action: "login_failed", username });
      return json({ error: "Unauthorized" }, 401);
    }

    const role = isSuperadmin ? "owner" : (matchedAdmin.role || "admin");

    // Whitelist IP HANYA berlaku untuk akun tambahan (admin/manager), bukan
    // superadmin — supaya superadmin selalu punya jalan masuk untuk
    // memperbaiki whitelist kalau ada salah konfigurasi.
    if (role !== "owner") {
      const ip = getClientIp(request);
      const allowed = await isIpWhitelisted(env.LUCKYWHEEL_KV, ip);
      if (!allowed) {
        await addAudit(env.LUCKYWHEEL_KV, { action: "login_blocked_ip", username, ip });
        return json({ error: `Login ditolak: alamat IP kamu (${ip}) belum ada di Whitelist IP. Hubungi superadmin untuk menambahkannya.` }, 403);
      }
    }

    await addAudit(env.LUCKYWHEEL_KV, { action: "login", username });
    return json(
      { ok: true, username, role },
      200,
      { "set-cookie": await createSessionCookie(username, env.ADMIN_SESSION_SECRET, role) }
    );
  }

  if (action === "logout") {
    const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
    await addAudit(env.LUCKYWHEEL_KV, { action: "logout", username: session?.username || "unknown" });
    return json({ ok: true }, 200, { "set-cookie": clearSessionCookie() });
  }

  return json({ error: "Aksi tidak dikenal." }, 400);
}
