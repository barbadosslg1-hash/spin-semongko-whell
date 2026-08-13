import { requireAdmin, loadAdmins, saveAdmins, hashPassword, addAudit, json } from "../_lib.js";

// Endpoint terpisah untuk mengelola akun admin panel TAMBAHAN (di luar
// superadmin dari Cloudflare Environment Variables ADMIN_USERNAME/PASSWORD).
// Siapapun yang sedang login sebagai admin bisa menambah/menghapus akun lain
// dari sini — sama seperti kepercayaan yang sudah dipakai di fitur lain
// (Kode Tiket, Daftar Hadiah, dst).

export async function onRequestGet({ request, env }) {
  const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
  if (!session) return json({ error: "Unauthorized" }, 401);

  const admins = await loadAdmins(env.LUCKYWHEEL_KV);
  return json({
    superadminUsername: env.ADMIN_USERNAME || "",
    admins: admins.map(a => ({
      username: a.username,
      createdAt: a.createdAt,
      createdBy: a.createdBy || ""
    }))
  });
}

export async function onRequestPost({ request, env }) {
  const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
  if (!session) return json({ error: "Unauthorized" }, 401);

  let body = {};
  try { body = await request.json(); } catch {}
  const { action } = body;

  if (action === "add") {
    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if (!username || !password) {
      return json({ error: "Username dan password wajib diisi." }, 400);
    }
    if (password.length < 6) {
      return json({ error: "Password minimal 6 karakter." }, 400);
    }
    if (username === (env.ADMIN_USERNAME || "")) {
      return json({ error: "Username tersebut sudah dipakai oleh superadmin." }, 409);
    }

    const admins = await loadAdmins(env.LUCKYWHEEL_KV);
    if (admins.some(a => a.username.toLowerCase() === username.toLowerCase())) {
      return json({ error: "Username sudah dipakai." }, 409);
    }

    const { hash, salt } = await hashPassword(password);
    admins.unshift({
      username,
      hash,
      salt,
      createdAt: new Date().toISOString(),
      createdBy: session.username
    });
    await saveAdmins(env.LUCKYWHEEL_KV, admins);
    await addAudit(env.LUCKYWHEEL_KV, { action: "admin_added", username: session.username, target: username });

    return json({
      ok: true,
      admins: admins.map(a => ({ username: a.username, createdAt: a.createdAt, createdBy: a.createdBy || "" }))
    });
  }

  if (action === "delete") {
    const username = String(body.username || "").trim();
    if (!username) return json({ error: "Username wajib diisi." }, 400);

    const admins = await loadAdmins(env.LUCKYWHEEL_KV);
    const next = admins.filter(a => a.username !== username);
    if (next.length === admins.length) {
      return json({ error: "Akun admin tidak ditemukan." }, 404);
    }

    await saveAdmins(env.LUCKYWHEEL_KV, next);
    await addAudit(env.LUCKYWHEEL_KV, { action: "admin_deleted", username: session.username, target: username });

    return json({
      ok: true,
      admins: next.map(a => ({ username: a.username, createdAt: a.createdAt, createdBy: a.createdBy || "" }))
    });
  }

  return json({ error: "Aksi tidak dikenal." }, 400);
}
