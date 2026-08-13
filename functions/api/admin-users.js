import { requireAdmin, loadAdmins, saveAdmins, hashPassword, addAudit, json } from "../_lib.js";

// Endpoint untuk mengelola akun admin panel TAMBAHAN (di luar superadmin dari
// Cloudflare Environment Variables ADMIN_USERNAME/PASSWORD).
//
// Role yang dikenal:
// - "owner"   : superadmin dari env vars, implisit, tidak pernah disimpan di KV
// - "manager" : akun tambahan yang JUGA boleh menambah/menghapus akun admin lain
// - "admin"   : akun tambahan biasa — bisa kelola website/tiket/dsb tapi TIDAK
//               boleh menambah/menghapus akun admin lain
//
// Akun lama (dibuat sebelum fitur role ini ada) tidak punya field `role` di
// KV — diperlakukan sebagai "admin" (terbatas) secara default, bukan
// "manager", supaya defaultnya aman (least privilege) kalau data lama tidak
// eksplisit menyatakan wewenang lebih tinggi.

function canManageAdmins(session) {
  return session.role === "owner" || session.role === "manager";
}

export async function onRequestGet({ request, env }) {
  const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
  if (!session) return json({ error: "Unauthorized" }, 401);

  const admins = await loadAdmins(env.LUCKYWHEEL_KV);
  return json({
    superadminUsername: env.ADMIN_USERNAME || "",
    currentRole: session.role || "admin",
    canManage: canManageAdmins(session),
    admins: admins.map(a => ({
      username: a.username,
      role: a.role || "admin",
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
    if (!canManageAdmins(session)) {
      return json({ error: "Akun kamu tidak punya izin untuk menambah admin. Hanya owner/manager yang bisa." }, 403);
    }

    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    const role = body.role === "manager" ? "manager" : "admin";

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
      role,
      createdAt: new Date().toISOString(),
      createdBy: session.username
    });
    await saveAdmins(env.LUCKYWHEEL_KV, admins);
    await addAudit(env.LUCKYWHEEL_KV, { action: "admin_added", username: session.username, target: username, role });

    return json({
      ok: true,
      admins: admins.map(a => ({ username: a.username, role: a.role || "admin", createdAt: a.createdAt, createdBy: a.createdBy || "" }))
    });
  }

  if (action === "delete") {
    if (!canManageAdmins(session)) {
      return json({ error: "Akun kamu tidak punya izin untuk menghapus admin. Hanya owner/manager yang bisa." }, 403);
    }

    const username = String(body.username || "").trim();
    if (!username) return json({ error: "Username wajib diisi." }, 400);
    if (username === session.username) {
      return json({ error: "Tidak bisa menghapus akun kamu sendiri yang sedang login." }, 400);
    }

    const admins = await loadAdmins(env.LUCKYWHEEL_KV);
    const next = admins.filter(a => a.username !== username);
    if (next.length === admins.length) {
      return json({ error: "Akun admin tidak ditemukan." }, 404);
    }

    await saveAdmins(env.LUCKYWHEEL_KV, next);
    await addAudit(env.LUCKYWHEEL_KV, { action: "admin_deleted", username: session.username, target: username });

    return json({
      ok: true,
      admins: next.map(a => ({ username: a.username, role: a.role || "admin", createdAt: a.createdAt, createdBy: a.createdBy || "" }))
    });
  }

  if (action === "set_role") {
    if (!canManageAdmins(session)) {
      return json({ error: "Akun kamu tidak punya izin untuk mengubah role admin. Hanya owner/manager yang bisa." }, 403);
    }
    const username = String(body.username || "").trim();
    const role = body.role === "manager" ? "manager" : "admin";
    if (!username) return json({ error: "Username wajib diisi." }, 400);

    const admins = await loadAdmins(env.LUCKYWHEEL_KV);
    const target = admins.find(a => a.username === username);
    if (!target) return json({ error: "Akun admin tidak ditemukan." }, 404);

    target.role = role;
    await saveAdmins(env.LUCKYWHEEL_KV, admins);
    await addAudit(env.LUCKYWHEEL_KV, { action: "admin_role_changed", username: session.username, target: username, role });

    return json({
      ok: true,
      admins: admins.map(a => ({ username: a.username, role: a.role || "admin", createdAt: a.createdAt, createdBy: a.createdBy || "" }))
    });
  }

  return json({ error: "Aksi tidak dikenal." }, 400);
}
