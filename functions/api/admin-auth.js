import { addAudit, createSessionCookie, clearSessionCookie, json, requireAdmin } from "../_lib.js";

export async function onRequestGet({ request, env }) {
  const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
  return json({ authenticated: Boolean(session), username: session?.username || null });
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
    if (username !== validUser || password !== validPass) {
      await addAudit(env.LUCKYWHEEL_KV, { action: "login_failed", username });
      return json({ error: "Unauthorized" }, 401);
    }

    await addAudit(env.LUCKYWHEEL_KV, { action: "login", username });
    return json(
      { ok: true, username },
      200,
      { "set-cookie": await createSessionCookie(username, env.ADMIN_SESSION_SECRET) }
    );
  }

  if (action === "logout") {
    const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
    await addAudit(env.LUCKYWHEEL_KV, { action: "logout", username: session?.username || "unknown" });
    return json({ ok: true }, 200, { "set-cookie": clearSessionCookie() });
  }

  return json({ error: "Aksi tidak dikenal." }, 400);
}
