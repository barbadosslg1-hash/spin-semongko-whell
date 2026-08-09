import { addAudit, createSessionCookie, clearSessionCookie, json, requireAdmin } from "./_lib.mjs";

export default async (req) => {
  if (req.method === "GET") {
    const session = requireAdmin(req);
    return json({ authenticated: Boolean(session), username: session?.username || null });
  }

  if (req.method === "POST") {
    let body = {};
    try { body = await req.json(); } catch {}
    const { action } = body;

    if (action === "login") {
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      const validUser = process.env.ADMIN_USERNAME || "";
      const validPass = process.env.ADMIN_PASSWORD || "";

      if (!validUser || !validPass) {
        return json({ error: "ADMIN_USERNAME/ADMIN_PASSWORD belum diset di Netlify Environment Variables." }, 500);
      }
      if (username !== validUser || password !== validPass) {
        await addAudit({ action: "login_failed", username });
        return json({ error: "Unauthorized" }, 401);
      }

      await addAudit({ action: "login", username });
      return json({ ok: true, username }, 200, { "set-cookie": createSessionCookie(username) });
    }

    if (action === "logout") {
      const session = requireAdmin(req);
      await addAudit({ action: "logout", username: session?.username || "unknown" });
      return json({ ok: true }, 200, { "set-cookie": clearSessionCookie() });
    }

    return json({ error: "Aksi tidak dikenal." }, 400);
  }

  return json({ error: "Method not allowed" }, 405);
};
