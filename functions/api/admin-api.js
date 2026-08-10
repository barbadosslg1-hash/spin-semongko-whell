import {
  requireAdmin,
  loadConfig,
  saveConfig,
  loadLogs,
  addAudit,
  clearLogs,
  json,
  DEFAULT_CONFIG
} from "../_lib.js";

export async function onRequestGet({ request, env }) {
  const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
  if (!session) return json({ error: "Unauthorized" }, 401);
  const config = await loadConfig(env.LUCKYWHEEL_KV);
  const logs = await loadLogs(env.LUCKYWHEEL_KV);
  return json({ config, logs });
}

export async function onRequestPost({ request, env }) {
  const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
  if (!session) return json({ error: "Unauthorized" }, 401);

  let body = {};
  try { body = await request.json(); } catch {}
  const { action } = body;

  if (action === "save") {
    const config = await saveConfig(env.LUCKYWHEEL_KV, body.config);
    await addAudit(env.LUCKYWHEEL_KV, { action: "save_config", username: session.username });
    return json({ ok: true, config });
  }

  if (action === "reset") {
    const config = structuredClone(DEFAULT_CONFIG);
    await saveConfig(env.LUCKYWHEEL_KV, config);
    await addAudit(env.LUCKYWHEEL_KV, { action: "reset_config", username: session.username });
    return json({ ok: true, config });
  }

  if (action === "clear_logs") {
    await clearLogs(env.LUCKYWHEEL_KV);
    await addAudit(env.LUCKYWHEEL_KV, { action: "clear_logs", username: session.username });
    return json({ ok: true });
  }

  return json({ error: "Aksi tidak dikenal." }, 400);
}
