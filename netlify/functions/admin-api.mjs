import {
  requireAdmin,
  loadConfig,
  saveConfig,
  loadLogs,
  addAudit,
  clearLogs,
  json,
  DEFAULT_CONFIG
} from "./_lib.mjs";

export default async (req) => {
  const session = requireAdmin(req);
  if (!session) return json({ error: "Unauthorized" }, 401);

  if (req.method === "GET") {
    const config = await loadConfig();
    const logs = await loadLogs();
    return json({ config, logs });
  }

  if (req.method === "POST") {
    let body = {};
    try { body = await req.json(); } catch {}
    const { action } = body;

    if (action === "save") {
      const config = await saveConfig(body.config);
      await addAudit({ action: "save_config", username: session.username });
      return json({ ok: true, config });
    }

    if (action === "reset") {
      const config = structuredClone(DEFAULT_CONFIG);
      await saveConfig(config);
      await addAudit({ action: "reset_config", username: session.username });
      return json({ ok: true, config });
    }

    if (action === "clear_logs") {
      await clearLogs();
      await addAudit({ action: "clear_logs", username: session.username });
      return json({ ok: true });
    }

    return json({ error: "Aksi tidak dikenal." }, 400);
  }

  return json({ error: "Method not allowed" }, 405);
};
