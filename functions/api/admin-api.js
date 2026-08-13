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
    const oldConfig = await loadConfig(env.LUCKYWHEEL_KV);
    const oldTickets = oldConfig.tickets || [];
    const newTickets = body.config?.tickets || [];

    const oldIds = new Set(oldTickets.map(t => t.id ?? t.code));
    const newIds = new Set(newTickets.map(t => t.id ?? t.code));

    const addedTickets = newTickets.filter(t => !oldIds.has(t.id ?? t.code));
    const removedTickets = oldTickets.filter(t => !newIds.has(t.id ?? t.code));

    const config = await saveConfig(env.LUCKYWHEEL_KV, body.config);

    for (const t of addedTickets) {
      await addAudit(env.LUCKYWHEEL_KV, {
        action: "ticket_created",
        username: session.username,
        code: t.code,
        prizeId: t.prizeId || undefined
      });
    }
    for (const t of removedTickets) {
      await addAudit(env.LUCKYWHEEL_KV, { action: "ticket_deleted", username: session.username, code: t.code });
    }
    // Log generik hanya kalau bukan murni perubahan tiket, biar audit log
    // tidak dobel-catat aksi yang sama (create/delete tiket sudah tercatat
    // rinci di atas).
    const onlyTicketsChanged =
      (addedTickets.length > 0 || removedTickets.length > 0) &&
      JSON.stringify({ ...oldConfig, tickets: [] }) === JSON.stringify({ ...body.config, tickets: [] });
    if (!onlyTicketsChanged) {
      await addAudit(env.LUCKYWHEEL_KV, { action: "save_config", username: session.username });
    }

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
