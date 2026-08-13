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

// Dipakai bareng oleh action "save" dan "import" — membandingkan tiket lama
// vs baru supaya penambahan/penghapusan tiket tercatat rinci di Audit Log
// (bukan cuma satu baris generik), lalu menyimpan config-nya.
async function saveConfigWithTicketDiff(kv, oldConfig, newConfig, username) {
  const oldTickets = oldConfig.tickets || [];
  const newTickets = newConfig?.tickets || [];

  const oldIds = new Set(oldTickets.map(t => t.id ?? t.code));
  const newIds = new Set(newTickets.map(t => t.id ?? t.code));

  const addedTickets = newTickets.filter(t => !oldIds.has(t.id ?? t.code));
  const removedTickets = oldTickets.filter(t => !newIds.has(t.id ?? t.code));

  const config = await saveConfig(kv, newConfig);

  for (const t of addedTickets) {
    await addAudit(kv, {
      action: "ticket_created",
      username,
      code: t.code,
      prizeId: t.prizeId || undefined
    });
  }
  for (const t of removedTickets) {
    await addAudit(kv, { action: "ticket_deleted", username, code: t.code });
  }

  const onlyTicketsChanged =
    (addedTickets.length > 0 || removedTickets.length > 0) &&
    JSON.stringify({ ...oldConfig, tickets: [] }) === JSON.stringify({ ...newConfig, tickets: [] });

  return { config, onlyTicketsChanged };
}

export async function onRequestPost({ request, env }) {
  const session = await requireAdmin(request, env.ADMIN_SESSION_SECRET);
  if (!session) return json({ error: "Unauthorized" }, 401);

  let body = {};
  try { body = await request.json(); } catch {}
  const { action } = body;

  if (action === "save") {
    const oldConfig = await loadConfig(env.LUCKYWHEEL_KV);
    const { config, onlyTicketsChanged } = await saveConfigWithTicketDiff(
      env.LUCKYWHEEL_KV, oldConfig, body.config, session.username
    );
    // Log generik hanya kalau bukan murni perubahan tiket, biar audit log
    // tidak dobel-catat aksi yang sama (create/delete tiket sudah tercatat
    // rinci di atas).
    if (!onlyTicketsChanged) {
      await addAudit(env.LUCKYWHEEL_KV, { action: "save_config", username: session.username });
    }
    return json({ ok: true, config });
  }

  if (action === "import") {
    if (!body.config || typeof body.config !== "object") {
      return json({ error: "File backup tidak valid." }, 400);
    }
    const oldConfig = await loadConfig(env.LUCKYWHEEL_KV);
    const { config } = await saveConfigWithTicketDiff(
      env.LUCKYWHEEL_KV, oldConfig, body.config, session.username
    );
    await addAudit(env.LUCKYWHEEL_KV, { action: "config_imported", username: session.username });
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
