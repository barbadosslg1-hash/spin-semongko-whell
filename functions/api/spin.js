import { loadConfig, saveConfig, addAudit, json } from "../_lib.js";

function pickWeighted(segments) {
  const active = segments.filter(s => s.enabled !== false && Number(s.weight) > 0);
  const total = active.reduce((sum, s) => sum + Number(s.weight), 0);
  if (total <= 0) return active[0] || null;
  let r = Math.random() * total;
  for (const s of active) {
    r -= Number(s.weight);
    if (r <= 0) return s;
  }
  return active[active.length - 1];
}

// Calls the TicketLock Durable Object to atomically claim a ticket code.
// Returns true if this request is the one that gets to proceed (first claim),
// false if the ticket was already claimed by another request.
// If the binding is missing for any reason, falls back to "allow" so the
// old KV-only check still runs instead of hard-failing the whole endpoint.
async function claimTicketLock(env, code) {
  if (!env.TICKET_LOCK) return true; // graceful fallback if binding absent
  try {
    const id = env.TICKET_LOCK.idFromName(code);
    const stub = env.TICKET_LOCK.get(id);
    const res = await stub.fetch("https://ticket-lock/claim", { method: "POST" });
    const data = await res.json();
    return data.ok === true;
  } catch (err) {
    // If the DO call itself fails, fail open to the old KV-only logic
    // rather than blocking every spin due to an infra hiccup.
    return true;
  }
}

export async function onRequestPost({ request, env }) {
  let body = {};
  try { body = await request.json(); } catch {}
  const code = String(body.code || "").trim().toUpperCase();
  if (!code) return json({ error: "Kode tiket wajib diisi." }, 400);

  // Atomic claim FIRST, before touching KV at all. This is the fix for the
  // double-spin bug: only one concurrent request can ever get ok:true back
  // from the Durable Object for a given ticket code.
  const claimed = await claimTicketLock(env, code);
  if (!claimed) {
    await addAudit(env.LUCKYWHEEL_KV, { action: "spin_locked", code });
    const config = await loadConfig(env.LUCKYWHEEL_KV);
    return json({ error: config.messages?.expiredCode || "Kode tiket sudah digunakan." }, 409);
  }

  const config = await loadConfig(env.LUCKYWHEEL_KV);
  const ticket = (config.tickets || []).find(t => t.code === code);
  if (!ticket) {
    await addAudit(env.LUCKYWHEEL_KV, { action: "spin_invalid", code });
    return json({ error: config.messages?.invalidCode || "Kode tiket tidak valid." }, 404);
  }
  if (ticket.status !== "active") {
    await addAudit(env.LUCKYWHEEL_KV, { action: "spin_expired", code });
    return json({ error: config.messages?.expiredCode || "Kode tiket sudah digunakan." }, 409);
  }

  let prize = null;
  if (ticket.prizeId) {
    prize = config.wheel.segments.find(s => s.id === ticket.prizeId) || null;
  }
  if (!prize) prize = pickWeighted(config.wheel.segments);
  if (!prize) return json({ error: config.messages?.systemError || "Tidak ada hadiah aktif." }, 500);

  ticket.status = "used";
  ticket.usedAt = new Date().toISOString();
  ticket.winner = { id: prize.id, label: prize.label };
  await saveConfig(env.LUCKYWHEEL_KV, config);
  await addAudit(env.LUCKYWHEEL_KV, { action: "spin", code, prizeId: prize.id });

  return json({ code, prize: { id: prize.id, label: prize.label } });
}
