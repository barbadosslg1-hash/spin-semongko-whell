import { loadConfig, json } from "../_lib.js";

export async function onRequestGet({ env }) {
  const config = await loadConfig(env.LUCKYWHEEL_KV);
  const publicConfig = {
    site: config.site,
    wheel: {
      duration: config.wheel.duration,
      spins: config.wheel.spins,
      outerRadius: config.wheel.outerRadius,
      innerRadius: config.wheel.innerRadius,
      textFontSize: config.wheel.textFontSize,
      segments: config.wheel.segments.filter(s => s.enabled !== false)
    },
    claim: config.claim,
    messages: config.messages
  };
  return json(publicConfig);
}
