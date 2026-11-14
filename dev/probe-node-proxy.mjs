// 只读探针：确认 Node 24 在 NODE_USE_ENV_PROXY=1 下能否经 Clash 代理访问 Supabase。
// 目的： publication 卡在平台队列时，用本地 harness 跑当前代码的真实评测。
import { readFileSync } from "node:fs";

const env = Object.fromEntries(
  readFileSync(new URL("../data/.env", import.meta.url), "utf-8")
    .split(/\r?\n/)
    .filter((l) => /^[A-Z_]+=/.test(l))
    .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
);

const url = `${env.SUPABASE_URL}/rest/v1/knowledge_base?select=id,title&limit=1`;
try {
  const r = await fetch(url, { headers: { apikey: env.SUPABASE_KEY, Authorization: `Bearer ${env.SUPABASE_KEY}` } });
  console.log("status", r.status, (await r.text()).slice(0, 200));
} catch (e) {
  console.log("FAILED", e?.cause?.code ?? e?.message);
}
