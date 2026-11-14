// 临时探针：本地库 attack 条目的 metadata 里有没有 tactic（决定能否在 Function 侧做阶段过滤）
import { readFileSync } from "node:fs";

const t = readFileSync(new URL("../data/.env", import.meta.url), "utf8");
const g = (k) => (t.match(new RegExp("^" + k + "=(.*)$", "m")) || [])[1]?.trim();
const url = g("SUPABASE_URL");
const key = g("SUPABASE_KEY");

const q = `${url}/rest/v1/knowledge_base?select=id,title,metadata&category=eq.attack&limit=3`;
const r = await fetch(q, { headers: { apikey: key, Authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(15000) });
console.log("status", r.status);
console.log((await r.text()).slice(0, 600));
