// 临时探针：确认线上 match_documents 真的把 metadata 带回来（阶段过滤靠 metadata.tactics）。
// 直接调 RPC 与 Function 里用的是同一个入口，因此这一步过了，dropOffTacticDocs 才有牙。
import { readFileSync } from "node:fs";

const t = readFileSync(new URL("../data/.env", import.meta.url), "utf8");
const g = (k) => (t.match(new RegExp("^" + k + "=(.*)$", "m")) || [])[1]?.trim();
const url = g("SUPABASE_URL");
const key = g("SUPABASE_KEY");

const body = { query_embedding: null, match_count: 2, category_filter: "attack", match_threshold: 0.0 };
const r = await fetch(`${url}/rest/v1/rpc/match_documents`, {
  method: "POST",
  headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json", Prefer: "return=representation" },
  body: JSON.stringify(body),
  signal: AbortSignal.timeout(20000),
});
console.log("status", r.status);
const txt = await r.text();
console.log(txt.slice(0, 700));
