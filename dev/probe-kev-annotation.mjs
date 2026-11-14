// 一次性核查：本地库里这几条 CVE 的正文到底带不带 KEV 标注（kevFacts 只认该前缀）。
// 用法：node dev/probe-kev-annotation.mjs
import fs from "node:fs";

const env = Object.fromEntries(
  fs.readFileSync(new URL("../data/.env", import.meta.url), "utf8")
    .split(/\r?\n/).filter((l) => /^\s*[A-Z]/.test(l))
    .map((l) => [l.split("=")[0].trim(), l.split("=").slice(1).join("=").trim()]),
);
const base = env.SUPABASE_URL, key = env.SUPABASE_KEY;

for (const id of ["CVE-2026-21509", "CVE-2026-124194", "CVE-2026-83542"]) {
  const url = `${base}/rest/v1/knowledge_base?select=title,category,source_url,content&or=(title.ilike.*${id}*,content.ilike.*${id}*)&limit=8`;
  const res = await fetch(url, { headers: { apikey: key, Authorization: `Bearer ${key}` } });
  const json = await res.json();
  console.log(`== ${id}  命中 ${Array.isArray(json) ? json.length : JSON.stringify(json)}`);
  for (const it of Array.isArray(json) ? json : []) {
    const has = /在野利用（CISA KEV）/.test(it.content ?? "");
    console.log(`   [${it.category}] ${String(it.title).slice(0, 55)} | KEV前缀=${has} | ${has ? String(it.content).match(/KEV 收录：[^｜\n]*/)?.[0] : ""}`);
  }
}
