// 缺陷 7 的机制核查：这道题的本地资料集合是什么、kevFacts 对它们生成了什么、
// 以及"库里到底有没有 124194 / 83542"。
// 用法：NODE_USE_ENV_PROXY=1 HTTP_PROXY=http://127.0.0.1:7897 HTTPS_PROXY=http://127.0.0.1:7897 \
//        NO_PROXY=dashscope.aliyuncs.com node dev/probe-kevgate.mjs
import fs from "node:fs";

const env = Object.fromEntries(
  fs.readFileSync(new URL("../data/.env", import.meta.url), "utf8")
    .split(/\r?\n/).filter((l) => /^\s*[A-Z]/.test(l))
    .map((l) => [l.split("=")[0].trim(), l.split("=").slice(1).join("=").trim()]),
);
const { embed } = await import("../functions/lib/dashscope.ts");
const { vector } = await import("../functions/lib/kb.ts");
const { kevFacts } = await import("../functions/lib/chat.ts");

const b = { url: env.SUPABASE_URL, h: { apikey: env.SUPABASE_KEY, Authorization: `Bearer ${env.SUPABASE_KEY}`, "Content-Type": "application/json" } };
const q = "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";

// 连问三次，看检索集合是否真的会波动
for (let i = 1; i <= 3; i++) {
  const emb = await embed(env.DASHSCOPE_API_KEY, q);
  const docs = await vector(b, emb, null, 5);
  const mark = docs.filter((d) => /在野利用（CISA KEV）/.test(String(d.content))).length;
  console.log(`第 ${i} 次：拿到 ${docs.length} 条，其中带 KEV 前缀 ${mark} 条 ->`,
    docs.map((d) => String(d.title).match(/CVE-\d{4}-\d{4,7}/i)?.[0]).join(","));
  console.log("   kevFacts:", (kevFacts(q, docs).match(/标注的编号：[^。]*。/) ?? ["（无 KEV 标注）"])[0]);
}

for (const id of ["CVE-2026-124194", "CVE-2026-83542"]) {
  const res = await fetch(`${b.url}/rest/v1/knowledge_base?select=title&or=(title.ilike.*${id}*,content.ilike.*${id}*)&limit=3`,
    { headers: b.h });
  const json = await res.json();
  console.log(`库里是否有 ${id}:`, Array.isArray(json) ? `${json.length} 行` : JSON.stringify(json));
}
