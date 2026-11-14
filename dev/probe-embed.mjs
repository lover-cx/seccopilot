// 生成一段真实 embedding，落到 /tmp/embed.json，供 curl 走代理调 rpc/match_documents 用。
// 目的只有一个：确认线上 match_documents 返回的行里带 metadata（dropOffTacticDocs 的阶段过滤依赖它）。
import { readFileSync, writeFileSync } from "node:fs";

const t = readFileSync(new URL("../data/.env", import.meta.url), "utf8");
const g = (k) => (t.match(new RegExp("^" + k + "=(.*)$", "m")) || [])[1]?.trim();

const res = await fetch("https://dashscope.aliyuncs.com/compatible-mode/v1/embeddings", {
  method: "POST",
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${g("DASHSCOPE_API_KEY")}` },
  body: JSON.stringify({ model: "text-embedding-v3", input: "MITRE ATT&CK 初始访问阶段有哪些技术？", dimensions: 1024 }),
  signal: AbortSignal.timeout(30000),
});
const j = await res.json();
const vec = j?.data?.[0]?.embedding;
if (!Array.isArray(vec)) throw new Error(JSON.stringify(j).slice(0, 300));
writeFileSync(new URL("./embed.json", import.meta.url), JSON.stringify({
  query_embedding: vec, match_count: 6, category_filter: "attack", match_threshold: 0.0,
}));
console.log("embedding dims:", vec.length, "→ dev/embed.json");
