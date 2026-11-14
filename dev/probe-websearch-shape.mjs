// 直接打 DashScope 原生协议，看"联网确实执行了但 web_sources 为空"到底是哪一种：
//   A) usage.plugins.search 有、search_info.search_results 是空数组  → 上游这次没返回来源
//   B) search_results 有、但 rankWebSources 把 URL 过滤光了          → 我们的清洗逻辑在吃来源
// 今天 KEV 那道题 6/6 次出现 search_used=true + web_sources=[]，所以必须定性。
// 用法：NODE_USE_ENV_PROXY=1 NO_PROXY=dashscope.aliyuncs.com node dev/probe-websearch-shape.mjs ["问题"]
import { readFileSync } from "node:fs";

const env = Object.fromEntries(
  readFileSync(new URL("../data/.env", import.meta.url), "utf-8")
    .split(/\r?\n/)
    .filter((l) => /^[A-Z_]+=/.test(l))
    .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim()]),
);
const KEY = env.DASHSCOPE_API_KEY;
if (!KEY) { console.error("data/.env 里没有 DASHSCOPE_API_KEY"); process.exit(1); }

const q = process.argv[2] ?? "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";
const t0 = Date.now();
const r = await fetch(
  "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
  {
    method: "POST",
    headers: { Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "qwen-plus",
      input: { messages: [{ role: "system", content: "你是安全研究助手。" }, { role: "user", content: q }] },
      parameters: {
        result_format: "message", temperature: 0.5, max_tokens: 800,
        enable_search: true,
        search_options: { search_strategy: "max", forced_search: true, enable_source: true, enable_citation: true, citation_format: "[<number>]" },
      },
    }),
    signal: AbortSignal.timeout(60000),
  },
);
const d = await r.json().catch(() => null);
console.log(`HTTP ${r.status}  ${Date.now() - t0}ms`);
if (!d) { console.error("响应不是 JSON"); process.exit(1); }
console.log("code/message:", d.code ?? "-", d.message ?? "-");
console.log("usage.plugins:", JSON.stringify(d?.usage?.plugins ?? null));
const sr = d?.output?.search_info?.search_results;
console.log("search_info keys:", Object.keys(d?.output?.search_info ?? {}));
console.log("search_results 条数:", Array.isArray(sr) ? sr.length : typeof sr);
if (Array.isArray(sr)) {
  for (const w of sr.slice(0, 6)) {
    console.log(" -", JSON.stringify({ url: w?.url, site: w?.site_name, title: String(w?.title ?? "").slice(0, 40) }));
  }
}
console.log("回答前 200 字:", String(d?.output?.choices?.[0]?.message?.content ?? "").slice(0, 200));
