// 冒烟测试：本地 harness 的一问一答，确认三道闸门在真实检索+真实模型下确实生效。
// 用法：node dev/probe-local-chat.mjs "<问题>" [mode]   （可用 SITE=http://127.0.0.1:8000 覆盖目标）
const [question, mode = "on"] = process.argv.slice(2);
const r = await fetch(`${process.env.SITE ?? "http://127.0.0.1:8000/functions/v1/app"}?action=chat`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ question, mode }),
});
const d = await r.json();
console.log("status", r.status, "mode", d.mode, "search_used", d.search_used, "coverage", d.coverage);
console.log("--- answer ---");
console.log(String(d.answer ?? d.error ?? JSON.stringify(d)));
console.log("--- local sources ---");
(d.sources ?? []).forEach((s) => console.log(`· ${s.title} | ${s.source_url ?? s.url ?? ""}`));
console.log("--- web sources ---");
(d.web_sources ?? []).forEach((s) => console.log(`· ${s.title ?? ""} | ${s.url ?? s.source_url ?? ""}`));
