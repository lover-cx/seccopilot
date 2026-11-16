// Task 4 接线诊断：绕开 HTTP，直接用 runChat 打本机，看 Step 4 的目录注入与 Step 5 的硬校验
// 到底哪一支没生效。用法见文件末尾。诊断专用，不入库（dev/*.mjs 允许，产物 .log/.json 不进提交包）。
import fs from "node:fs";

function readDotEnv(file) {
  const out = {};
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
  return out;
}
const dot = readDotEnv(new URL("../data/.env", import.meta.url).pathname.replace(/^\/(\w:)/, "$1"));
const b = {
  url: dot.SUPABASE_URL,
  h: { apikey: dot.SUPABASE_KEY, Authorization: `Bearer ${dot.SUPABASE_KEY}`, "Content-Type": "application/json" },
};

const { runChat } = await import("../functions/lib/chat.ts");
const { kevCatalog, kevScopeMatches } = await import("../functions/lib/kb.ts");

const q = process.argv[2] ?? "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";
const mode = process.argv[3] ?? "off";

const map0 = await kevCatalog();
console.log(`[前置] kevCatalog() -> ${map0 ? map0.size + " 条" : "null（拉不到）"}`);
if (map0) {
  const r = kevScopeMatches(q, map0.values());
  console.log(`[前置] kevScopeMatches -> scope=${r.scope} totalMatched=${r.totalMatched} entries=${r.entries.map((e) => e.cveID).join(",")}`);
}

const out = await runChat(b, dot.DASHSCOPE_API_KEY, q, null, mode);
const body = out.body ?? {};
console.log(`[runChat] status=${out.status} coverage=${body.coverage} note=${body.note}`);
console.log(`[runChat] sources=${(body.sources ?? []).length} 其中 live=${(body.sources ?? []).filter((s) => s.live).length}`);
console.log("[sources]", (body.sources ?? []).map((s) => `${s.live ? "*" : ""}${String(s.title).slice(0, 60)}`).join(" | "));
console.log("[answer]", String(body.answer).slice(0, 700));
