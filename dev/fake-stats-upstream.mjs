// Task 5 验收用的假上游：让"某一类统计失败"这条分支可复现，而不是只能等上游抖。
// 为什么需要它：aggregateStats 的纯函数用例只测聚合，routes.ts 的 `if (!r.ok) return null`
// 与前端那条"部分分类未能统计"提示都没有别的用例能打到——真实 Supabase 不会配合在指定分类上 500。
// attack 那一类固定回 500，其余回 200 + Content-Range，用来验证：失败的那格是 null/degraded，
// 而不是 0，也不是把整页打成 502。
// 注意这是 .mjs，不能写 TS 类型标注（Node 的 type stripping 只对 .ts 生效；11-16 实测
// `const COUNTS: Record<string, number>` 在这里直接 SyntaxError，服务根本没起来，
// 于是 stats 全线 502——看着像"部分失败"验通过了其实验的是"上游不存在"）。
// 用法（Git Bash，仓库根）：
//   node dev/fake-stats-upstream.mjs &
//   APP_SUPABASE_URL=http://127.0.0.1:8010 APP_SUPABASE_ANON_KEY=x DASHSCOPE_API_KEY=x node dev/function-node.ts
//   curl -s -H "Origin: http://127.0.0.1:8000" "http://127.0.0.1:8000/functions/v1/app?action=stats"
// 期望：categories.attack 为 null、degraded 含 "attack"、status 200、其余分类仍是数字。
import http from "node:http";

const COUNTS = { cve: 1774, cwe: 956, paper: 1800, general: 0 };
const TOTAL = 5397;
const FAILING = "attack";

http.createServer((req, res) => {
  const u = new URL(req.url ?? "/", "http://127.0.0.1:8010");
  const cat = u.searchParams.get("category");
  if (cat === `eq.${FAILING}`) {
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "induced_failure_for_test" }));
    console.log("-> 500 for category=eq." + FAILING);
    return;
  }
  const n = cat ? (COUNTS[cat.replace("eq.", "")] ?? 0) : TOTAL;
  res.writeHead(200, { "Content-Range": `0-${Math.max(n - 1, 0)}/${n}` });
  res.end("[]");
  console.log(`-> 200 count=${n} (${cat ?? "total"})`);
}).listen(8010, "127.0.0.1", () => console.log("fake upstream → http://127.0.0.1:8010"));
