// 线上 KEV 旗标题探针：同一问题连跑 N 次，逐次留档并判定"给出编号 + 给出 KEV 收录日期"。
// 用法：SITE=https://seccopilot-kpa8w0w9u7e.qoder.zone N=6 node scripts/probe-online-kev.mjs
//       SITE=http://127.0.0.1:8000 node scripts/probe-online-kev.mjs     # 修完代码后本机自证
// 判据与 scripts/eval.mjs 的 KEV 题保持一致：CVE-2026-21509 + 2026-01-26（或中文写法），
// 外加"类型对得上"（Security Feature Bypass / 安全功能绕过）。
// 退出码：不合规次数 > 0 → 1。留档落 docs/eval-archive/online-kev-<date>.json（此目录入库，评委不重打接口也能核）。
import { writeFileSync } from "node:fs";

const SITE = (process.env.SITE ?? "https://seccopilot-kpa8w0w9u7e.qoder.zone").replace(/\/+$/, "");
const N = Number(process.env.N ?? 6);
const Q = "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";
const HEADERS = { Origin: SITE, Referer: `${SITE}/`, "Content-Type": "application/json" };
const ID = /CVE-2026-21509/i;
const DATE = /2026[-/年]0?1[-/月]26/;              // 2026-01-26 / 2026-01-26 / 2026年1月26日
const TYPE = /Security Feature Bypass|安全功能绕过/i;
const DOWNGRADE = /资料未说明|未说明其在野利用|未在野利用|未明确标注|无公开|尚无/;

const OUT = `docs/eval-archive/online-kev-${new Date().toISOString().slice(0, 10)}.json`;
const rows = [];
for (let i = 0; i < N; i++) {
  let row;
  try {
    const r = await fetch(`${SITE}/functions/v1/app?action=chat`, {
      method: "POST", headers: HEADERS, body: JSON.stringify({ question: Q, category: null }),
      signal: AbortSignal.timeout(90000),
    });
    const d = await r.json();
    const a = String(d.answer ?? "");
    row = {
      i: i + 1, http: r.status, coverage: d.coverage, searchUsed: d.search_used, note: d.note,
      nSrc: (d.sources ?? []).length, nWeb: (d.web_sources ?? []).length,
      srcHasId: (d.sources ?? []).some((s) => ID.test(String(s.title ?? "") + String(s.content ?? ""))),
      hasId: ID.test(a), hasDate: DATE.test(a), hasType: TYPE.test(a),
      degraded: DOWNGRADE.test(a), webTitles: (d.web_sources ?? []).map((w) => w.title).slice(0, 5),
      answer: a.slice(0, 1500),
    };
  } catch (e) {
    row = { i: i + 1, error: String(e?.message ?? e).slice(0, 200) };
  }
  rows.push(row);
  console.log(JSON.stringify({ ...row, answer: undefined, webTitles: undefined }).slice(0, 260));
  writeFileSync(OUT, JSON.stringify({ site: SITE, q: Q, rows }, null, 1), "utf-8");
}
const ok = rows.filter((r) => r.hasId && r.hasDate && r.hasType && !r.degraded).length;
const retrievalOk = rows.filter((r) => r.srcHasId).length;
console.log(`\n${SITE}：${ok}/${rows.length} 次给出「编号 + 收录日期 + 类型」且未降级；`
  + `其中 ${retrievalOk} 次的检索结果里本来就有 CVE-2026-21509。`);
console.log(`留档：${OUT}`);
process.exit(ok === rows.length ? 0 : 1);
