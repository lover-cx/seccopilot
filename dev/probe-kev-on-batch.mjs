// KEV 那道题在 mode=on 下的遵守率采样：连续跑 N 次，每次记录
//   是否列出 CVE-2026-21509 / 是否给出 KEV 收录日期 / 网络来源条数（web_sources.length）
// 之前"6 次全对"这类话只写在稿子里、没有留档，判分争议无法复核，所以补这个批量探针。
// 用法（先起 harness）：
//   NODE_USE_ENV_PROXY=1 HTTP_PROXY=http://127.0.0.1:7897 HTTPS_PROXY=http://127.0.0.1:7897 \
//     NO_PROXY=dashscope.aliyuncs.com,nvd.nist.gov,services.nvd.nist.gov \
//     node dev/probe-kev-on-batch.mjs [次数] [mode]
import { writeFileSync } from "node:fs";

const SITE = process.env.SITE ?? "http://127.0.0.1:8000";
const N = Number(process.argv[2] ?? 6);
const MODE = process.argv[3] ?? "on";
const Q = "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";
const OUT = `dev/kev-${MODE}-batch.json`;

const out = [];
for (let i = 0; i < N; i++) {
  let row;
  try {
    const r = await fetch(`${SITE}/functions/v1/app?action=chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: SITE, Referer: `${SITE}/` },
      body: JSON.stringify({ question: Q, mode: MODE, category: null }),
      signal: AbortSignal.timeout(90000),
    });
    const d = await r.json();
    const a = String(d.answer ?? "");
    row = {
      i: i + 1,
      http: r.status,
      coverage: d.coverage,
      searchUsed: d.search_used,
      nSrc: (d.sources ?? []).length,
      nWeb: (d.web_sources ?? []).length,
      has21509: a.includes("CVE-2026-21509"),
      // 正则原来只认 /2026-01-26/，把"2026年1月26日"这种中文写法漏掉了：留档字段 6 次里只报 2 次为真，
      // 而逐条读正文 6 次全给了日期。字段太窄会让我们误说"模型没给日期"，所以两种写法都认。
      hasKevDate: /2026[-/年]0?1[-/月]26/.test(a),
      srcHas21509: (d.sources ?? []).some((s) => String(s.title ?? "").includes("CVE-2026-21509")),
      answer: a.slice(0, 1200),
    };
  } catch (e) {
    row = { i: i + 1, error: String(e.message ?? e).slice(0, 160) };
  }
  out.push(row);
  console.log(JSON.stringify(row).slice(0, 220));
  writeFileSync(OUT, JSON.stringify({ q: Q, mode: MODE, site: SITE, rows: out }, null, 1), "utf-8");
}
const ok = out.filter((r) => r.has21509 && r.hasKevDate).length;console.log(`\n${MODE}：${ok}/${out.length} 次同时列出 CVE-2026-21509 与其 KEV 收录日期（2026-01-26）`);
console.log(`web_sources=0 的次数：${out.filter((r) => r.nWeb === 0).length}；检索结果里含 21509 的次数：${out.filter((r) => r.srcHas21509).length}`);
