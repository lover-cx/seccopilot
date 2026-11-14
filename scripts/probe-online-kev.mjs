// 线上 KEV 旗标题探针：同一问题连跑 N 次，逐次留档并判定"给出编号 + 给出收录日期 + 类型对得上、未降级"。
// 用法：N=6 node scripts/probe-online-kev.mjs                                  # 默认线上站点、默认 MODE=on
//       SITE=http://127.0.0.1:8000 MODE=off N=4 node scripts/probe-online-kev.mjs   # 本机自证；off 可排除网络因素
// 判据与 scripts/eval.mjs 的 KEV 题一致：CVE-2026-21509 + 2026-01-26 + Security Feature Bypass / 安全功能绕过。
// MODE 默认 "on"：与 docs/eval-archive/online-kev-empty-retrieval-2026-11-14.json 那条失败留档同模式，
// 这样"同一模式、曾经红、现在绿"才是可比的；auto 模式请显式 MODE=auto 并另存一份。
// 留档按天累加：同一天第二次运行追加为新 run（runId 含时间、MODE、站点），绝不覆盖既有 run 的行。
// 退出码：本次 run 有不合规 → 1。HTTP 非 200 / 非 JSON / HTML 响应都记成显式不合规行，不静默算通过。
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const SITE = (process.env.SITE ?? "https://seccopilot-kpa8w0w9u7e.qoder.zone").replace(/\/+$/, "");
const N = Number(process.env.N ?? 6);
const MODE = process.env.MODE ?? "on";                 // 直接进请求体，由服务端 normalizeMode 处理
const Q = "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";
const HEADERS = { Origin: SITE, Referer: `${SITE}/`, "Content-Type": "application/json" };
const ID = /CVE-2026-21509/i;
const DATE = /2026[-/年]0?1[-/月]26/;                  // 2026-01-26 / 2026/01/26 / 2026年1月26日
const TYPE = /Security Feature Bypass|安全功能绕过/i;
// 降级说法要盖住"只说 NVD 收录、不说在野利用"这一类（线上 6 次里真出现过）。
const DOWNGRADE = /资料未说明|未说明其在野利用|未在野利用|未明确标注|无公开|尚无|无法确认|未经\s*KEV|是否被利用(?:无法|不明)|知识库与网络检索均未覆盖|未覆盖/;
// 判据只到 21509（与 scripts/eval.mjs 一致）。这两条是观察项，不进退出码：
// 目录里 2026 年微软 Office 实际有 3 条，回答漏了 21514 仍会判绿，所以必须逐行记下来。
const WATCH = { "CVE-2026-21514": /CVE-2026-21514/i, "CVE-2026-124194": /CVE-2026-124194/i };

const DAY = new Date().toISOString().slice(0, 10);
// 默认写线上证据文件；打本机 harness 时必须用 OUT= 换文件——同一天把本机行并进线上文件，
// 第 9 条的"线上 9/9 绿"就分不清哪几行是线上、哪几行是自己机器上改过代码之后的结果了。
const OUT = process.env.OUT ?? `docs/eval-archive/online-kev-${DAY}.json`;
const RUN_ID = `${new Date().toISOString().replace(/[:.]/g, "-")}_${MODE}_${SITE.replace(/^\w+:\/\//, "").replace(/\W+/g, "-")}`;

const rows = [];
for (let i = 0; i < N; i++) {
  let row;
  try {
    const r = await fetch(`${SITE}/functions/v1/app?action=chat`, {
      method: "POST", headers: HEADERS, body: JSON.stringify({ question: Q, category: null, mode: MODE }),
      signal: AbortSignal.timeout(90000),
    });
    const text = await r.text();
    let d = null;
    try { d = JSON.parse(text); } catch { /* 非 JSON：下面是显式失败行 */ }
    if (!r.ok || !d || typeof d !== "object") {
      row = { i: i + 1, http: r.status, badResponse: true,
              bodyHead: text.slice(0, 160), ct: r.headers.get("content-type") ?? "",
              hasId: false, hasDate: false, hasType: false, degraded: true };
    } else {
      const a = String(d.answer ?? "");
      const src = Array.isArray(d.sources) ? d.sources : [];
      row = {
        i: i + 1, run: RUN_ID, http: r.status, mode: d.mode, coverage: d.coverage,
        searchUsed: d.search_used, note: d.note,
        nSrc: src.length, nWeb: (d.web_sources ?? []).length,
        // 响应里没有正文可查，只有标题：srcHasId 判的就是"来源标题里有没有该编号"，不要写成能看内容。
        srcHasId: src.some((s) => ID.test(String(s.title ?? ""))),
        srcTitles: src.map((s) => String(s.title ?? "")).slice(0, 6),
        srcSims: src.map((s) => s.similarity),
        hasId: ID.test(a), hasDate: DATE.test(a), hasType: TYPE.test(a),
        degraded: DOWNGRADE.test(a),
        watch: Object.fromEntries(Object.entries(WATCH).map(([k, re]) => [k, re.test(a)])),
        webTitles: (d.web_sources ?? []).map((w) => w.title).slice(0, 5),
        answer: a.slice(0, 1500),
      };
    }
  } catch (e) {
    row = { i: i + 1, run: RUN_ID, http: null, badResponse: true,
            error: String(e?.message ?? e).slice(0, 200),
            hasId: false, hasDate: false, hasType: false, degraded: true };
  }
  rows.push(row);
  console.log(JSON.stringify({ ...row, answer: undefined, webTitles: undefined, srcTitles: undefined }).slice(0, 300));
}
// 追加而不是覆盖：把本次 run 的行并入当天文件，历史 run 原样保留。
// 旧形状 {site,q,rows} 必须先原地迁移成一个 legacy run——当天的 6 行线上证据已经提交在库里，
// 直接按 prev.runs ?? [] 读会把它们静默丢掉，那等于用新脚本删掉了第 9 条唯一引用的证据文件内容。
const prev = existsSync(OUT) ? JSON.parse(readFileSync(OUT, "utf-8")) : { site: SITE, q: Q, runs: [] };
const pass = (rs) => rs.filter((r) => r.hasId && r.hasDate && r.hasType && !r.degraded).length;
const legacy = Array.isArray(prev.rows) && prev.rows.length
  ? [{ runId: `legacy-${DAY}`, mode: prev.mode ?? "unrecorded", site: prev.site ?? SITE,
       ok: pass(prev.rows), total: prev.rows.length,
       srcHasId: prev.rows.filter((r) => r.srcHasId).length,
       watch: Object.fromEntries(Object.keys(WATCH).map((k) =>
         [k, prev.rows.filter((r) => WATCH[k].test(String(r.answer ?? ""))).length])),
       migratedFrom: "rows", rows: prev.rows }]
  : [];
const runs = [...(prev.runs ?? []), ...legacy].filter((x) => x.runId !== RUN_ID);
const ok = pass(rows);
const retrievalOk = rows.filter((r) => r.srcHasId).length;
runs.push({ runId: RUN_ID, mode: MODE, site: SITE, startedAt: new Date().toISOString(),
            ok, total: rows.length, srcHasId: retrievalOk,
            watch: Object.fromEntries(Object.keys(WATCH).map((k) =>
              [k, rows.filter((r) => r.watch?.[k]).length])), rows });
writeFileSync(OUT, JSON.stringify({ site: SITE, q: Q, runs }, null, 1), "utf-8");
console.log(`\n${SITE} mode=${MODE}：${ok}/${rows.length} 次给出「编号 + 收录日期 + 类型」且未降级；`
  + `${retrievalOk}/${rows.length} 次的来源标题里本来就有 CVE-2026-21509；`
  + `观察项 21514 ${runs.at(-1).watch["CVE-2026-21514"]}/${rows.length}、124194 ${runs.at(-1).watch["CVE-2026-124194"]}/${rows.length}。`);
console.log(`留档：${OUT}（本次 runId=${RUN_ID}，文件内共 ${runs.length} 个 run）`);
process.exit(ok === rows.length ? 0 : 1);
