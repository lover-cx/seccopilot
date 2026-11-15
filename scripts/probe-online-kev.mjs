// 线上 KEV 旗标题探针：同一问题连跑 N 次，逐次留档并判定"给出编号 + 给出收录日期 + 类型对得上、未降级"。
// 用法：N=6 node scripts/probe-online-kev.mjs                                  # 默认线上站点、默认 MODE=on
//       SITE=http://127.0.0.1:8000 MODE=off N=4 node scripts/probe-online-kev.mjs   # 本机自证；off 可排除网络因素
// 判据的编号+类型来自 scripts/eval.mjs 的 KEV 题（:92 只有 pattern 与 title，**没有日期判据**），
// 日期口径来自 dev/probe-kev-on-batch.mjs:38 与 dev/check-kev-samples.mjs:12，降级词表只有探针有——探针比 eval.mjs 严。
// MODE 默认 "on"：与 docs/eval-archive/online-kev-empty-retrieval-2026-11-14.json 那条失败留档同模式，
// 这样"同一模式、曾经红、现在绿"才是可比的；auto 模式请显式 MODE=auto 并另存一份。
// 留档按天累加：同一天第二次运行追加为新 run（runId 含时间、MODE、站点），绝不覆盖既有 run 的行。
// 退出码：本次 run 有不合规 → 1。HTTP 非 200 / 非 JSON / HTML 响应都记成显式不合规行，不静默算通过。
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SITE = (process.env.SITE ?? "https://seccopilot-kpa8w0w9u7e.qoder.zone").replace(/\/+$/, "");
// N 必须显式校验：Number("") 是 0、Number("abc") 是 NaN、负数也能过，三者都让循环一次不跑，
// 于是 ok===rows.length 为 0===0 → 退出码 0，一份"全绿"的空留档就这么进库了。
const N = Number(process.env.N ?? 6);
if (!Number.isInteger(N) || N < 1 || N > 50) {
  console.error(`N 必须是 1~50 的整数（当前 N=${JSON.stringify(process.env.N)}）`);
  process.exit(2);
}
const MODE = process.env.MODE ?? "on";                 // 直接进请求体，由服务端 normalizeMode 处理
const Q = "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";
const HEADERS = { Origin: SITE, Referer: `${SITE}/`, "Content-Type": "application/json" };
const ID = /CVE-2026-21509/i;
const DATE = /2026[-/年]0?1[-/月]26/;                  // 2026-01-26 / 2026/01/26 / 2026年1月26日
const TYPE = /Security Feature Bypass|安全功能绕过/i;
// 降级说法要盖住"只说 NVD 收录、不说在野利用"这一类（线上 6 次里真出现过）。
const DOWNGRADE = /资料未说明|未说明其在野利用|未在野利用|未明确标注|未明确指出|未指明|无公开|尚无|无法确认|未经\s*KEV|是否被利用(?:无法|不明)|知识库与网络检索均未覆盖|未覆盖/;
// 判据只到 21509（编号与类型同 eval.mjs 那道题；日期与降级词表是探针更严，eval.mjs 没有）。这两条是观察项，不进退出码：
// 按 dateAdded 落在 2026 年、产品为 Office 的目录条目实际有 5 条（21509、21514、124194，外加两条 2026 年才收录的
// 2009 编号 0238/0556），按 CVE 编号年份算才是 3 条。回答漏了 21514 或 124194 仍会判绿，所以必须逐行记下来。
const WATCH = { "CVE-2026-21514": /CVE-2026-21514/i, "CVE-2026-124194": /CVE-2026-124194/i };

// 日期按北京时区算，不用裸 toISOString()：那是 UTC，北京时间 11-15 01:00 跑会写成 11-14，
// 与文档里"11-15 实测"对不上，而评测日与留档文件名必须同日可追。本项目全部留档文件名用的都是北京日期。
const CN_NOW = () => new Date(Date.now() + 8 * 3600_000);   // 只用于打时间戳：+8 小时后取其 UTC 分量即北京时刻
const DAY = CN_NOW().toISOString().slice(0, 10);
// 默认写线上证据文件；打本机 harness 时必须用 OUT= 换文件——同一天把本机行并进线上文件，
// 第 9 条的"线上 6/6 绿"就分不清哪几行是线上、哪几行是自己机器上改过代码之后的结果了。
// 路径锚到仓库根（脚本所在目录的上一级），不看 cwd：在子目录里裸跑会把留档写到别处，
// 相对 OUT= 同理；给了 OUT= 也按仓库根解析，除非它本身是绝对路径。
const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const OUT = resolve(REPO_ROOT, process.env.OUT ?? `docs/eval-archive/online-kev-${DAY}.json`);
const RUN_ID = `${CN_NOW().toISOString().replace(/[:.]/g, "-")}_${MODE}_${SITE.replace(/^\w+:\/\//, "").replace(/\W+/g, "-")}`;

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
const passLocal = (rs) => rs.filter((r) => r.srcHasId && r.hasId && r.hasDate && r.hasType && !r.degraded).length;
const legacy = Array.isArray(prev.rows) && prev.rows.length
  ? [{ runId: `legacy-${DAY}`, mode: prev.mode ?? "unrecorded", site: prev.site ?? SITE,
       ok: pass(prev.rows), okWithLocal: passLocal(prev.rows), total: prev.rows.length,
       srcHasId: prev.rows.filter((r) => r.srcHasId).length,
       watch: Object.fromEntries(Object.keys(WATCH).map((k) =>
         [k, prev.rows.filter((r) => WATCH[k].test(String(r.answer ?? ""))).length])),
       migratedFrom: "rows", rows: prev.rows }]
  : [];
const runs = [...(prev.runs ?? []), ...legacy].filter((x) => x.runId !== RUN_ID);
const ok = pass(rows);
const retrievalOk = rows.filter((r) => r.srcHasId).length;
// okWithLocal 才是"本地知识库覆盖"这个数字：ok 只看正文有没有编号/日期/类型/降级措辞，
// 2026-11-14 22:33 线上 mode=on 第 1 次实测就是"5 条来源全是 0.3 关键词兜底、一条不是 Office"而正文靠网络答对 → 记绿。
// 若不与 ok 并排给出，探针就会把"检索失败但网络兜住"读成没问题——下一次兜不住时我们看不见。
const okWithLocal = rows.filter((r) => r.srcHasId && r.hasId && r.hasDate && r.hasType && !r.degraded).length;
// 错误行必须单独计数并进摘要：HTTP 非 200 / 非 JSON / 网络异常都算 badResponse，
// 它们已经让 ok < rows.length 从而退出码 1，但若摘要只说"3/6 次合规"，读的人会以为剩下 3 次是降级回答，
// 而不是"根本没打通"——这两种情况的处置完全不同。
const bad = rows.filter((r) => r.badResponse).length;
runs.push({ runId: RUN_ID, mode: MODE, site: SITE, startedAt: new Date().toISOString(),
            ok, okWithLocal, total: rows.length, bad, srcHasId: retrievalOk,
            watch: Object.fromEntries(Object.keys(WATCH).map((k) =>
              [k, rows.filter((r) => r.watch?.[k]).length])), rows });
writeFileSync(OUT, JSON.stringify({ site: SITE, q: Q, runs }, null, 1) + "\n", "utf-8");  // 结尾补换行：探针写的与手写的入库件都要有，diff 才不会带 No newline at end of file
console.log(`\n${SITE} mode=${MODE}：${ok}/${rows.length} 次给出「编号 + 收录日期 + 类型」且未降级，`
  + `其中 ${okWithLocal}/${rows.length} 次的来源标题里本来就有 CVE-2026-21509（"本地有据可引"才是知识库覆盖，`
  + `ok 与 okWithLocal 的差 = 全靠网络兜住的次数）；`
  + `接口异常 ${bad}/${rows.length} 次（HTTP 非 200 / 非 JSON / 抛错）；`
  + `观察项 21514 ${runs.at(-1).watch["CVE-2026-21514"]}/${rows.length}、124194 ${runs.at(-1).watch["CVE-2026-124194"]}/${rows.length}。`);
console.log(`留档：${OUT}（本次 runId=${RUN_ID}，文件内共 ${runs.length} 个 run）`);
process.exit(ok === rows.length ? 0 : 1);
