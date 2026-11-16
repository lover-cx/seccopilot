// 时效题基准刷新：核对 scripts/eval.mjs 里写死的 ground truth 有没有过期，并把当天实测落档。
//
// 为什么要有这个脚本（Task 7）：eval.mjs 的时效题基准是 2026-11-10 逐条对过 NVD 写死的，
// 而 KEV 目录每天在长。基准过期不是产品缺陷，是**尺子过期**——不主动刷新并留核校记录，
// 报告里那个"时效正确率"的含义就会悄悄变掉。所以每次要引用时效题分数之前，先跑这个脚本。
//
// 用法：
//   node scripts/refresh-time-grounds.mjs
//     直连 NVD 与 CISA。CISA（cisa.gov）在本机要走代理时用下面这条：
//   PROXY=1 node scripts/refresh-time-grounds.mjs
//     脚本会在发第一个请求前补上 NODE_USE_ENV_PROXY=1 与 HTTP(S)_PROXY=127.0.0.1:7897，
//     并把 NVD 放进 NO_PROXY（NVD 走代理反而会被限流拖死）。
//
// 限流：NVD 无 key 约 5 请求/30 秒，因此**串行 + 7 秒间隔**（与 scripts/verify-suspects.mjs 同一做法），
// 整个脚本约 30 秒。不要并发化。
//
// 退出码：0 = 现有基准全部仍成立；1 = 有变化，需要人工改 eval.mjs 的 expect/ground；2 = 上游取不到。
// 留档：docs/eval-archive/time-grounds-<日期>.json（日期按北京时区，与报告头部同一口径）。
import { readFileSync, writeFileSync } from "node:fs";

if (process.env.PROXY) {
  process.env.NODE_USE_ENV_PROXY ||= "1";
  process.env.HTTP_PROXY ||= "http://127.0.0.1:7897";
  process.env.HTTPS_PROXY ||= "http://127.0.0.1:7897";
  process.env.NO_PROXY ||= "services.nvd.nist.gov,nvd.nist.gov";
}

const KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const DAY = new Date(Date.now() + 8 * 3600_000).toISOString().slice(0, 10); // 北京时区的"今天"
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const fetchKev = async () => {
  const r = await fetch(KEV_FEED, { signal: AbortSignal.timeout(45000), headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`KEV feed HTTP ${r.status}`);
  return r.json();
};
const nvd = async (id) => {
  const get = async () => {
    const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, { signal: AbortSignal.timeout(30000) });
    if (r.status === 404) return { id, exists: false, httpStatus: 404 };
    if (r.status !== 200) return { id, exists: null, httpStatus: r.status };
    const d = await r.json();
    const c = d?.vulnerabilities?.[0]?.cve;
    if (!c) return { id, exists: false, httpStatus: 200 };
    return {
      id, exists: true, httpStatus: 200,
      published: c.published?.slice(0, 10) ?? null,
      kevAdd: c.cisaExploitAdd ?? null,
      kevDue: c.cisaActionDue ?? null,
      title: (c.descriptions ?? []).find((x) => x.lang === "en")?.value?.slice(0, 160) ?? null,
    };
  };
  let r = await get();
  // 503 / 超时是"没核到"，不是"不存在"——与 stats 那条契约同一个口径。退避后只重试一次。
  if (r.exists === null) {
    await sleep(15000);
    const again = await get();
    if (again.exists !== null) r = { ...again, retried: true };
    else r = { ...again, retried: true, attempts: [r.httpStatus, again.httpStatus] };
  }
  return r;
};

// 时效题基准里点过名的编号，逐条回 NVD 核存在性与收录日期。
const IDS = ["CVE-2026-21509", "CVE-2026-21514", "CVE-2026-124194", "CVE-2026-34477", "CVE-2026-34486", "CVE-2026-49844"];

const out = { checkedAt: new Date().toISOString(), evalDay: DAY, nvd: [], kev: {}, changes: [] };
console.log(`基准核对日（北京时区）：${DAY}\n`);
console.log("── NVD 逐条核对（串行 + 7s，限流约 5 次/30s）──");
for (let i = 0; i < IDS.length; i++) {
  let r;
  try {
    r = await nvd(IDS[i]);
  } catch (e) {
    r = { id: IDS[i], exists: null, error: String(e.message ?? e).slice(0, 120) };
  }
  out.nvd.push(r);
  console.log(`  ${r.id}  exists=${r.exists}  published=${r.published ?? "-"}  kevAdd=${r.kevAdd ?? "-"}${r.error ? `  error=${r.error}` : ""}`);
  if (i < IDS.length - 1) await sleep(7000);
}

console.log("\n── CISA KEV 目录 ──");
let feed;
try {
  feed = await fetchKev();
} catch (e) {
  console.log(`KEV 目录取不到：${e.message}——本次不下"基准仍成立"的结论（上游不可达 ≠ 基准没变）`);
  process.exit(2);
}
out.kev.catalogVersion = feed.catalogVersion;
out.kev.dateReleased = feed.dateReleased;
out.kev.count = feed.count;
console.log(`  版本 ${feed.catalogVersion}（发布于 ${feed.dateReleased}），共 ${feed.count} 条`);

// 两个口径都要算，且判据按 dateAdded 那一套推：题面"2026 年被 CISA 确认"里的"确认"对应 dateAdded。
// 只按 CVE 编号年份筛会漏掉 CVE-2009-0556 / 0238 这种"老编号、2026 年才进 KEV"的条目——它们恰恰最容易被答漏。
const isOffice = (x) => /Office/i.test(`${x.product} ${x.vulnerabilityName}`) && /Microsoft/i.test(x.vendorProject);
const row = (x) => ({ cveID: x.cveID, dateAdded: x.dateAdded, dueDate: x.dueDate, product: x.product, name: x.vulnerabilityName });
const byAdded = feed.vulnerabilities.filter((x) => /^2026/.test(x.dateAdded) && isOffice(x)).sort((a, b) => a.dateAdded.localeCompare(b.dateAdded));
const byNumber = feed.vulnerabilities.filter((x) => /^CVE-2026/.test(x.cveID) && isOffice(x)).sort((a, b) => a.cveID.localeCompare(b.cveID));
out.kev.officeByDateAdded2026 = byAdded.map(row);
out.kev.officeByCveYear2026 = byNumber.map(row);
console.log(`  微软 Office 的 2026 条目：按 dateAdded 落在 2026 → ${byAdded.length} 条；按 CVE 编号年份=2026 → ${byNumber.length} 条`);
for (const o of byAdded) console.log(`    [dateAdded] ${o.dateAdded}  ${o.cveID}  ${o.vulnerabilityName}`);
for (const o of byNumber) console.log(`    [编号年份] ${o.dateAdded}  ${o.cveID}  ${o.vulnerabilityName}`);

// 最近 7 天窗口的 KEV 新增——"本周有没有新披露高危漏洞"那道题的参考事实。
const weekStart = new Date(Date.parse(`${DAY}T00:00:00Z`) - 7 * 864e5).toISOString().slice(0, 10);
const thisWeek = feed.vulnerabilities.filter((x) => x.dateAdded > weekStart && x.dateAdded <= DAY);
out.kev.weekWindow = { from: weekStart, to: DAY, count: thisWeek.length, ids: thisWeek.map((x) => x.cveID) };
console.log(`\n  最近 7 天（${weekStart} ~ ${DAY}）KEV 新增 ${thisWeek.length} 条`);

// 与 eval.mjs 现有基准对比。pattern **从 eval.mjs 源码里读**，不在这里抄一份：
// 抄一份就等于把"尺子现在认哪些编号"这个事实放到第二个地方，改了 eval.mjs 而这个脚本还在拿旧集合比，
// 报出来的"基准仍成立"就是假的。
const expandAlternations = (p) => {
  const i = p.indexOf("(");
  if (i < 0) return [p];
  const j = p.indexOf(")", i);
  if (j < 0) return [p];
  const head = p.slice(0, i), mid = p.slice(i + 1, j), tail = p.slice(j + 1);
  const acc = [];
  for (const alt of mid.split("|")) for (const s of expandAlternations(head + alt + tail)) acc.push(s);
  return acc;
};
const KEV_Q = "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";
let evalSrc = "";
try {
  evalSrc = readFileSync(new URL("./eval.mjs", import.meta.url), "utf-8");
} catch (e) {
  console.log(`读不到 scripts/eval.mjs（${e.message}），无法对比现有基准`);
  process.exit(2);
}
const qIdx = evalSrc.indexOf(KEV_Q);
const patM = qIdx < 0 ? null : /pattern:\s*"((?:[^"\\]|\\.)*)"/.exec(evalSrc.slice(qIdx, qIdx + 1200));
if (!patM) {
  console.log("在 eval.mjs 里没定位到那道旗标题的 expect.pattern，无法对比现有基准——先修脚本再说基准成立不成立。");
  process.exit(2);
}
const CUR_KEV_PATTERN = [...new Set(expandAlternations(patM[1]).flatMap((s) => s.match(/CVE-\d{4}-\d{4,7}/g) ?? []))];
console.log(`\n  eval.mjs 现基准覆盖：${CUR_KEV_PATTERN.join(", ")}`);
const addedIds = byAdded.map((x) => x.cveID);
const missing = addedIds.filter((id) => !CUR_KEV_PATTERN.includes(id));
const extra = CUR_KEV_PATTERN.filter((id) => !addedIds.includes(id));
if (missing.length) out.changes.push(`旗标题按 dateAdded 口径应覆盖而现基准未覆盖：${missing.join(", ")}（改 eval.mjs 的 expect.pattern）`);
if (extra.length) out.changes.push(`现基准里的 ${extra.join(", ")} 已不在当天目录的 dateAdded-2026 口径内（可能是目录修正，也可能是筛选口径变了，人工确认）`);
const notInNvd = out.nvd.filter((r) => r.exists === false);
if (notInNvd.length) out.changes.push(`NVD 查不到的基准编号：${notInNvd.map((r) => r.id).join(", ")}`);
const degraded = out.nvd.filter((r) => r.exists === null);
if (degraded.length) {
  console.log(`  ⚠ NVD 未能核对（重试后仍非 200）：${degraded.map((r) => `${r.id}→${JSON.stringify(r.attempts ?? r.httpStatus)}`).join(", ")}。这些编号记为"不知道"，不是"不存在"。`);
  out.degradedNvd = degraded.map((r) => r.id);
}
// 交叉核对：NVD 的 cisaExploitAdd 应当能在当天目录里找到同一条，且 dateAdded 一致。
// 只看"这条不在 Office 集合里"是没有意义的——CVE-2026-34486 确实在 KEV，只是不是 Office 产品。
const feedById = new Map(feed.vulnerabilities.map((x) => [x.cveID, x]));
const kevMismatch = [];
for (const r of out.nvd) {
  if (!r.exists || !r.kevAdd) continue;
  const f = feedById.get(r.id);
  if (!f) kevMismatch.push(`${r.id}: NVD 说 KEV 收录 ${r.kevAdd}，当天目录里没有这条`);
  else if (f.dateAdded !== r.kevAdd) kevMismatch.push(`${r.id}: NVD kevAdd=${r.kevAdd} 与目录 dateAdded=${f.dateAdded} 不一致`);
}
if (kevMismatch.length) out.changes.push(`NVD ↔ KEV 目录交叉核对不一致：${kevMismatch.join("；")}`);

writeFileSync(`docs/eval-archive/time-grounds-${DAY}.json`, JSON.stringify(out, null, 1) + "\n", "utf-8");
console.log(`\n留档：docs/eval-archive/time-grounds-${DAY}.json`);
if (out.changes.length) {
  console.log(`\n需要人工确认的基准变化：\n- ${out.changes.join("\n- ")}`);
  process.exit(1);
}
if (degraded.length) {
  console.log(`\n目录侧一致，但 NVD 有 ${degraded.length} 个编号没核到——本次不能宣布"基准全部成立"（退出码 2）。`);
  process.exit(2);
}
console.log("\n基准仍成立（当天目录的 dateAdded-2026 Office 集合与 eval.mjs 的 expect.pattern 一致，NVD 全部核到）。");
