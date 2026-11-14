// SecCopilot 联网搜索评测：mode=off 与 mode=on 同题对照，自动打分并产出 markdown 报告
//
// 用法：
//   node scripts/eval.mjs                # 跑全部（off + on），写 docs/eval-report.md
//   node scripts/eval.mjs --only=off     # 只跑一种模式（off | on | auto，省时间）
//   node scripts/eval.mjs --grep="在野"  # 只跑问题里含该子串的题（必须同时给 EVAL_JSON=dev/...，见下）
//   node scripts/eval.mjs --rescore      # 不重跑模型，复用留档回答正文按当前判分口径重算时效题判据
//   node scripts/eval.mjs --selfcheck    # 不发网络请求，用 7 条合成样本验判分器本身（含 3 条必须判红）
//   EVAL_OUT=/path/report.md node scripts/eval.mjs
//   BASELINE_JSON=docs/eval-archive/xxx.json node scripts/eval.mjs
//     ↑ 附一节"对照基线"：同一份判分代码打两组留档，只换被测版本（报告里会列出判定翻转的行）
//   SITE=http://127.0.0.1:8000 EVAL_JSON=dev/eval-local.json node scripts/eval.mjs
//     ↑ 发布被平台队列卡住时，用 `npm run dev:function:node` 对当前源码做同题实测（留档另开路径，
//       不要覆盖 docs/eval-report.json）
//
// 2026-11-12 踩过两个同类的坑，都在"参数静默改变被测对象"这一类里：
//   ① --only= 只接受模式名。当时把它当"题目过滤器"用了（--only="微软 Office 漏洞"），未知值在
//      Function 侧被 normalizeMode 归成 auto，于是静默跑完整套 21 题、留档里的 mode 字段还是个假模式名。
//      现在 --only= 校验取值，想筛题目用 --grep=；--grep= 且没显式给 EVAL_JSON 时直接退出。
//   ② --rescore 不带 SITE= 时，报告头部会按本次 env 写成线上站点，而回答正文其实来自本地 harness 那轮——
//      数字没错、来源声明错了。现在留档自带 meta.site，头部只认留档，与本次 env 不一致就打印警告。
// 注：docs/eval-report.json 现在是"本地 harness·闸门版"那一轮（分数较低的第二遍）；线上已发布版本的
// 证据在 docs/eval-archive/deployed-prompt-only-2026-11-12.json，两份都不要在报告里混成一栏。
//
// 三类题型各自的判分口径：
//   local   知识库内：来源里必须出现期望的权威标识（编号或官方域名）
//   time    时效性：回答必须命中"时效题基准"表里已核验的具体事实（不接受话题相近的其它编号）
//   outside 知识库外：回答必须明确表达"未覆盖/无法确认"，且不得编造编号
// 幻觉检查独立于题型：回答里出现的 CVE/CWE/T 编号若既不在来源也不在回答依据中，记为可疑。
import { readFileSync, writeFileSync, existsSync } from "node:fs";

const SITE = process.env.SITE ?? "https://seccopilot-kpa8w0w9u7e.qoder.zone";
const FN = `${SITE}/functions/v1/app?action=chat`;
// 回答正文的留档路径。判分口径变更（--rescore）和可疑编号核验（verify-suspects.mjs）都读它，
// 所以本地 harness 试跑必须写到别处，否则会把线上那一版的证据覆盖掉。
const ARCHIVE = process.env.EVAL_JSON ?? "docs/eval-report.json";
// 可选的另一份留档，用来做"同一判分口径、不同被测版本"的对照（例如线上已发布版 vs 本地闸门版）。
const BASELINE = process.env.BASELINE_JSON ?? "";
const HEADERS = {
  "Content-Type": "application/json",
  Origin: SITE,
  Referer: `${SITE}/`,
};
const OUT = process.env.EVAL_OUT ?? "docs/eval-report.md";
// 被测对象必须写进留档，而不是只留在报告头部：--rescore 复用上一次的回答正文重算，
// 如果头部那次跑的是本地 harness、这次忘了带 SITE=，报告就会把线上站点当成被测目标——
// 这是坑 7（"参数写错会静默换掉被测对象"）的另一个入口，所以让留档自己声明来源。
let measuredSite = SITE;
const flag = (name) => (process.argv.find((a) => a.startsWith(`${name}=`)) ?? "").slice(name.length + 1);
const ONLY = flag("--only");
const GREP = flag("--grep");
const RESCORE = process.argv.includes("--rescore");
if (ONLY && !["off", "on", "auto"].includes(ONLY)) {
  console.error(`--only=${ONLY} 不是模式名。--only 只接受 off | on | auto；想按关键字筛题目请用 --grep="…"`);
  process.exit(2);
}

const QUESTIONS = [
  // ── 知识库内：本地权威条目应当命中，不需要联网 ──────────────────────────
  { kind: "local", q: "T1059 是什么攻击技术？有哪些子技术？", expect: { id: "T1059", host: "attack.mitre.org" } },
  { kind: "local", q: "MITRE ATT&CK 初始访问阶段有哪些技术？", expect: { host: "attack.mitre.org" } },
  { kind: "local", q: "如何检测 PowerShell 恶意脚本执行？", expect: { id: "T1059", host: "attack.mitre.org" } },
  { kind: "local", q: "CVE-2021-44228 的影响范围和修复版本是什么？", expect: { id: "CVE-2021-44228", host: "nvd.nist.gov" } },
  { kind: "local", q: "XZ Utils 后门（CVE-2024-3094）的原理是什么？", expect: { id: "CVE-2024-3094" } },
  { kind: "local", q: "CWE-79 是什么弱点？如何缓解？", expect: { id: "CWE-79", host: "cwe.mitre.org" } },
  { kind: "local", q: "CWE-787 越界写入和 CWE-125 有什么区别？", expect: { id: "CWE-787", host: "cwe.mitre.org" } },
  { kind: "local", q: "硬编码凭据类漏洞对应哪个 CWE？", expect: { host: "cwe.mitre.org" } },
  { kind: "local", q: "最近有哪些已被确认在野利用的 Apache 产品漏洞？", expect: { host: "nvd.nist.gov" } },
  { kind: "local", q: "Windows 打印后台处理器相关的在野利用漏洞是哪个 CVE？", expect: { id: "CVE-" } },
  { kind: "local", q: "隐私计算、同态加密方向近年有哪些安全论文？", expect: { host: "arxiv.org" } },
  { kind: "local", q: "arXiv 上关于大模型越狱（jailbreak）的研究讲了什么？", expect: { host: "arxiv.org" } },

  // ── 时效性：不联网基本不可能答对 ─────────────────────────────────────────
  // 判分口径（2026-11-10 收紧）：每题写死已核验的 ground truth，答出该事实才算对；
  // "承认自己不知道"同样算对——这条题真正考的是时效覆盖，不是措辞。
  // ground truth 来源见文件末尾"时效题基准"表，全部逐条对过 NVD 接口。
  // admit 分支不是放水：mode=off 明确不联网，而本地 CVE 库没有 2026 Log4j 批次
  // （search_cves 现查 totalResults=0）。此时唯一正确的产品行为是承认本地没覆盖、无法确认。
  // 口径收紧为"必须把这句话说成本地库缺记录"：2026-11-12 实测 off 答"目前无 2026 年新披露的
  // Log4j CVE"——那是把"本库没条目"说成"现实中不存在"的全局否定式幻觉，不允许算通过。
  { kind: "time", q: "2026 年新披露的 Apache Log4j 相关 CVE 有哪些？修复版本是什么？",
    expect: { pattern: "CVE-2026-344(7[7-9]|8[01])|CVE-2026-49844",
      admit: "(知识库|本地库|资料)[^。；]{0,16}(未覆盖|未收录|没有.{0,6}记录)|未覆盖该时间段" },
    ground: "CVE-2026-34477~34481（NVD published 2026-04-10）+ CVE-2026-49844（2026-07-10）；本地库无此批次，off 模式须说『知识库未覆盖/无法确认』才算对，说『目前无』算错" },
  { kind: "time", q: "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？",
    // title 判据：编号之外还要求漏洞类型对得上。NVD 描述为 "Reliance on untrusted inputs in a security
    // decision in Microsoft Office ... bypass a security feature locally"，KEV 收录 2026-01-26，
    // 本地库与 MSRC 的标题都是 "Microsoft Office Security Feature Bypass Vulnerability"。
    // 防的是缺陷 6 那一类的另一种形态：编号真、类型挂错（原判据只看编号出现，抓不到）。
    // 我们一度以为线上留档里出现过把 21509 写成"Azure Portal 前端 CSRF"的回答——逐条回查确认没有那种文本，
    // 那次误读来自把来源标题当成回答内容。所以这条是**预防性收紧**，不是修已测到的缺陷（见 timeAccuracy 注释）。
    expect: { pattern: "CVE-2026-21509", title: "Security Feature Bypass|安全功能绕过" },
    ground: "CVE-2026-21509（NVD：Reliance on untrusted inputs in a security decision in Microsoft Office；官方名 Security Feature Bypass；KEV 收录 2026-01-26、修复期限 2026-02-16）" },
  { kind: "time", q: "本周有没有新披露的高危漏洞？",
    expect: { pattern: "CVE-2026-\\d{4,7}",
      failIf: "2026-0[1-8]-|2026年[1-8]月|收录日期[:：]?\\s*2026-0",
      // 2026-11-12 放宽：原口径只认"无法确认本周"这三种连续写法，实测本地闸门版的回答写成
      // "本地知识库未覆盖近 7 天的新增条目，无法确认"——语义完全合格却被判错，是判据欠包含。
      // 放宽后仍要求"缺口承认词"与"本周/近 7 天"同句共现，不接受只说"无法确认"的泛泛推脱。
      admit: "(未覆盖|无法确认|不能确认|无法确定|没有)[^。；]{0,24}(本周|近\\s*7\\s*天|这一周)"
        + "|(本周|近\\s*7\\s*天|这一周)[^。；]{0,24}(未覆盖|无法确认|不能确认|无法确定|无记录)" },
    ground: "评测日为 2026-11-10；把 8 月及更早的 KEV 收录记录说成“本周”即判错（off 模式实测踩过）" },
  { kind: "time", q: "目前最新的 ATT&CK 框架是哪个版本？今年有更新吗？",
    expect: { pattern: "v?1[7-9](\\.\\d+)?\\b", failIf: "版本为?\\s*14|14\\.0", admit: "无法确认|知识库未覆盖" },
    ground: "v18（本地库战术命名已含 v18 新命名，回归用例 attack：14 个战术（含 v18 新命名）；网络检索亦为 V18/2026）" },
  { kind: "time", q: "2026 年量子计算或后量子密码领域有什么新进展？",
    expect: { pattern: "(2026|PQC|后量子)" },
    ground: "本地论文库（arXiv 2026 批次）即可覆盖，off 模式答对属正当命中" },

  // ── 知识库外：考幻觉，应当承认未覆盖 ────────────────────────────────────
  { kind: "outside", q: "SecCopilot 这个项目的内部代码仓库地址是什么？", expect: { refuse: true } },
  { kind: "outside", q: "2019 年某款我没听过的国产路由器型号 CVE-9999-00001 详情？", expect: { refuse: true } },
  { kind: "outside", q: "CVE-2030-99999 的 CVSS 评分和利用链是什么？", expect: { refuse: true } },

  // ── 域外可答题：不属于安全知识库范围，允许正常回答，但不得冒出安全编号 ──────
  // 这类题原先按"必须拒答"判，是判分口径错了：问 WiFi 密码怎么找回，
  // 助手正常给通用建议是对的，真正的底线是不要顺手编一个 CVE/CWE 编号。
  { kind: "general", q: "我本机 WiFi 密码忘了怎么办？", expect: { noFakeId: true } },
];

const REFUSE = /(未覆盖|没有|无法确认|无法提供|不在知识库|未检索到|抱歉|不清楚|没有相关|未收录|无相关)/;
const ID_RE = /\b(CVE-\d{4}-\d{4,7}|CWE-\d{1,4}|T\d{4}(?:\.\d{3})?)\b/g;
const MODES = ONLY ? [ONLY] : ["off", "on"];
const SELECTED = GREP ? QUESTIONS.filter((x) => x.q.includes(GREP)) : QUESTIONS;
if (GREP && SELECTED.length === 0) {
  console.error(`--grep="${GREP}" 没匹配到任何题目（21 题题库里没有这个子串）`);
  process.exit(2);
}
// 子集运行只写子集留档；不给路径就默认写 docs/eval-report.json，那会把线上证据替换成一题的样本。
if (GREP && !RESCORE && !process.env.EVAL_JSON) {
  console.error(`--grep 只会留被子集命中的回答。请显式指定 EVAL_JSON=dev/xxx.json，` +
    `否则会覆盖 docs/eval-report.json（线上已发布版本的证据）。`);
  process.exit(2);
}

async function ask(question, mode) {
  const res = await fetch(FN, {
    method: "POST",
    headers: HEADERS,
    body: JSON.stringify({ question, mode, category: null }),
    signal: AbortSignal.timeout(90000),
  });
  if (res.status !== 200) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 160)}`);
  return await res.json();
}

const hostOf = (u) => { try { return new URL(u).hostname; } catch { return ""; } };

// 时效题判据单独成函数：score() 与 --rescore 共用同一口径，避免两处各写一遍、改一处漏一处。
function timeAccuracy(e, answer) {
  // 必须"答出那个具体事实"才算对。只看 CVE-2026-\d+ 是错的：
  // 实测 off 模式问 Log4j 时答了 Tomcat 的 CVE-2026-34486，也被判通过。
  const a = answer ?? "";
  const hit = e.pattern ? new RegExp(e.pattern, "i").test(a) : false;
  // failIf 必须逐句判定：把旧日期"说出来"本身不是错，把它当作本周才是错。
  // 2026-11-12 实测：提示词修好后 off 答"最近一条是 CVE-2026-34486，KEV 收录于 2026-08-04，
  // 不在本周（2026-11-12）范围内，无法确认"——这是标准正确答案，却被整篇 failIf 判成不合格。
  const QUALIFY = /不在|超出|早于|更早|未覆盖|无法确认|并非|不属于|需开启联网/;
  const failRe = e.failIf ? new RegExp(e.failIf, "i") : null;
  const bad = failRe
    ? String(a).split(/(?<=[。；;\n])/).some((s) => failRe.test(s) && !QUALIFY.test(s))
    : false;
  const honest = e.admit ? new RegExp(e.admit, "i").test(a) : false;
  // title 判据：编号出现之外，还要求回答里的漏洞类型/产品与官方名对得上。
  // 这是**预防性收紧，不是修已测到的缺陷**：2026-11-12 用这条口径把三份留档逐行重算过，判定一个都没变
  // （我们一度以为线上留档里出现过"21509 被写成 Azure Portal CSRF"，逐条回查后确认没有那种文本，
  //  那次误读来自把来源标题当成回答内容）。它防的是缺陷 6 那一类的另一种形态：编号真、类型挂错。
  // 判分器自己会不会又把它写成空转？`--selfcheck` 用合成样本同时钉住"必须判红"和"必须判绿"。
  const titleOk = e.title ? new RegExp(e.title, "i").test(a) : true;
  return (hit && titleOk && !bad) || honest;
}

// 判分器自检：不发网络请求，用合成样本同时钉住"必须判绿"和"必须判红"两个方向。
// 为什么需要它——这份判分器今天已经骗过我们两次，两次都是"看起来在工作"：
//   整篇 failIf 把合格的诚实回答判成违规（假阳性）；正则写成字符串时被转义吃掉反斜杠，永远匹配不到（假阴性）。
//   新加一条判据而不去证明它会判红，就等于允许它空转。
// 用法：node scripts/eval.mjs --selfcheck
if (process.argv.includes("--selfcheck")) {
  const KEV_EXPECT = { pattern: "CVE-2026-21509", title: "Security Feature Bypass|安全功能绕过" };
  const cases = [
    { name: "编号 + 官方漏洞类型（应当判绿）", e: KEV_EXPECT,
      a: "- CVE-2026-21509：Microsoft Office 安全功能绕过漏洞，于 2026-01-26 被收录至 CISA KEV 目录，修复期限 2026-02-16。", want: true },
    { name: "编号对但漏洞类型挂错（应当判红）", e: KEV_EXPECT,
      a: "- CVE-2026-21509：Microsoft Office Azure Portal 前端跨站请求伪造（CSRF）漏洞，2026-01-26 列入 KEV。", want: false },
    { name: "没答出该编号（应当判红）", e: KEV_EXPECT,
      a: "- CVE-2026-124194：Outlook 零日漏洞，2026-11-10 列入 KEV。", want: false },
    { name: "承认本地库未覆盖（应当判绿）", e: { pattern: "CVE-2026-21509", admit: "无法确认" },
      a: "本地知识库未覆盖 2026 年的该主题，无法确认，需开启联网检索。", want: true },
    { name: "旧日期未加限定（应当判红）", e: { pattern: "CVE-2026-34486", failIf: "2026-0[1-8]-\\d{2}" },
      a: "本周新增：CVE-2026-34486，KEV 收录于 2026-08-04。", want: false },
    { name: "旧日期已限定'不在本周'（应当判绿）", e: { pattern: "CVE-2026-34486", failIf: "2026-0[1-8]-\\d{2}" },
      a: "最近一条是 CVE-2026-34486，KEV 收录于 2026-08-04，不在本周（2026-11-12）范围内，无法确认本周新增。", want: true },
    { name: "无 title 判据时不应受影响（应当判绿）", e: { pattern: "CVE-2026-34477" },
      a: "CVE-2026-34477 影响 log4j-core，修复版本 2.25.4。", want: true },
  ];
  let bad = 0;
  for (const c of cases) {
    const got = timeAccuracy(c.e, c.a);
    const ok = got === c.want;
    if (!ok) bad++;
    console.log(`${ok ? "OK  " : "FAIL"} ${c.name} :: 期望 ${c.want}，实得 ${got}`);
  }
  console.log(bad ? `\n判分器自检失败 ${bad}/${cases.length} 项——判据本身有错，先别信任何分数` : `\n判分器自检通过 ${cases.length}/${cases.length}（含 3 个"必须判红"的方向）`);
  process.exit(bad ? 1 : 0);
}

function score(item, d) {
  const srcHosts = (d.sources ?? []).map((s) => hostOf(s.url));
  const allIds = [...new Set((d.answer ?? "").match(ID_RE) ?? [])];
  // 引用侧同时看标题和 URL：联网来源常把编号放在 URL 里（NVD 详情页尤其如此）
  const cited = [...(d.sources ?? []).flatMap((s) => [s.title, s.url]),
    ...(d.web_sources ?? []).flatMap((w) => [w.title, w.url])].filter(Boolean).join(" ").toUpperCase();
  const out = { citation: null, accuracy: null, refuse: null, noFakeId: null, suspect: [], coverage: d.coverage, searched: d.search_used };
  const e = item.expect;
  if (e.id) out.citation = (d.sources ?? []).some((s) => s.title.toUpperCase().includes(e.id.toUpperCase()));
  else if (e.host) out.citation = srcHosts.some((h) => h.includes(e.host));
  if (e.pattern) out.accuracy = timeAccuracy(e, d.answer ?? "");
  if (e.refuse) out.refuse = REFUSE.test(d.answer ?? "");
  // 可疑编号：回答给出、但任何来源（标题或 URL）里都没有的编号。
  // 两类必须先排除，否则指标会把正确行为算成幻觉：
  //   1) 问题里本来就带的编号（如假的 CVE-2030-99999），复述回来是对的；
  //   2) 子技术 T1059.001——来源标题通常只写父技术 T1059。
  const qIds = new Set(((item.q ?? "").match(ID_RE) ?? []).map((s) => s.toUpperCase()));
  out.suspect = allIds.filter((id) => {
    if (qIds.has(id.toUpperCase())) return false;
    if (cited.includes(id.toUpperCase())) return false;
    if (id.startsWith("T") && id.includes(".") && cited.includes(id.split(".")[0])) return false;
    return true;
  });
  if (e.noFakeId) out.noFakeId = out.suspect.length === 0 && (d.answer ?? "").length > 0;
  return out;
}

const rows = [];
// 每类题型的通过判据（口径见文件头注释与报告末尾）
const passOf = (r) => (r.kind === "local" ? r.citation : r.kind === "time" ? r.accuracy : r.kind === "general" ? r.noFakeId : r.refuse);
if (RESCORE) {
  // 判分口径改了（例如 failIf 改成逐句），但 42 条回答正文已经留档在 docs/eval-report.json 里，
  // 用 --rescore 重算即可，不必再打一次模型——判分争议要能离线复核，否则每次改口径都要花 10 分钟重跑。
  // 只重算 accuracy：时效题判据只看回答正文，正文是完整留档的。
  // citation / suspect 依赖来源标题与 URL，留档时没存这些字段，保留原值（报告头部会注明）。
  const prevDoc = JSON.parse(readFileSync(ARCHIVE, "utf-8"));
  const prev = prevDoc.rows ?? [];
  // 报告头部的"站点"必须来自留档，不能来自本次运行的环境变量：--rescore 一条模型都不打，
  // 环境变了但回答没变，头部跟着环境走就会把被测对象写错。
  if (prevDoc.meta?.site) {
    measuredSite = prevDoc.meta.site;
    if (prevDoc.meta.site !== SITE) {
      console.log(`⚠ 留档记录的被测对象是 ${prevDoc.meta.site}，本次 SITE=${SITE}；报告按留档的 ${prevDoc.meta.site} 写。`);
    }
  } else {
    console.log(`⚠ 留档没有 meta.site（旧格式），报告只能沿用本次 SITE=${SITE}——重跑一次才会补上留档来源。`);
  }
  for (const r of prev) {
    const item = QUESTIONS.find((x) => x.q === r.q);
    const row = { ...r };
    if (item && r.kind === "time" && !r.error) row.accuracy = timeAccuracy(item.expect, r.answer ?? "");
    rows.push(row);
  }
  console.log(`--rescore：复用 ${rows.length} 条留档回答，只重算时效题判据`);
} else {
  for (const mode of MODES) {
    console.log(`\n===== mode=${mode} =====`);
    for (const item of SELECTED) {
      let d, err = "";
      try { d = await ask(item.q, mode); } catch (e) { err = String(e.message ?? e).slice(0, 120); }
      if (!d) {
        rows.push({ mode, kind: item.kind, q: item.q, error: err, coverage: "-", searched: false, citation: false, accuracy: false, refuse: false, noFakeId: false, suspect: [] });
        console.log(`  FAIL ${item.q.slice(0, 28)} :: ${err}`);
        continue;
      }
      const s = score(item, d);
      rows.push({ mode, kind: item.kind, q: item.q, error: "", coverage: s.coverage, searched: s.searched,
        citation: s.citation, accuracy: s.accuracy, refuse: s.refuse, noFakeId: s.noFakeId, suspect: s.suspect,
        nSrc: (d.sources ?? []).length, nWeb: (d.web_sources ?? []).length,
        // 每轮的检索上下文也要留档：KEV 那道题的争议（闸门算对了、模型没照办）本来只能靠"是不是
        // 那一轮没检索到"猜，因为留档只有条数没有标题。把标题存下来，判分争议才能离线判定。
        srcTitles: (d.sources ?? []).map((s) => String(s.title ?? "").slice(0, 80)),
        webTitles: (d.web_sources ?? []).map((w) => String(w.title ?? "").slice(0, 80)),
        // 判分是启发式，未通过时必须能回看原文才能定性（模型有输出波动，同一题两次跑可能不同）。
        answer: String(d.answer ?? "").slice(0, 1500) });
      const okKind = passOf(rows[rows.length - 1]);
      console.log(`  ${okKind ? "PASS" : "pass?"} [${item.kind}] ${item.q.slice(0, 30)}… cov=${s.coverage} src=${(d.sources ?? []).length} web=${(d.web_sources ?? []).length}${s.suspect.length ? " SUSPECT=" + s.suspect.join(",") : ""}`);
    }
  }
}

const statOf = (rs) => {
  const by = (k) => rs.filter((r) => r.kind === k);
  const pct = (arr) => (arr.length ? Math.round((arr.filter(passOf).length / arr.length) * 100) : 0);
  return {
    total: rs.length, ok: rs.filter(passOf).length,
    local: pct(by("local")), time: pct(by("time")), outside: pct(by("outside")), general: pct(by("general")),
    searched: rs.filter((r) => r.searched).length,
    suspect: rs.reduce((n, r) => n + (r.suspect?.length ?? 0), 0),
  };
};
const stat = (mode) => statOf(rows.filter((r) => r.mode === mode));

const md = [];
md.push("# SecCopilot 联网搜索评测报告\n");
md.push(`- 站点：${measuredSite}${measuredSite.includes("seccopilot-kpa8w0w9u7e.qoder.zone")
  ? "（线上已发布版本）"
  : "（本地 harness：跑的是仓库当前源码，含尚未发布的代码闸门；Supabase 检索、模型与上游全部是真实网络调用）"}`);
md.push(`- 生成时间：${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC${
  RESCORE ? "（--rescore：只按当前判分口径重算时效题，回答正文取自上一次实测，未重新调用模型；来源类判据沿用上一次结果）" : ""}`);
md.push(`- 题量：${SELECTED.length} 题 × ${MODES.length} 种模式 = ${rows.length} 次回答${
  GREP ? `（--grep="${GREP}" 子集运行，题库共 ${QUESTIONS.length} 题）` : ""}`);
// "触发联网次数"这一列读的是响应里的 search_used，而 search_used = 上游搜索插件执行过（usage.plugins.search 有值），
// 不等于给得出可核验来源：2026-11-12 下午起同一批请求的 output.search_info.search_results 是空数组，
// 于是 search_used=true 而 web_sources=[]。所以这一列不能单独用来判断"联网效果"，必须和"网络源"列一起看。
md.push("- ⚠ `触发联网次数` 统计的是 `search_used`，它的含义是**上游搜索插件执行过**，不是「本次回答带回了可核验的网络来源」。" +
  "2026-11-12 下午实测：`usage.plugins.search` = `{count:1, strategy:max}` 而 `search_info.search_results` 是空数组，" +
  "同一道题 `mode=on` 连采 10 次 `web_sources` 全为 0——这一列必须和后文「网络源」一列合起来读，单看会把「没带回来源」读成「检索成功」。\n");
md.push("## 汇总\n");
md.push("| 模式 | 总体命中 | 知识库内题 | 时效性题 | 知识库外题（正确拒答） | 域外可答题（不编编号） | 触发联网次数 | 可疑编造编号 |");
md.push("| --- | --- | --- | --- | --- | --- | --- | --- |");
for (const m of MODES) {
  const s = stat(m);
  md.push(`| \`${m}\` | ${s.ok}/${s.total} | ${s.local}% | ${s.time}% | ${s.outside}% | ${s.general}% | ${s.searched} | ${s.suspect} |`);
}
if (BASELINE) {
  if (!existsSync(BASELINE)) {
    md.push(`\n> ⚠ 基线留档不存在：\`${BASELINE}\`，本节跳过。\n`);
  } else {
    const baseRows = JSON.parse(readFileSync(BASELINE, "utf-8")).rows ?? [];
    md.push("\n## 对照基线（同一套判分代码）\n");
    md.push(`基线留档：\`${BASELINE}\`（${baseRows.length} 条回答）。两张表由**同一份判分代码**打分（含 \`timeAccuracy\` 与逐句限定语例外），唯一差别是被测的那一版 Function——判据改动不会让任何一边占便宜。\n`);
    md.push("| 被测版本 | 模式 | 总体命中 | 知识库内题 | 时效性题 | 知识库外题 | 域外可答题 | 触发联网 | 可疑编号 |");
    md.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for (const m of MODES) {
      const s = statOf(baseRows.filter((r) => r.mode === m));
      md.push(`| 基线 | \`${m}\` | ${s.ok}/${s.total} | ${s.local}% | ${s.time}% | ${s.outside}% | ${s.general}% | ${s.searched} | ${s.suspect} |`);
    }
    for (const m of MODES) {
      const s = stat(m);
      md.push(`| 本次 | \`${m}\` | ${s.ok}/${s.total} | ${s.local}% | ${s.time}% | ${s.outside}% | ${s.general}% | ${s.searched} | ${s.suspect} |`);
    }
    // 只报判定翻转的行：总数相同但错在不同题，必须看出来
    const key = (r) => `${r.mode}|${r.q}`;
    const cur = new Map(rows.map((r) => [key(r), r]));
    const flips = baseRows
      .filter((b) => cur.has(key(b)) && Boolean(b.q) && passOf(b) !== passOf(cur.get(key(b))))
      .map((b) => ({ b, c: cur.get(key(b)) }));
    md.push(`\n判定翻转的行（基线 → 本次）：${flips.length} 处\n`);
    if (flips.length) {
      md.push("| 模式 | 问题 | 基线 | 本次 |");
      md.push("| --- | --- | --- | --- |");
      for (const f of flips) {
        md.push(`| \`${f.b.mode}\` | ${f.b.q.slice(0, 40)}${f.b.q.length > 40 ? "…" : ""} | ${passOf(f.b) ? "通过" : "未通过"} | ${passOf(f.c) ? "通过" : "未通过"} |`);
      }
    } else md.push("无——两版在相同判据下逐行同结果。");
    md.push("");
  }
}

md.push("\n## 逐题明细\n");
for (const m of MODES) {
  md.push(`### mode = \`${m}\`\n`);
  md.push("| 类型 | 问题 | 来源命中 | 时效正确 | 正确拒答 | 不编编号 | coverage | 知识库源 | 网络源 | 判定 |");
  md.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const r of rows.filter((x) => x.mode === m)) {
    const yn = (v) => (v === null || v === undefined ? "—" : v ? "✅" : "❌");
    md.push(`| ${r.kind} | ${r.q.slice(0, 34)}${r.q.length > 34 ? "…" : ""} | ${yn(r.citation)} | ${yn(r.accuracy)} | ${yn(r.refuse)} | ${yn(r.noFakeId)} | ${r.coverage ?? "—"} | ${r.nSrc ?? 0} | ${r.nWeb ?? 0} | ${passOf(r) ? "通过" : "未通过"}${r.error ? ` ｜ ${r.error}` : ""} |`);
  }
  md.push("");
}
md.push("## 判分口径\n");
md.push("- **知识库内题**：回答引用的知识库来源中出现期望编号或权威域名即通过（不要求措辞一致）。");
md.push("- **时效性题**：回答必须命中下方“时效题基准”里已核验的具体事实；把话题相近的其它编号答进来不算对（例：问 Log4j 却给 Tomcat 的 CVE-2026-34486）。明确承认“无法确认本周/知识库未覆盖”同样算通过——这类题考的是时效覆盖，不是措辞。KEV 那道还额外要求漏洞类型与官方名对得上（`title` 判据），防“编号真、类型挂错”；这条是**预防性收紧**，不是修已测到的缺陷——`node dev/check-title-criterion.mjs` 重算四份留档那道题的 8 行，判定翻转 0 行，且判分器本身由 `node scripts/eval.mjs --selfcheck` 用 7 条合成样本钉住（含 3 个必须判红的方向）。");
md.push("- **知识库外题**：回答出现明确的未覆盖/无法确认表述即通过；这是幻觉防线，不是检索能力。");
md.push("- **域外可答题**：问题本身合法但不在安全知识库范围（如找回 WiFi 密码），允许正常回答，判据是不得冒出来源里没有的安全编号。");
md.push("- **可疑编造编号**：回答里出现 CVE/CWE/T 编号，但所有来源的标题与 URL 都没有该编号。已排除两类误报：问题里本来就带的编号（复述回来是正确行为）、以及父技术被引用的子技术编号。`off` 模式下这项仍需人工确认——本地条目正文里合法引用的其他编号也会出现在回答中，而响应只回传来源标题以控制体积。");
md.push("- 自动判分只覆盖形式正确性，语义质量仍需抽查回答正文。\n");

md.push("## 时效题基准（ground truth）\n");
md.push("下表事实于评测日逐条对过 NVD 接口 `services.nvd.nist.gov/rest/json/cves/2.0?cveId=`（或本地库版本元数据），判分直接引用，不接受措辞相近的其它编号。\n");
md.push("| 问题 | 基准事实 |");
md.push("| --- | --- |");
for (const q of QUESTIONS.filter((x) => x.kind === "time")) {
  md.push(`| ${q.q} | ${q.ground ?? "—"} |`);
}
md.push("");

if (!existsSync("docs")) { /* docs 目录在项目里已存在 */ }
writeFileSync(OUT, md.join("\n"), "utf-8");
const summary = MODES.map((m) => `${m}: ${JSON.stringify(stat(m))}`).join("\n");
writeFileSync(ARCHIVE, JSON.stringify({
  meta: {
    site: measuredSite,                       // 被测对象：留档自己声明，报告头部从这里取
    generatedAt: new Date().toISOString(),
    modes: MODES,
    questions: SELECTED.length,
    totalQuestions: QUESTIONS.length,
    grep: GREP || undefined,
    rescore: RESCORE || undefined,
  },
  rows,
}, null, 1), "utf-8");
console.log(`\n报告已写入 ${OUT}\n${summary}`);

