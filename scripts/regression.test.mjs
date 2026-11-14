// SecCopilot 回归测试套件（零依赖，使用 Node 内置 node:test）
// 覆盖已发布站点的 Function 契约：stats / attack / cve / chat
// 运行：npm test                （默认打到线上站点）
//       SITE=http://127.0.0.1:5173 npm test   （打到本地预览）
// 注意：chat 用例会真实调用 DashScope embedding + LLM，产生少量 API 费用，
//       只想跑只读回归时用：SKIP_LLM=1 npm test
import { test } from "node:test";
import assert from "node:assert/strict";

const SITE = (process.env.SITE ?? "https://seccopilot-kpa8w0w9u7e.qoder.zone").replace(/\/+$/, "");
const SKIP_LLM = process.env.SKIP_LLM === "1";
const FN = `${SITE}/functions/v1/app`;
const ORIGIN_HEADERS = { Origin: SITE, Referer: `${SITE}/` };

const get = async (action, params = {}) => {
  const qs = new URLSearchParams({ action, ...params });
  const res = await fetch(`${FN}?${qs}`, { headers: ORIGIN_HEADERS });
  assert.equal(res.status, 200, `${action} 应返回 200，实际 ${res.status}`);
  return res.json();
};

const postChat = async (question, extra = {}) => {
  const res = await fetch(`${FN}?action=chat`, {
    method: "POST",
    headers: { ...ORIGIN_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify({ question, ...extra }),
  });
  const text = await res.text();
  if (res.status !== 200) {
    assert.fail(`chat 应返回 200，实际 ${res.status}：${text.slice(0, 200)}`);
  }
  return JSON.parse(text);
};

// ── 1. 知识库统计 ────────────────────────────────────────────────────────────
test("stats 返回完整计数", async () => {
  const d = await get("stats");
  assert.ok(Number.isInteger(d.total) && d.total > 0, "total 应为正整数");
  // 分类会随数据扩充增加（cwe、paper 已加入），因此按返回的键求和，不再写死分类列表
  for (const c of ["cve", "attack", "cwe", "paper"]) {
    assert.ok(c in d.categories, `categories 缺少 ${c}`);
  }
  const sum = Object.values(d.categories).reduce((a, b) => a + b, 0);
  assert.equal(sum, d.total, `分类求和 ${sum} 应等于 total ${d.total}`);
  assert.ok(d.categories.attack >= 800, "ATT&CK 数据应已导入");
  assert.ok(d.categories.cve >= 1700, "KEV 在野利用漏洞应已导入");
  assert.ok(d.categories.cwe >= 900, "CWE 弱点应已导入");
  assert.ok(d.categories.paper >= 1500, "arXiv 安全论文应已导入");
});

// ── 2. ATT&CK 战术筛选 ───────────────────────────────────────────────────────
const TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact",
];
test("attack：14 个战术（含 v18 新命名）均可筛出结果", async () => {
  for (const tactic of TACTICS) {
    const d = await get("attack", { tactic });
    assert.ok(d.results?.length > 0, `${tactic} 不应返回空结果`);
    assert.ok(d.results.length <= 20, `${tactic} 结果应被限制在 20 条内`);
  }
});

test("attack：technique 精确查询 T1059", async () => {
  const d = await get("attack", { technique: "T1059" });
  assert.ok(d.results?.length >= 10, `T1059 应返回主技术+子技术，实际 ${d.results?.length}`);
  assert.ok(d.results.some((r) => r.technique_id === "T1059"), "应包含父技术 T1059");
});

test("attack：结果字段完整且无裸 HTML 标签泄漏到 description 之外的结构", async () => {
  const d = await get("attack", { tactic: "Defense Evasion" });
  for (const r of d.results.slice(0, 5)) {
    for (const f of ["technique_id", "technique_name", "tactic", "description", "source_url"]) {
      assert.ok(f in r, `缺少字段 ${f}`);
    }
    assert.match(r.source_url, /^https:\/\//, "source_url 应为绝对 URL");
    assert.match(r.technique_id, /^T\d{4}(\.\d{3})?$/, `technique_id 格式异常：${r.technique_id}`);
  }
});

// ── 3. CVE 检索 ──────────────────────────────────────────────────────────────
const CVE_CASES = [
  ["log4j", "CVE-2021-44228"],
  ["CVE-2024-3094", "CVE-2024-3094"],
  ["activemq", "CVE-2023-46604"],
];
test("cve：按关键词与编号检索命中预期条目", async () => {
  for (const [q, expected] of CVE_CASES) {
    const d = await get("cve", { q });
    assert.ok(d.results?.length > 0, `查询 ${q} 不应为空`);
    assert.ok(
      d.results.some((r) => r.cve_id === expected),
      `查询 ${q} 应命中 ${expected}，实际 ${d.results.map((r) => r.cve_id).join(",")}`,
    );
  }
});

test("cve：severity 与 cvss 元数据可用（JSONB metadata 修复回归）", async () => {
  const d = await get("cve", { q: "log4j" });
  const hit = d.results.find((r) => r.cve_id === "CVE-2021-44228");
  assert.ok(hit, "应命中 Log4Shell");
  assert.equal(String(hit.severity).toLowerCase(), "critical");
  assert.ok(Number(hit.cvss_score) >= 9.0, `CVSS 应 >= 9.0，实际 ${hit.cvss_score}`);
});

test("cve：缺少查询词时返回 400", async () => {
  const res = await fetch(`${FN}?action=cve`, { headers: ORIGIN_HEADERS });
  assert.equal(res.status, 400);
});

// ── 3b. Phase2 扩充数据：KEV 在野利用条目 ────────────────────────────────────
test("cve：KEV 条目可按编号检索，且保留前端依赖的事实前缀", async () => {
  const d = await get("cve", { q: "CVE-2022-33891" });
  const hit = d.results?.find((r) => r.cve_id === "CVE-2022-33891");
  assert.ok(hit, "应命中 KEV 中的 Apache Spark 条目");
  // CvePanel 靠这个前缀解析厂商/收录日期/修复期限（RPC 不返回 metadata），改格式要同步改前端
  assert.match(hit.content, /^在野利用（CISA KEV）｜厂商：/, "KEV 行应以事实前缀开头");
  assert.match(hit.content, /修复期限：\d{4}-\d{2}-\d{2}/, "KEV 行应含修复期限");
  assert.match(hit.source_url, /^https:\/\//, "KEV 行应有可点击官方链接");
});

test("cve：厂商关键词能命中多条 KEV 条目（数据面已扩充，不再是 3 条样例）", async () => {
  for (const q of ["Fortinet", "Microsoft", "Windows"]) {
    const d = await get("cve", { q });
    assert.ok(d.results?.length >= 5, `${q} 应命中至少 5 条，实际 ${d.results?.length}`);
  }
});

// ── 3c. Phase2 新分类可被向量检索到（走 chat，受 SKIP_LLM 控制）──────────────
for (const [label, question, category, host] of [
  ["CWE 弱点", "CWE-79 是什么弱点？如何缓解？", "cwe", "cwe.mitre.org"],
  ["安全论文", "arXiv 上关于大模型越狱（jailbreak）的研究讲了什么？", "paper", "arxiv.org"],
]) {
  test(`chat：按 ${label} 分类限定检索（来源应含 ${host}）`, async (t) => {
    if (SKIP_LLM) return t.skip("SKIP_LLM=1");
    const d = await postChat(question, { category });
    assert.ok(!isDegenerate(d.answer), `回答异常：${JSON.stringify(d.answer).slice(0, 120)}`);
    assert.ok(d.sources?.length > 0, `${category} 分类下应返回来源`);
    assert.ok(
      d.sources.some((s) => (s.url || "").includes(host)),
      `${category} 分类的来源应包含 ${host}，实际：${d.sources.map((s) => s.url).join(",").slice(0, 220)}`,
    );
    assert.ok(["auto", "on", "off"].includes(d.mode), `mode 字段应为三态之一，实际 ${d.mode}`);
    assert.ok(Array.isArray(d.web_sources), "web_sources 字段应始终为数组");
  });
}

// ── 4. Chat RAG（会产生 API 调用）─────────────────────────────────────────────
const isDegenerate = (a) =>
  !a || /AI 服务暂不可用|向量服务暂不可用|服务尚未配置/.test(a) || a.trim().length < 20;

for (const [name, question, expectInSource] of [
  ["T1059 战术归类", "T1059 是什么技术？", "T1059"],
  ["Log4Shell 归属", "CVE-2021-44228 的严重程度和影响是什么？", "CVE-2021-44228"],
]) {
  test(`chat：${name}（引用来源含 ${expectInSource}）`, async (t) => {
    if (SKIP_LLM) return t.skip("SKIP_LLM=1");
    const d = await postChat(question);
    assert.ok(!isDegenerate(d.answer), `回答异常：${JSON.stringify(d.answer).slice(0, 120)}`);
    assert.ok(d.sources?.length > 0, "应返回参考来源");
    const titles = d.sources.map((s) => s.title).join(" | ");
    assert.ok(titles.includes(expectInSource), `来源标题中应出现 ${expectInSource}，实际：${titles.slice(0, 200)}`);
    if (name === "T1059 战术归类") {
      assert.ok(d.sources[0].title.startsWith("T1059"), "首条来源应是父技术 T1059，而非子技术");
    }
    assert.ok(d.sources.every((s) => /^https:\/\//.test(s.url || "")), "每条来源都应有可点击 URL");
    // LLM 输出非确定性：引用标记缺失只记录，不判失败
    if (!/\[\d+\]/.test(d.answer)) console.warn(`  [note] ${name}：回答未带 [n] 引用标记`);
  });
}

test("chat：知识库未覆盖的问题不编造来源", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat("请用三句话介绍量子纠缠在光纤传感中的最新进展。");
  assert.ok(typeof d.answer === "string" && d.answer.length > 0, "仍应有回答文本");
  assert.ok(Array.isArray(d.sources), "sources 字段应始终为数组");
});

// ── 5. 联网搜索（三层知识来源：本地库 / 实时上游 / 通用网页）───────────────────
const WEB_PROBE = "2026 年新披露的 Apache Log4j 相关 CVE 有哪些？修复版本是什么？";

test("chat：响应含联网搜索契约字段", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat(WEB_PROBE);
  for (const f of ["web_sources", "search_used", "mode", "coverage"]) {
    assert.ok(f in d, `响应缺少新增字段 ${f}`);
  }
  assert.equal(d.mode, "auto", "默认 mode 应为 auto");
  assert.ok(Array.isArray(d.web_sources), "web_sources 应为数组");
  assert.ok(["local", "mixed", "web"].includes(d.coverage), `coverage 取值异常：${d.coverage}`);
  // 时效性问题在 auto 模式下必须触发联网
  assert.equal(d.search_used, true, "含 2026 时效信号的问题应触发联网检索");
  assert.ok(d.web_sources.length > 0, "应返回可核验的网络来源列表");
  for (const w of d.web_sources.slice(0, 5)) {
    for (const f of ["index", "title", "url", "site"]) assert.ok(f in w, `网络来源字段不完整：${JSON.stringify(w)}`);
    assert.match(w.url, /^https:\/\//, "网络来源应有绝对 URL");
  }
});

test("chat：联网结果能答出知识库中没有的 2026 年 CVE 编号", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat(WEB_PROBE);
  assert.ok(!isDegenerate(d.answer), `回答异常：${String(d.answer).slice(0, 120)}`);
  const m = d.answer.match(/CVE-20(2[5-7])-\d{4,7}/g) ?? [];
  assert.ok(m.length > 0, `回答应包含 2025/2026 年 CVE 编号，实际：${String(d.answer).slice(0, 200)}`);
  assert.ok(!/2024\s*年.*?(尚未|不).*?2026/.test(d.answer), "不应再出现“2026 尚未到来”这类过期时间认知");
});

test("chat：mode=off 时不产生联网调用", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat(WEB_PROBE, { mode: "off" });
  assert.equal(d.mode, "off");
  assert.equal(d.search_used, false, "mode=off 不应联网");
  assert.equal(d.web_sources.length, 0, "mode=off 不应返回网络来源");
});

test("chat：mode=on 时强制联网（即便本地库已覆盖）", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat("T1059 是什么技术？", { mode: "on" });
  assert.equal(d.search_used, true, "mode=on 应强制联网");
  assert.ok(d.sources.length > 0, "本地知识库来源仍应保留");
});

test("chat：知识库已覆盖的问题不联网（省钱且避免污染权威引用）", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat("MITRE ATT&CK 的 T1059 Command and Scripting Interpreter 有哪些常见子技术？");
  assert.equal(d.coverage, "local", `本地充分命中时 coverage 应为 local，实际 ${d.coverage}`);
  assert.equal(d.search_used, false, "本地充分命中时不应联网");
});

// 评测暴露的两个真实缺陷，用测试锁住（见 docs/eval-report.md 判分口径）：
// 1) 语义检索对 "CWE-79" 这类短编号会命中 CWE-829/CWE-749，正确条目排不进来；
// 2) 相似度分不开库内库外（WiFi 密码 0.571 vs ATT&CK 初始访问 0.576），
//    所以域外问题必须靠"有没有精确锚点"来判断，而不是靠阈值硬切。
test("chat：CWE 编号问题精确锚定到该弱点条目", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat("CWE-79 是什么弱点？如何缓解？", { mode: "off" });
  assert.ok(d.sources?.length > 0, "应返回来源");
  const first = d.sources[0].title;
  assert.ok(first.startsWith("CWE-79"), `首条来源应是 CWE-79 本身，实际：${d.sources.map((s) => s.title).join(" | ").slice(0, 160)}`);
  assert.match(d.sources[0].url, /cwe\.mitre\.org\/data\/definitions\/79\.html$/, "应指向 MITRE 官方定义页");
});

test("chat：知识库外问题不得声称“回答基于本地知识库”", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat("帮我写一首关于秋天的诗", { mode: "off" });
  assert.equal(d.search_used, false, "mode=off 不应联网");
  assert.match(String(d.note ?? ""), /未有效覆盖|未命中/, `note 应承认知识库未覆盖，实际：${d.note}`);
});

test("chat：mode=off 的回答不得声称做过网络检索", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat("2026 年最新披露的一个零日漏洞是什么？", { mode: "off" });
  assert.equal(d.search_used, false, "mode=off 不应联网");
  assert.ok(!/网络检索|联网检索|已搜索网络|全网核实/.test(String(d.answer)),
    `没有联网却声称查过网络：${String(d.answer).slice(0, 220)}`);
});

test("chat：时效题以当天日期为基准，不把旧收录记录说成本周", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat("本周有没有新披露的高危漏洞？", { mode: "off" });
  const a = String(d.answer);
  assert.ok(!/当前(为|是)?\s*20(19|2[0-5])\s*年/.test(a), `模型自报了过期的当前年份：${a.slice(0, 220)}`);
  if (/2026-0([1-8])-/.test(a)) {
    assert.match(a, /无法确认|未覆盖|不属于|远超|更早|并非/,
      `引用了早于本周的日期却没有相应限定表述：${a.slice(0, 240)}`);
  }
});

// 规则 7：本地库缺记录 ≠ 现实中不存在。
// 本地 CVE 库确实没有 2026 Log4j 批次（search_cves 现查 totalResults=0），不联网时唯一
// 诚实的回答是承认本地未覆盖；2026-11-12 实测旧提示词答"目前无 2026 年新披露的 Log4j CVE"，
// 用户照这句话写报告就会漏掉真实存在的批次——属全局否定式幻觉，必须钉住。
const FALSE_NEGATIVE = [
  /(目前|现阶段|当前)[^。；]{0,8}(无|没有|不存在)[^。；]{0,14}(新披露|新增|新漏洞|相关 CVE)/,
  /2026\s*年[^。；]{0,6}(无|没有|不存在)[^。；]{0,14}(新增|新披露)/,
];
// 判分口径（2026-11-12 本地 harness 实测修正）：整段匹配会把"因本地知识库在 2026 年内无新增条目"
// 这种明确限定在本地库、并且紧接着承认"无法确认"的诚实陈述也判红——那是判分器假阳性，不是产品缺陷。
// 改成按句判定，且只认"本地知识库/本地库/本地资料/本地收录"这一类显式本地限定词作豁免；
// 下面两条自检把口径钉住：线上实测过的全局否定句式必须仍然判红。
const LOCAL_SCOPE = /本地知识库|本地库|本地资料|本地收录/;
const hasFalseNegative = (text) =>
  String(text)
    .split(/[。；\n]/)
    .some((s) => FALSE_NEGATIVE.some((re) => re.test(s)) && !LOCAL_SCOPE.test(s));

test("chat：mode=off 不得把“本地库没记录”答成“现实中不存在”", async (t) => {
  assert.ok(hasFalseNegative("目前无 2026 年新披露的 Apache Log4j 相关 CVE。\n因此，2026 年无新增的 Apache Log4j 相关 CVE 记录。"),
    "判分器漏掉了 2026-11-12 线上实测到的全局否定句式");
  assert.ok(!hasFalseNegative("因本地知识库在 2026 年内无新增条目，故无法确认修复版本或具体漏洞详情。"),
    "判分器把限定在本地库的诚实陈述误判为全局否定");
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat("2026 年新披露的 Apache Log4j 相关 CVE 有哪些？修复版本是什么？", { mode: "off" });
  const a = String(d.answer);
  assert.equal(d.search_used, false, "mode=off 不应联网");
  assert.ok(!hasFalseNegative(a), `声称现实中不存在：${a.slice(0, 260)}`);
  assert.match(a, /未覆盖|未收录|无法确认|需开启联网/, `应承认本地库未覆盖该批次：${a.slice(0, 260)}`);
});

// 纯函数回归（不发网络请求，SKIP_LLM 下也要跑）：mode=off 时效题的"缺记录 ≠ 不存在"兜底。
// 这段逻辑是提示词规则 7 的代码化——规则 7 单独用压不住（4 次采样 1 次复发），
// 改成由代码把"本地库在该时间窗内的条目数、最近一条日期"算出来喂给模型。
let gapFacts = null;
let dropOffTacticDocs = null;
let requestedTactic = null;
let kevFacts = null;
try {
  const m = await import("../functions/lib/chat.ts");
  gapFacts = m.localTimeGapFacts;
  dropOffTacticDocs = m.dropOffTacticDocs;
  requestedTactic = m.requestedTactic;
  kevFacts = m.kevFacts;
} catch { /* Node 版本不支持 .ts 直读时跳过本用例 */ }

test("localTimeGapFacts：只在本地库确实缺该时间窗条目时兜底", () => {
  if (!gapFacts) return t_skip();
  const doc = (title, content) => ({ id: 1, title, content, source_url: "u", category: "cve", similarity: 0.6 });
  const log4jDocs = [
    doc("CVE-2026-34486: Apache Tomcat Improper Encryption", "厂商：Apache｜产品：Tomcat｜KEV 收录：2026-08-04"),
    doc("CVE-2021-45046: Apache Log4j2 Deserialization", "厂商：Apache｜产品：Log4j2｜KEV 收录：2023-05-01｜修复期限：2023-05-22"),
  ];
  const fired = (q, docs) => gapFacts(q, docs).length > 0;
  // 必须触发：本库有 2026 年的 Apache Tomcat，却没有 2026 年的 Log4j——这正是幻觉的发生地
  assert.ok(fired("2026 年新披露的 Apache Log4j 相关 CVE 有哪些？修复版本是什么？", log4jDocs),
    "2026 Log4j 缺条目时应给出兜底事实");
  assert.ok(fired("本周有没有新披露的高危漏洞？", log4jDocs), "本周无条目时应给出兜底事实");
  // 不得触发：误伤会把能正常回答的题变成拒答
  assert.ok(!fired("最近有哪些已被确认在野利用的 Apache 产品漏洞？", log4jDocs),
    "模糊时间词不应触发（本地 KEV 目录本身是近期快照）");
  assert.ok(!fired("CWE-79 是什么弱点？如何缓解？", log4jDocs), "非时效题不应触发");
  assert.ok(!fired("2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？",
    [doc("CVE-2026-21509: Microsoft Office", "产品：Office｜KEV 收录：2026-01-20｜修复期限：2026-02-16")]),
    "本地确有该年该主题条目时不应触发");
  // 触发时必须给出可照抄的事实，而不是又一条抽象禁令
  const msg = gapFacts("2026 年新披露的 Apache Log4j 相关 CVE 有哪些？修复版本是什么？", log4jDocs);
  assert.match(msg, /条目数为 0/);
  assert.match(msg, /2023-05-22|2023-05-01/);
  assert.match(msg, /无法确认/);
});

// 纯函数回归：ATT&CK 的"阶段"是硬约束。2026-11-12 线上实测问"初始访问阶段有哪些技术"时，
// 语义检索把本地库标注为 credential-access 的 T1214 捞了进来，模型不仅列进初始访问，
// 还编了个不存在的中文名"利用第三方应用"。这里锁住过滤逻辑本身。
test("dropOffTacticDocs：问某阶段时不把别的阶段的语义条目塞进上下文", () => {
  if (!dropOffTacticDocs || !requestedTactic) return t_skip();
  const atk = (tid, tactics, anchor = false) => ({
    id: 1, title: `${tid} Name`, content: "c", source_url: "u",
    category: "attack", similarity: 0.6, tactics, anchor,
  });
  assert.equal(requestedTactic("MITRE ATT&CK 初始访问阶段有哪些技术？"), "initial-access");
  assert.equal(requestedTactic("持久化阶段有哪些技术？"), "persistence");
  assert.equal(requestedTactic("有哪些高危漏洞？"), null, "没点名的题不该触发过滤");
  const docs = [
    atk("T1190", ["initial-access"], true),
    atk("T1078", ["initial-access", "persistence", "defense-evasion"]),
    atk("T1214", ["credential-access"]),
    { id: 9, title: "CVE-2026-1 x", content: "c", source_url: "u", category: "cve", similarity: 0.6 },
    atk("T9999", undefined),
  ];
  const kept = dropOffTacticDocs("MITRE ATT&CK 初始访问阶段有哪些技术？", docs).map((d) => d.title);
  assert.ok(kept.some((x) => x.startsWith("T1190")) && kept.some((x) => x.startsWith("T1078"))
    && kept.some((x) => x.startsWith("CVE-")) && kept.some((x) => x.startsWith("T9999")),
    `该保留的条目被误删：${kept.join(",")}`);
  assert.ok(!kept.some((x) => x.includes("T1214")), `别的阶段条目应被挡掉：${kept.join(",")}`);
  // 滤空要退回原集合：标注不可靠时宁可给近似资料，也不该把能答的题变成拒答
  assert.equal(dropOffTacticDocs("横向移动阶段有哪些技术？", [atk("T1214", ["credential-access"])]).length, 1,
    "全部被滤掉时应退回原集合");
});

test("chat：mode=on 问某阶段技术时不得列入别的阶段的技术", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat("MITRE ATT&CK 初始访问阶段有哪些技术？", { mode: "on" });
  const a = String(d.answer);
  assert.ok(!/T1214/.test(a), `把 credential-access 的 T1214 列进初始访问：${a.slice(0, 260)}`);
  assert.ok(!/利用第三方应用/.test(a), `出现资料里没有的编造技术名：${a.slice(0, 260)}`);
  assert.match(a, /T1190|T1566|T1078|T1133|T1195/, `初始访问的常见技术应至少出现一个：${a.slice(0, 260)}`);
});

// 纯函数回归：2026-11-12 实测 mode=on 把 CVE-2026-83542（NVD 里 cisaExploitAdd 为空，不在 KEV）
// 列进了"已被确认在野利用"清单。这里锁住"KEV 证据清单"的计算：只有正文带 KEV 标注的编号才能进清单。
test("kevFacts：在野利用只能引用带 KEV 标注的资料", () => {
  if (!kevFacts) return t_skip();
  const kevDoc = {
    id: 1, title: "CVE-2024-38475: Apache HTTP Server Improper Escaping",
    content: "在野利用（CISA KEV）｜厂商：Apache｜产品：HTTP Server｜KEV 收录：2025-05-01｜修复期限：2025-05-22\n正文…",
    source_url: "u", category: "cve", similarity: 1,
  };
  const plainDoc = {
    id: 2, title: "CVE-2026-83542: Apache OFBiz Code Injection",
    content: "厂商：Apache｜产品：OFBiz｜发布：2026-11-05\n正文…", source_url: "u", category: "cve", similarity: 1,
  };
  const q = "最近有哪些已被确认在野利用的 Apache 产品漏洞？";
  const msg = kevFacts(q, [kevDoc, plainDoc]);
  assert.ok(msg.length, "KEV 类问题应给出证据清单");
  assert.match(msg, /CVE-2024-38475（收录 2025-05-01）/);
  assert.ok(!msg.includes("CVE-2026-83542"), "没有 KEV 标注的编号不得进证据清单");
  assert.match(msg, /禁止把它们列进/);
  assert.match(kevFacts(q, [plainDoc]), /没有任何条目/, "全部无 KEV 标注时应说明清单为空");
  assert.equal(kevFacts("CWE-79 是什么弱点？如何缓解？", [kevDoc]), "", "非 KEV 问题不该插入这段");
});

test("chat：mode=on 不得把未经 KEV 确认的编号说成在野利用", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  const d = await postChat("最近有哪些已被确认在野利用的 Apache 产品漏洞？", { mode: "on" });
  const a = String(d.answer);
  // 逐句判：句子里出现"在野利用/已被利用"级别的断言 + 具体编号，就必须同时给出 KEV 收录日期
  // 例外词得包含否定式写法。2026-11-12 线上实测踩过一次判分误伤：模型写的是
  // "CVE-2026-119618 ……目前尚无公开的在野利用报告，且未进入 CISA KEV 目录，因此不满足'已被确认
  // 在野利用'的条件"——这恰恰是我们要的表述，却因为句子里有"在野利用"四个字被判成违规。
  const bad = a.split(/(?<=[。；;\n])/).filter((s) =>
    /CVE-\d{4}-\d{4,7}/i.test(s) && /在野|已被利用|确认利用|active exploitation/i.test(s)
    && !/20\d\d-\d\d-\d\d/.test(s)
    && !/未经|无法确认|不确定|未见|不属于|尚无|未进入|不在|不满足|没有公开|无公开/.test(s));
  assert.equal(bad.length, 0, `在野利用断言缺少 KEV 日期：${bad.join(" / ").slice(0, 260)}`);
});

function t_skip() { console.warn("  [skip] 本地 Node 不支持直接导入 .ts，跳过纯函数用例"); }

console.log(`SecCopilot 回归测试目标站点：${SITE}${SKIP_LLM ? "（已跳过 LLM 用例）" : ""}`);
