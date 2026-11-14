// chat 编排：本地精编库 → （不足或时效问题时）实时上游 → 联网检索，最后统一生成
// 三层来源各自保留自己的引用命名，前端分组展示，避免"把博客当权威"的问题。

import { embed, generate } from "./dashscope.ts";
import type { WebSource } from "./dashscope.ts";
import { byArxiv, byCve, byCwe, byTactic, byTechnique, keyword, nvdLive, vector } from "./kb.ts";
import type { Backend, Doc } from "./kb.ts";

export type Mode = "auto" | "on" | "off";

// 前端引用列表用的精简结构：不回传正文，避免把整段知识塞进响应体
export interface SourceRef {
  title: string;
  url: string;
  category: string;
  similarity: number;
  live: boolean; // true = 本次实时查询上游官方库（NVD），不在本地知识库内
}

export interface ChatPayload {
  answer: string;
  sources: SourceRef[];
  web_sources: WebSource[];
  search_used: boolean;
  mode: Mode;
  coverage: "local" | "mixed" | "web";
  note: string;
}

// 问题里点到某个战术（中文或英文）时，直接按战术取权威条目，避免向量检索跑偏
const TACTIC_HINTS: string[][] = [
  ["初始访问|initial access", "Initial Access"],
  ["侦察|reconnaissance", "Reconnaissance"],
  ["资源开发|resource development", "Resource Development"],
  ["命令执行|脚本执行|执行阶段|\\bexecution\\b", "Execution"],
  ["持久化|持久性|\\bpersistence\\b", "Persistence"],
  ["权限提升|提权|privilege escalation", "Privilege Escalation"],
  ["防御规避|防御削弱|defense evasion", "Defense Evasion"],
  ["凭据访问|凭证访问|credential access", "Credential Access"],
  ["系统发现|信息发现|\\bdiscovery\\b", "Discovery"],
  ["横向移动|lateral movement", "Lateral Movement"],
  ["收集阶段|\\bcollection\\b", "Collection"],
  ["命令与控制|指挥与控制|command and control", "Command and Control"],
  ["渗出|exfiltration", "Exfiltration"],
  ["破坏|\\bimpact\\b", "Impact"],
];

const TIME_HINTS = /最新|最近|今年|本周|本月|目前|当前|刚披露|新披露|刚刚|近期|20(2[5-9])-| Poc|POC|在野|已利用|exploited/i;const NOW_YEAR = new Date().getUTCFullYear();

export const normalizeMode = (m: unknown): Mode => (m === "on" || m === "off" ? m as Mode : "auto");

// 时效性判定：显式时效词，或问题中出现 CVE 编号且年份 ≥ 当前年（本地库不可能有当年的新条目）
function isTimeSensitive(question: string): boolean {
  if (TIME_HINTS.test(question)) return true;
  const years = (question.match(/\bCVE-(\d{4})-/gi) ?? []).map((s: string) => Number(s.slice(4, 8)));
  return years.some((y: number) => y >= NOW_YEAR);
}

// 本地命中充分判定（可复现，不靠模型自觉）。
// 不能只看"最高相似度"：2026-11-10 用 11 个问题实测 top1 相似度，
//   库内问题 0.576 / 0.646 / 0.686 / 0.722
//   库外问题 0.571（WiFi 密码忘了）/ 0.573（问内部仓库地址）/ 0.630（不存在的 CVE-9999-0000）
// 两个区间完全重叠，任何单一阈值都会同时误伤两头——多语言向量对"话题相近"和"真正命中"
// 本来就分不开。所以只认两种可靠信号：编号/战术精确命中（anchor），或高到不像巧合的语义分。
const SEMANTIC_FLOOR = 0.65;

function isLocalSufficient(docs: Doc[]): boolean {
  if (docs.some((d) => d.anchor)) return true;
  const best = docs.reduce((mx, d) => Math.max(mx, d.similarity), 0);
  return docs.length >= 3 && best >= SEMANTIC_FLOOR;
}

function dedupe(docs: Doc[]): Doc[] {
  const seen = new Set<string>();
  const out: Doc[] = [];
  for (const d of docs) {
    const k = `${d.category}|${d.id ?? d.title}|${d.title}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(d);
  }
  return out;
}

// 问题点名的 ATT&CK 阶段（slug），没点名返回 null。与 TACTIC_HINTS 共用一张表，避免两处措辞漂移。
export function requestedTactic(question: string): string | null {
  for (const [pattern, name] of TACTIC_HINTS) {
    if (new RegExp(pattern, "i").test(question)) return name.toLowerCase().replace(/\s+/g, "-");
  }
  return null;
}

// 2026-11-12 线上实测（mode=on，问"初始访问阶段有哪些技术"）：回答把 T1214 列进初始访问，
// 还给起名"利用第三方应用"。T1214 在本地库里是 credential-access（上游 ATT&CK 已撤销该技术），
// 是语义检索顺手捞进来的近似条目。"某阶段有哪些技术"里，阶段是硬约束，不能交给模型自觉：
// 带阶段标注、且阶段不符的语义条目直接不进上下文。
// 边界：① 只动非锚点的 attack 条目——byTactic 精确取回的就是该阶段条目，用户自己写了编号的
// 也按编号处理，都不该被这段删掉；② 条目没有阶段标注时保留，宁可多给资料不可误删；
// ③ 全被滤空则退回原集合（说明标注不可靠），拒答不是这里的目标。
export function dropOffTacticDocs(question: string, docs: Doc[]): Doc[] {
  const want = requestedTactic(question);
  if (!want) return docs;
  const kept = docs.filter((d) => {
    if (d.anchor || d.category !== "attack") return true;
    const list = (d.tactics?.length ? d.tactics : d.tactic ? [d.tactic] : []).map((s) => s.toLowerCase());
    if (!list.length) return true;
    return list.includes(want);
  });
  return kept.length ? kept : docs;
}

async function collectLocal(b: Backend, question: string, embedding: number[] | null, category: string | null): Promise<Doc[]> {
  // 精确编号优先（相似度记为 1），其后是语义命中，最后关键词兜底
  const exact: Doc[] = [];
  for (const tid of (question.match(/\bT\d{4}(?:\.\d{3})?\b/g) ?? []).slice(0, 2)) {
    exact.push(...await byTechnique(b, tid));
  }
  const cveIds = (question.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).slice(0, 2);
  for (const cid of cveIds) exact.push(...await byCve(b, cid));
  // CWE 编号必须精确取：语义检索在 "CWE-79 是什么弱点" 上会把 CWE-829 排到第一
  for (const wid of (question.match(/\bCWE-\d{1,4}\b/gi) ?? []).slice(0, 3)) {
    exact.push(...await byCwe(b, wid.toUpperCase()));
  }
  for (const aid of (question.match(/\b\d{4}\.\d{4,5}\b/g) ?? []).slice(0, 2)) {
    exact.push(...await byArxiv(b, aid));
  }
  for (const [pattern, tactic] of TACTIC_HINTS) {
    if (!new RegExp(pattern, "i").test(question)) continue;
    exact.push(...await byTactic(b, tactic));
    break; // 只取第一个命中的战术，避免来源被单一战术条目刷屏
  }

  const semantic = embedding ? await vector(b, embedding, category) : [];
  // 阶段过滤放在 slice 之前：挡掉别的路径是为了给本阶段的条目腾位置，不是为了缩短上下文
  let docs = dropOffTacticDocs(question, dedupe([...exact, ...semantic])).slice(0, 6);

  if (!docs.length) docs = dropOffTacticDocs(question, dedupe(await keyword(b, question))).slice(0, 5);

  // 第 2 层：本地库没有这个 CVE 编号时，现查 NVD（只查编号，控制上游限流风险）
  if (cveIds.length && !docs.some((d) => d.title.toUpperCase().includes(cveIds[0].toUpperCase()))) {
    docs = [...docs, ...await nvdLive(cveIds[0])].slice(0, 6);
  }
  return dropOffTacticDocs(question, docs);
}

const toSource = (d: Doc, i: number) => ({
  title: d.title || d.source_url || `来源 ${i + 1}`,
  url: d.source_url || "",
  category: d.category,
  similarity: Math.round(d.similarity * 100) / 100,
  live: d.live === true,
});

export interface ChatOutcome {
  status: number;
  body: ChatPayload;
}

// 模型不知道自己身处何年：实测 off 模式回答"本周有没有新漏洞"时写过"当前为 2024 年 4 月"。
// 时间限定词必须有基准，所以在 Function 侧按北京时间算出当天日期，注入 system。
function beijingToday(): string {
  try {
    return new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit", day: "2-digit",
    }).format(new Date());
  } catch {
    return new Date().toISOString().slice(0, 10);
  }
}

// mode=off 问时效题时的"全局否定式幻觉"兜底。
// 2026-11-12 实测：只靠提示词规则 7（"资料里没有 ≠ 现实中不存在"）压不住——同一题 4 次
// 采样仍有 1 次答"目前无 2026 年新披露的 Apache Log4j 相关 CVE"，把"本库缺这批条目"说成
// "现实中不存在"。小模型需要的是可照抄的事实，不是抽象禁令，所以这里由代码算出：
// 本地库在该时间窗 + 该主题下的条目数、最近一条日期、距今几天，再要求它照实承认未覆盖。
// 主题词必须全部命中同一条目：本地库有 2026 年的 Apache Tomcat/ActiveMQ，但没有 2026 年的
// Log4j，只按"有没有 2026 年条目"判断会把缺口错误地点亮。
const TOPIC_STOP = /^(cve|cwe|cvss|cisa|kev|mitre|arxiv|nvd|poc|api|id|it|os|the|and|for)$/i;

export function topicTokens(q: string): string[] {
  return [...new Set(
    (q.match(/[A-Za-z][A-Za-z0-9+._-]{2,}/g) ?? [])
      // \d{4} 挡掉 T1059 这类编号；"Log4j" 只有一个数字，必须留下——它正是区分
      // "2026 年的 Apache Tomcat" 和 "2026 年的 Log4j" 的关键主题词。
      .filter((t: string) => !TOPIC_STOP.test(t) && !/\d{4}/.test(t))
      .map((t: string) => t.toLowerCase()),
  )].slice(0, 3);
}

type Window = { kind: "year"; years: number[] } | { kind: "days"; days: number };

// 只对"问题里写死了时间范围"的情形兜底。"最近/最新/目前"这类模糊说法不触发：
// 本地 KEV 目录本身就是近期快照（正文里带 2026.11.09 版本号），按条目自身日期
// 判窗口会把"最近有哪些在野利用漏洞"这种能正常回答的题误伤成拒答。
function requestedWindow(q: string): Window | null {
  if (/本周|这周|这一周|近一周|过去\s*7\s*天|过去一周/.test(q)) return { kind: "days", days: 7 };
  if (/本月|这个月|近一个月|过去\s*30\s*天/.test(q)) return { kind: "days", days: 30 };
  const years = [...new Set((q.match(/\b20\d{2}\b/g) ?? []).map((s: string) => Number(s)))];
  if (years.length) return { kind: "year", years };
  if (/今年|本年/.test(q)) return { kind: "year", years: [NOW_YEAR] };
  return null;
}

const DOC_DATE_RE = /\b20\d{2}-\d{2}-\d{2}\b/g;

export function localTimeGapFacts(question: string, docs: Doc[]): string {
  if (!isTimeSensitive(question)) return "";
  const today = beijingToday();
  const ago = (s: string) => Math.floor(
    (Date.parse(`${today}T00:00:00Z`) - Date.parse(`${s}T00:00:00Z`)) / 86400000);

  const dated = docs.map((d: Doc) => ({
    text: `${d.title} ${d.content}`.toLowerCase(),
    dates: (String(d.content).match(DOC_DATE_RE) ?? []).sort(),
  }));
  const allDates = dated.flatMap((x) => x.dates).sort();
  if (!allDates.length) return "";

  const win = requestedWindow(question);
  if (!win) return "";
  const inWin = (s: string) => win.kind === "year"
    ? win.years.some((y: number) => s.startsWith(String(y)))
    : ago(s) >= 0 && ago(s) <= win.days;
  const tokens = topicTokens(question);
  const topicHit = dated.filter((x) => tokens.every((t: string) => x.text.includes(t)));
  const newestAll = allDates[allDates.length - 1];
  const topicDates = topicHit.flatMap((x) => x.dates).sort();
  const newestTopic = topicDates.length ? topicDates[topicDates.length - 1] : "";

  const winDesc = win.kind === "year" ? `${win.years.join("/")} 年` : `近 ${win.days} 天`;
  if (topicHit.some((x) => x.dates.some(inWin))) return ""; // 本地库确实覆盖该窗口，交给正常流程

  const topicNote = tokens.length
    ? `主题词 ${tokens.join("、")} 全部命中的条目中，最近一条日期为 ${newestTopic || "无（本库没有该主题条目）"}`
    : `本地库最近一条日期为 ${newestAll}`;
  const gapNote = newestTopic && win.kind === "days"
    ? `距今 ${ago(newestTopic)} 天（今日 ${today}）`
    : `今日 ${today}`;
  return `【代码核算的本地收录事实】本次未联网。本地知识库在「${winDesc}」内与该主题同时命中的条目数为 0；${topicNote}，${gapNote}。`
    + "以上只说明本地库的收录情况，不说明现实中不存在该批次。本题结论必须写成"
    + `“本地知识库未覆盖 ${winDesc} ${tokens.length ? "的该主题" : "的新增条目"}，无法确认，需开启联网检索才能确认”，`
    + `禁止输出“目前无/${winDesc}没有新增/不存在相关漏洞”这类全局否定，也不得据此推断编号、修复版本或日期。`;
}

// "在野利用"是有门槛的断言：本库里 KEV 条目的正文固定以「在野利用（CISA KEV）｜…｜KEV 收录：日期」开头，
// 没这段就等于没有 KEV 证据。2026-11-12 实测（mode=on，问"最近有哪些已被确认在野利用的 Apache 产品漏洞"）
// 把 CVE-2026-83542 列进了"已被确认在野利用"清单，而 NVD 的 cisaExploitAdd 为空——编号是真的、
// 描述也对，错在给它加了一个来源没支持的结论。所以这里同样不讲道理，只把证据清单算出来：
// 只有出现在这份清单里（或来源正文明确给出 KEV 收录信息）的编号，才能被说成在野利用。
const KEV_HINT = /在野|KEV|被利用|已利用|exploited|勒索/i;
const KEV_MARK_RE = /在野利用（CISA KEV）/;
const CVE_ID_RE = /\bCVE-\d{4}-\d{4,7}\b/i;

export function kevFacts(question: string, docs: Doc[]): string {
  if (!KEV_HINT.test(question)) return "";
  const listed: string[] = [];
  for (const d of docs) {
    const c = String(d.content);
    if (!KEV_MARK_RE.test(c)) continue;
    const id = (c.match(CVE_ID_RE) ?? String(d.title).match(CVE_ID_RE))?.[0];
    if (!id) continue;
    const date = c.match(/KEV 收录：(20\d\d-\d\d-\d\d)/)?.[1];
    if (!listed.some((s) => s.startsWith(id.toUpperCase()))) listed.push(`${id.toUpperCase()}${date ? `（收录 ${date}）` : ""}`);
  }
  const head = listed.length
    ? `【代码核算的 KEV 证据】本地资料中带“在野利用（CISA KEV）”标注的编号：${listed.join("、")}。`
    : "【代码核算的 KEV 证据】本次提供的本地资料里没有任何条目带“在野利用（CISA KEV）”标注。";
  return head + "判定“在野利用”的唯一依据是资料里给出 CISA KEV 收录信息（收录日期或修复期限）："
    + "未满足这个条件的编号，即使出现在联网检索结果里，也只能说“NVD 已收录，是否在野利用未经 KEV 确认”，"
    + "禁止把它们列进“已被确认在野利用”的清单。";
}

export async function runChat(b: Backend, dashKey: string, rawQuestion: string, category: string | null, mode: Mode): Promise<ChatOutcome> {
  const question = rawQuestion;

  const embedding = await embed(dashKey, question);
  const docs = await collectLocal(b, question, embedding, category);

  const sufficient = isLocalSufficient(docs);
  const wantWeb = mode === "on" || (mode === "auto" && (!sufficient || isTimeSensitive(question)));
  // 不联网时才需要代码兜底：联网了就有实时资料，"缺记录"由搜索结果本身说明
  const gapFacts = wantWeb ? "" : localTimeGapFacts(question, docs);
  // KEV 证据两种模式都要给：把新披露说成在野利用，恰恰发生在联网之后资料变多的时候
  const kevFactsText = kevFacts(question, docs);

  // 阶段标注直接写在资料行上：即使有条目漏过过滤（例如它自己也属于该阶段），模型也得照标注说，
  // 而不是按"看起来像"往用户问的阶段里塞。
  const localBlock = docs.map((d, i) => {
    const stage = d.category === "attack" && (d.tactics?.length || d.tactic)
      ? `\nATT&CK 阶段：${(d.tactics?.length ? d.tactics : [d.tactic]).join(" / ")}`
      : "";
    return `[L${i + 1}] ${d.title}${stage}\n${String(d.content).slice(0, 900)}\n出处：${d.source_url}${d.live ? "（本次实时查询上游官方库）" : ""}`;
  }).join("\n\n");

  const system = [
    "你是 SecCopilot，网络安全研究助手。回答规则：",
    "1) 优先使用【本地知识库资料】，其编号形如 [L1]，引用时写 [L1]；",
    "2) 当提供了联网检索结果时，其角标形如 [1]，引用时保留该角标，并在句末注明“(网络检索)”；",
    // 原来这里不分模式，统一让模型说"知识库与网络检索均未覆盖"。mode=off 根本没联网，
    // 于是线上实测出现过"知识库与网络检索均未覆盖"这种对本系统行为的虚假陈述——改成按模式措辞。
    wantWeb
      ? "3) 两类资料都不足时明确说“知识库与网络检索均未覆盖”，不要编造 CVE 编号、版本号或日期；"
      : "3) 资料不足时只说“本地知识库未覆盖本题，需开启联网检索才能确认”；本次没有联网检索，禁止声称查过网络或全网核实；不要编造 CVE 编号、版本号或日期；",
    "4) 中文、简洁分点，控制在 320 字内，不要输出代码块；",
    "5) 版本号、CVSS 分值、修复版本必须逐字来自资料，不得推断；",
    // 2026-11-12 实测：mode=off 问 Log4j 时把 CVE-2021-45046 的修复版本写成"2.17.1 及以上版本 [L1]"，
    // 而 [L1] 原文只有 "Apply updates per vendor instructions"。版本号碰巧对，但来源没写、角标挂错，
    // 正是本项目要消灭的"引用完整性"问题——用模型记忆补数字再贴上权威角标，比不写更危险。
    "5b) 资料只给出“按厂商说明更新”这类要求而没写具体版本号时，必须照实说“官方未公布具体版本号，仅要求按厂商说明更新”，" +
      "禁止用模型记忆补版本号，也禁止在这种句子上挂 [Lx] 角标；",
    "6) 时间限定词必须逐字对齐：问“本周/最近一周”时，只有资料里给出近 7 天内的日期才能当作本周；" +
      "若资料日期明显更早（如几个月前的收录记录），必须直说“本地知识库中最近一条是 X，无法确认本周新增”，不得把旧条目说成本周。",
    // 2026-11-12 线上实测：mode=off 问"2026 年新披露的 Log4j CVE"时，模型答"目前无 2026 年新披露的
    // Apache Log4j 相关 CVE"——把"本库没有这批条目"说成"现实中不存在"，属于全局否定式幻觉：
    // 用户照着这句话去写报告，就会漏掉真实存在的批次。缺记录 ≠ 不存在，必须显式禁止。
    "7) 资料里没有只等于“本库缺这条记录”，不等于“现实中不存在”：问“有哪些新漏洞/新进展”而资料未覆盖该时间范围时，" +
      "只能说“知识库未覆盖该时间段，无法确认”，禁止输出“目前无/不存在/没有新增/无新增记录”这类结论；",
    // 2026-11-12 实测：问"初始访问阶段有哪些技术"时，回答把本地库标注为 credential-access 的
    // T1214 列进初始访问，还起了个不存在的中文名"利用第三方应用"。阶段过滤已由代码做掉，
    // 这条规则负责剩下的部分：技术名称只能照抄资料，不许按记忆或语感改名。
    "8) ATT&CK 的技术名称与所属阶段一律照资料标注写：资料标注的阶段与用户问的阶段不同，就按资料的那个阶段说明，" +
      "不得挪进用户问的阶段；资料没给的中文名不要自己编，直接用英文原名。",
    "",
    `【今日日期】${beijingToday()}（北京时间）。判断“本周 / 最近 / 今年”一律以此为准，禁止使用训练记忆里的当前年份；` +
      "资料日期不在用户问的时间范围内，就说“未覆盖”，不要将就着答。",
    localBlock ? `【本地知识库资料】\n${localBlock}` : "【本地知识库资料】\n（本次未命中本地知识库）",
    kevFactsText,
    gapFacts,
    // 相关度不够时明确告诉模型"这些资料可能不相关"，否则它会拿着近似条目硬答
    sufficient ? "" : "【相关性提示】下列本地资料与本题只是话题相近，未确认命中权威条目；不足以回答时必须直说“知识库未覆盖”，不得据此推断编号、版本或日期。",
    wantWeb ? "【补充说明】本题已开启联网检索，请综合网络检索结果作答，并区分权威来源与社区内容。" : "",
  ].filter(Boolean).join("\n");

  // 联网检索的 query 由对话内容生成。本地知识库正文一旦进入 user 轮，检索会被旧条目
  // 的编号（如 CVE-2021-44228）带偏，2026 年新漏洞就再也搜不出来——实测过 A/B 两种写法，
  // 把资料放 system、user 轮只留原问题，才拿得到当年 CVE 编号和修复版本。
  const user = question;

  const gen = await generate(dashKey, { system, user, search: wantWeb });

  if (!gen) {
    return {
      status: 503,
      body: {
        answer: "AI 服务暂不可用，请稍后重试。",
        sources: docs.map(toSource), web_sources: [], search_used: false, mode,
        coverage: "local", note: docs.length ? "已检索到本地资料，但生成服务不可用" : "未检索到相关资料",
      },
    };
  }

  const searchUsed = gen.searchUsed;
  const coverage: ChatPayload["coverage"] = !searchUsed ? "local" : docs.length ? "mixed" : "web";
  const note = searchUsed
    ? (sufficient ? "结合本地知识库与网络检索作答；网络来源未经知识库校验" : "本地知识库未有效覆盖本题，回答主要依据网络检索")
    : (sufficient ? "回答基于本地知识库" : "本地知识库未有效覆盖本题，且当前模式不联网；下列来源仅为近似条目，请勿当作权威结论");

  return {
    status: 200,
    body: {
      answer: gen.answer,
      sources: docs.map(toSource),
      web_sources: searchUsed ? gen.web : [],
      search_used: searchUsed,
      mode,
      coverage,
      note,
    },
  };
}

