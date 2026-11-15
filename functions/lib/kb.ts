// 知识来源层 1/2：本地精编知识库（Supabase pgvector + RPC）与实时上游 API（NVD）
// 每个函数只负责一种检索方式，拼装策略在 lib/chat.ts。

export interface Doc {
  id: number | string | null;
  title: string;
  content: string;
  source_url: string;
  category: string;
  similarity: number;
  live?: boolean; // true = 本次现查上游 API，不在本地知识库内
  anchor?: boolean; // true = 编号/战术精确命中，权威锚点；语义命中不算锚点
  // ATT&CK 条目的所属阶段（库内 metadata.tactic / tactics 都带）。
  // 问"某阶段有哪些技术"时阶段是硬约束，必须由代码判断，不能留给模型自己归类。
  tactic?: string;
  tactics?: string[];
}

export interface Backend {
  url: string;
  h: Record<string, string>;
}

async function rpcRaw(b: Backend, fn: string, args: Record<string, unknown>, timeoutMs = 8000): Promise<any[]> {
  try {
    const r = await fetch(`${b.url}/rest/v1/rpc/${fn}`, {
      method: "POST", headers: b.h, body: JSON.stringify(args), signal: AbortSignal.timeout(timeoutMs),
    });
    if (!r.ok) return [];
    const d = await r.json();
    return Array.isArray(d) ? d as any[] : [];
  } catch { return []; }
}

export const rpcRows = rpcRaw;

// CVE 面板需要完整字段（cve_id / severity / cvss_score / published_date），直接透传 RPC 结果
export async function cveRows(b: Backend, text: string, limit = 10): Promise<any[]> {
  return await rpcRaw(b, "search_cves", { query_text: text, limit_count: limit });
}

const clip = (s: unknown, n: number) => String(s ?? "").replace(/\s+/g, " ").trim().slice(0, n);

// ── 向量检索（语义）──────────────────────────────────────────────────────────
export async function vector(b: Backend, embedding: number[], category: string | null, count = 5): Promise<Doc[]> {
  const rows = await rpcRaw(b, "match_documents", {
    query_embedding: embedding, match_count: count, category_filter: category ?? null,
  });
  return rows.map((m: any) => ({
    id: m.id, title: m.title ?? "", content: m.content ?? "",
    source_url: m.source_url ?? "", category: m.category ?? "general",
    similarity: Number(m.similarity) || 0,
    tactic: m.metadata?.tactic ?? undefined, tactics: tacticsOf(m.metadata),
  }));
}

// 库内 ATT&CK 条目的阶段标注：tactics 是权威数组（一个技术可跨多个阶段），tactic 是主阶段
export const tacticsOf = (meta: any): string[] | undefined => {
  const list = Array.isArray(meta?.tactics) ? meta.tactics : (meta?.tactic ? [meta.tactic] : []);
  return list.length ? list.map((s: unknown) => String(s).toLowerCase()) : undefined;
};

// ── 编号精确检索：向量对 "T1059" / "CVE-2021-44228" 这类短编号不稳定 ──────────
export async function byTechnique(b: Backend, tid: string, limit = 4): Promise<Doc[]> {
  const hits = await rpcRaw(b, "search_attacks", { p_tactic: null, p_technique_id: tid, limit_count: 8 });
  // 主技术（id 完全相等）排在子技术前，避免模型只看到子技术就误判父技术名称
  hits.sort((a: any, b2: any) =>
    Number(b2.technique_id === tid) - Number(a.technique_id === tid)
    || String(a.technique_id).localeCompare(String(b2.technique_id)));
  return hits.slice(0, limit).map((a: any) => ({
    id: a.id,
    title: `${a.technique_id} ${a.technique_name}`,
    content: [a.description, a.detection && `检测：${a.detection}`, a.mitigation && `缓解：${a.mitigation}`]
      .filter(Boolean).join("\n"),
    source_url: a.source_url ?? "", category: "attack", similarity: 1, anchor: true,
    tactic: a.tactic ?? undefined, tactics: tacticsOf({ tactics: a.tactics, tactic: a.tactic }),
  }));
}

export async function byTactic(b: Backend, tactic: string, limit = 3): Promise<Doc[]> {
  const hits = await rpcRaw(b, "search_attacks", { p_tactic: tactic, p_technique_id: null, limit_count: 20 });
  hits.sort((a: any, b2: any) =>
    Number(!String(b2.technique_id).includes(".")) - Number(!String(a.technique_id).includes("."))
    || String(a.technique_id).localeCompare(String(b2.technique_id)));
  return hits.slice(0, limit).map((a: any) => ({
    id: a.id, title: `${a.technique_id} ${a.technique_name}`,
    content: a.description ?? "", source_url: a.source_url ?? "", category: "attack", similarity: 1, anchor: true,
    tactic: a.tactic ?? undefined, tactics: tacticsOf({ tactics: a.tactics, tactic: a.tactic }),
  }));
}

export async function byCve(b: Backend, text: string, limit = 2): Promise<Doc[]> {
  const hits = await rpcRaw(b, "search_cves", { query_text: text, limit_count: Math.max(limit, 3) });
  return hits.slice(0, limit).map((c: any) => ({
    id: c.id, title: c.title ?? c.cve_id ?? "", content: c.content ?? "",
    source_url: c.source_url ?? "", category: "cve", similarity: 1, anchor: true,
  }));
}

// ── 编号精确检索：CWE / arXiv ────────────────────────────────────────────────
// 语义检索对 "CWE-79" 这类短编号完全不靠谱：实测问 "CWE-79 是什么弱点" 时，
// top1 是相似度 0.691 的 CWE-829，正确条目根本排不进来（中文问题 vs 英文标题，
// 相似度天花板本来就低）。因此凡问题里出现明确编号，一律走 JSONB 精确过滤。
async function selectDocs(b: Backend, params: string, limit: number): Promise<Doc[]> {
  try {
    const r = await fetch(`${b.url}/rest/v1/knowledge_base?select=id,title,content,source_url,category&limit=${limit}&${params}`,
      { headers: b.h, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    return ((await r.json()) as any[]).map((x: any) => ({
      id: x.id, title: x.title ?? "", content: x.content ?? "",
      source_url: x.source_url ?? "", category: x.category ?? "general", similarity: 1, anchor: true,
    }));
  } catch { return []; }
}

export const byCwe = (b: Backend, cweId: string, limit = 2): Promise<Doc[]> =>
  selectDocs(b, `category=eq.cwe&${encodeURIComponent("metadata->>cwe_id")}=eq.${cweId}`, limit);

export const byArxiv = (b: Backend, paperId: string, limit = 2): Promise<Doc[]> =>
  selectDocs(b, `category=eq.paper&${encodeURIComponent("metadata->>arxiv_id")}=like.${paperId}*`, limit);

// ── 关键词兜底：向量索引偶发返回空时仍保证有出处 ─────────────────────────────
export async function keyword(b: Backend, question: string, limit = 5): Promise<Doc[]> {
  const tokens = (question.match(/[A-Za-z][A-Za-z0-9.\-]{2,15}|[一-龥]{2,8}/g) ?? [])
    .filter((t: string) => !/[,()]/.test(t)).slice(0, 4);
  if (!tokens.length) return [];
  const or = tokens.flatMap((t: string) => [`title.ilike.*${t}*`, `content.ilike.*${t}*`]).join(",");
  try {
    const r = await fetch(`${b.url}/rest/v1/knowledge_base?select=id,title,content,source_url,category,metadata&limit=${limit}&or=(${encodeURIComponent(or)})`,
      { headers: b.h, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    return ((await r.json()) as any[]).map((x: any) => ({
      id: x.id, title: x.title ?? "", content: x.content ?? "",
      source_url: x.source_url ?? "", category: x.category ?? "general", similarity: 0.3,
      tactic: x.metadata?.tactic ?? undefined, tactics: tacticsOf(x.metadata),
    }));
  } catch { return []; }
}

// ── 第 2 层：NVD 实时上游（本地库未覆盖的 CVE，现查不落库）────────────────────
// NVD 无 key 时限流约 5 请求/30 秒，因此只在问题中出现 CVE 编号且本地未命中时调用。
export async function nvdLive(question: string, limit = 3): Promise<Doc[]> {
  const ids = (question.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).slice(0, limit);
  const out: Doc[] = [];
  for (const id of ids) {
    try {
      const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`,
        { signal: AbortSignal.timeout(9000) });
      if (!r.ok) continue;
      const d = await r.json();
      const c = d?.vulnerabilities?.[0]?.cve;
      if (!c) continue;
      const desc = (c.descriptions ?? []).find((x: any) => x.lang === "en")?.value ?? "";
      const m = c.metrics ?? {};
      const cvss = m.cvssMetricV31?.[0]?.cvssData ?? m.cvssMetricV30?.[0]?.cvssData ?? m.cvssMetricV2?.[0]?.cvssData ?? {};
      out.push({
        id: `nvd:${c.id}`,
        title: `${c.id}: ${clip(desc, 90)}`,
        content: [
          clip(desc, 700),
          cvss.baseScore && `CVSS ${cvss.baseScore} (${cvss.severity ?? "-"})`,
          c.vulnCitations?.[0]?.url && `参考：${c.vulnCitations[0].url}`,
        ].filter(Boolean).join("\n"),
        source_url: `https://nvd.nist.gov/vuln/detail/${c.id}`,
        category: "cve", similarity: 1, anchor: true, live: true,
      });
    } catch { continue; }
  }
  return out;
}

// ── 第 2 层：CISA KEV 现查目录（"在野利用"是有门槛的断言，本地快照会过期）──────
// 实测 2026-11-14：本地 KEV 快照是 2026.11.09，而目录已是 2026.11.13、1781 条，
// 按 dateAdded 落在 2026 年的微软 Office 有 5 条（2009-0556、21509、21514、2009-0238、124194），
// 按 CVE 编号年份算是 3 条（21509、21514、124194）——最后一条 11-10 才新增、本地库没有。两个口径都要写，只写一个必然引起矛盾。
// 目录只有一个 URL、无鉴权、约 1.8 MB，因此按 isolate 缓存 6 小时；拉不到时返回 null，
// 让上层说"本地快照 vX 未收录"而不是"KEV 未收录"——把"没查到"说成"不存在"是本项目明令禁止的。
export const KEV_SNAPSHOT_VERSION = "2026.11.09";
const KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const KEV_TTL_MS = 6 * 60 * 60 * 1000;

export interface KevEntry {
  cveID: string; vendorProject: string; product: string; vulnerabilityName: string;
  dateAdded: string; dueDate: string; requiredAction: string;
}

let kevCache: { at: number; map: Map<string, KevEntry> } | null = null;

export async function kevCatalog(force = false): Promise<Map<string, KevEntry> | null> {
  if (!force && kevCache && Date.now() - kevCache.at < KEV_TTL_MS) return kevCache.map;
  try {
    const r = await fetch(KEV_FEED, { signal: AbortSignal.timeout(12000) });
    if (!r.ok) return null;
    const d = await r.json();
    const list = d?.vulnerabilities;
    if (!Array.isArray(list) || !d?.catalogVersion) return null; // 结构异常 ≠ 空目录
    const map = new Map<string, KevEntry>();
    for (const v of list) {
      if (!v?.cveID) continue;
      map.set(String(v.cveID).toUpperCase(), {
        cveID: String(v.cveID).toUpperCase(),
        vendorProject: v.vendorProject ?? "", product: v.product ?? "",
        vulnerabilityName: v.vulnerabilityName ?? "",
        dateAdded: v.dateAdded ?? "", dueDate: v.dueDate ?? "",
        requiredAction: v.requiredAction ?? "",
      });
    }
    kevCache = { at: Date.now(), map };
    return map;
  } catch { return null; }
}

/** 纯函数：目录条目 → 本地库同款正文前缀，使 kevFacts() 的 KEV_MARK_RE 直接可用。 */
export function kevDocs(entries: KevEntry[]): Doc[] {
  return entries
    .filter((e) => e.cveID && e.dateAdded)
    .map((e) => ({
      id: `kev:${e.cveID}`,
      title: `${e.cveID}: ${clip(e.vulnerabilityName, 90)}`,
      content: `在野利用（CISA KEV）｜厂商：${e.vendorProject}｜产品：${e.product}`
        + `｜KEV 收录：${e.dateAdded}｜修复期限：${e.dueDate}\n`
        + `漏洞名：${e.vulnerabilityName}\n处置要求：${clip(e.requiredAction, 200)}`,
      source_url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?selected_cve=${e.cveID}`,
      category: "cve", similarity: 1, anchor: true, live: true,
    }));
}

/** 按编号取目录条目 → Doc（映射只写在 kevDocs 一处，这里只做筛选）。 */
export function kevFromCatalog(entries: KevEntry[], ids: string[]): Doc[] {
  const want = new Set(ids.map((x) => x.toUpperCase()));
  return kevDocs(entries.filter((e) => want.has(e.cveID.toUpperCase())));
}

// "来源词"不是产品词：不排除的话，任何提 CISA/KEV 的问题都会把这些词当产品拿去子串匹配。
const KEV_STOP_TOKENS = new Set(["cisa", "kev", "cve", "nvd", "cvss", "stix", "mitre", "api", "kb"]);
// 中文厂商别名 → 目录里的英文写法。只放实测/高频会出现在中文问题里的厂商，不做通用翻译。
const KEV_VENDOR_ALIAS: Record<string, string> = {
  "微软": "microsoft", "苹果": "apple", "谷歌": "google", "安卓": "android",
  "甲骨文": "oracle", "思科": "cisco", "飞塔": "fortinet", "帕洛阿尔托": "palo alto",
};

/**
 * 纯函数：不依赖问题里出现 CVE 编号，也能从目录里捞出"这个厂商/产品"的在野利用条目。
 * 存在的理由写在第 9 条缺陷里：旗标题真实失败那次是语义检索空集 → keyword() 兜底不相干条目，
 * 那次没有编号可查，只有 id 入口的目录层在最需要它的路径上不会被触发。
 * 匹配口径：问题里的 ASCII 词（去掉来源词）+ 中文厂商别名合成 terms；用目录自己的 vendorProject 取值把 terms 分成
 * 产品词与厂商词，**只有产品词命中 product 才算产品级命中**；问题里出现 20xx 时按 dateAdded 前缀收窄；倒序取前 12 条。
 * **最具体信号优先**：有产品级命中时只保留它们，否则退回厂商/名称匹配。这条不是风格问题，是真目录实测出来的两件事：
 * 三字段 OR 时"微软 Office + 2026"命中 42 条、截 12 后 21509 与 21514 双双被挤掉；而目录里 CVE-2026-42897 的
 * product 与 vendorProject 都写 "Microsoft"，把厂商词当产品词就会让它冒充产品命中、把 5 条变成 6 条。
 * 一个词都没命中时返回空数组——绝不允许"没匹配到就把整个目录塞进上下文"。
 */
export function kevScopeMatches(question: string, entries: Iterable<KevEntry>): KevEntry[] {
  const raw = String(question ?? "");
  const ascii = (raw.match(/[A-Za-z][A-Za-z0-9.\-/]{2,24}/g) ?? [])
    .map((s) => s.toLowerCase()).filter((s) => !KEV_STOP_TOKENS.has(s));
  const alias = Object.entries(KEV_VENDOR_ALIAS)
    .filter(([zh, en]) => en && raw.includes(zh)).map(([, en]) => en.toLowerCase());
  const terms = [...new Set([...ascii, ...alias])];
  if (!terms.length) return [];
  const year = (raw.match(/20\d{2}/) ?? [])[0] ?? null;
  const list = [...entries];
  // 厂商词表不另起一张表：目录里 vendorProject 出现过什么，什么就是厂商词（实测 295 个不同取值）。
  const vendorWords = new Set(list.map((e) => String(e.vendorProject ?? "").toLowerCase().trim()));
  const productTerms = terms.filter((t) => !vendorWords.has(t));
  // 逐条分别记录"产品级命中"与"厂商/名称命中"：产品是更具体的信号，需要按字段分开才知道该不该收窄。
  const hit = list.map((e) => {
    const prod = String(e.product ?? "").toLowerCase();
    const vend = String(e.vendorProject ?? "").toLowerCase();
    const name = String(e.vulnerabilityName ?? "").toLowerCase();
    return { e, byProduct: productTerms.some((t) => prod.includes(t)), byVendor: terms.some((t) => vend.includes(t) || name.includes(t)) };
  }).filter((h) => h.byProduct || h.byVendor);
  const scoped = hit.some((h) => h.byProduct) ? hit.filter((h) => h.byProduct) : hit;
  return scoped
    .map((h) => h.e)
    .filter((e) => !year || String(e.dateAdded ?? "").startsWith(year))
    .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)))
    .slice(0, 12);
}

/** 按编号现查：confirmed=目录里有（带日期），absent=目录里确实没有，unavailable=目录没拉到。 */
export async function kevLookup(ids: string[]): Promise<{ confirmed: KevEntry[]; absent: string[]; unavailable: boolean }> {
  const uniq = [...new Set(ids.map((x) => x.toUpperCase()))];
  if (!uniq.length) return { confirmed: [], absent: [], unavailable: false };
  const map = await kevCatalog();
  if (!map) return { confirmed: [], absent: [], unavailable: true };
  const confirmed: KevEntry[] = [];
  const absent: string[] = [];
  for (const id of uniq) {
    const e = map.get(id);
    if (e) confirmed.push(e); else absent.push(id);
  }
  return { confirmed, absent, unavailable: false };
}
