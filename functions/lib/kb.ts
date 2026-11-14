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
