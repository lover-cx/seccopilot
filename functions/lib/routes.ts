// 只读端点：知识库统计 / CVE 检索 / ATT&CK 浏览
// 与 chat 不同，这三个端点不做生成，纯结构化查询，便于前端直接渲染。

import { cveRows, rpcRows } from "./kb.ts";
import type { Backend } from "./kb.ts";

export interface EndpointResult {
  status: number;
  data: unknown;
}

export const CATEGORIES = ["cve", "attack", "cwe", "paper", "general"];

// ── stats：分类计数（用 Content-Range 头，避免真的把行取回来）─────────────────
export async function stats(b: Backend): Promise<EndpointResult> {
  if (!b.url) return { status: 200, data: { total: 0, categories: Object.fromEntries(CATEGORIES.map((c) => [c, 0])) } };
  const count = async (where: string | null): Promise<number> => {
    const q = where ? `&${where}` : "";
    try {
      const r = await fetch(`${b.url}/rest/v1/knowledge_base?select=id&limit=0${q}`, {
        headers: { ...b.h, Prefer: "count=exact" }, signal: AbortSignal.timeout(8000),
      });
      const m = (r.headers.get("content-range") ?? "").match(/\/(\d+)$/);
      return m ? Number(m[1]) : 0;
    } catch { return 0; }
  };
  const [total, ...per] = await Promise.all([count(null), ...CATEGORIES.map((c) => count(`category=eq.${c}`))]);
  const categories: Record<string, number> = {};
  CATEGORIES.forEach((c, i) => { categories[c] = per[i]; });
  return { status: 200, data: { total, categories } };
}

// ── cve：全文/编号检索 ───────────────────────────────────────────────────────
export async function cve(b: Backend, q: string | null): Promise<EndpointResult> {
  const query = (q ?? "").trim();
  if (!query) return { status: 400, data: { error: "missing_query" } };
  if (!b.url) return { status: 200, data: { results: [] } };
  const results = await cveRows(b, query, 10);
  return { status: 200, data: { results } };
}

// ── attack：战术别名展开 + 技术编号过滤 ──────────────────────────────────────
// 数据用的是 ATT&CK v18+ 的幕僚命名（stealth / defense-impairment），
// 界面沿用大家熟悉的 "Defense Evasion"，这里做一次别名展开并合并结果。
const ALIASES: Record<string, string[]> = {
  "defense-evasion": ["defense-evasion", "stealth", "defense-impairment"],
  "evasion": ["stealth", "defense-impairment"],
};

export async function attack(b: Backend, tactic: string | null, technique: string | null): Promise<EndpointResult> {
  if (!b.url) return { status: 200, data: { results: [] } };
  const key = (tactic ?? "").trim().toLowerCase().replace(/\s+/g, "-");
  const targets = ALIASES[key] ?? [tactic];
  const groups = await Promise.all(
    targets.map((t) => rpcRows(b, "search_attacks", {
      p_tactic: t ?? null, p_technique_id: technique ?? null, limit_count: 20,
    })),
  );
  const seen = new Set<string>();
  const results: any[] = [];
  for (const group of groups.flat()) {
    const id = `${group.technique_id ?? ""}|${group.id ?? ""}`;
    if (seen.has(id)) continue;
    seen.add(id);
    results.push(group);
  }
  results.sort((a, b2) => String(a.technique_id).localeCompare(String(b2.technique_id)));
  return { status: 200, data: { results: results.slice(0, 20) } };
}
