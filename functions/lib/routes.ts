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
// 关键约定：某一类没取到就是 null，不是 0。0 会被读成"这一类没有数据"，
// 而真实情况是上游超时/非 200——把失败说成 0 是我们记在清单里的第 ① 类根因（缺陷 5）。
// 11-16 本机实测过两种畸形：连打 5 次得到一次 `total:0` 而 categories 求和 5397（total 那次失败），
// 以及全量套件里分类求和 4530 ≠ total 5397（attack 那次失败，差值正好 867）。
// 静默归零一共有四处（routes.ts 的 catch、content-range 解析失败、!b.url 的 200+全 0、
// 前端 StatsPanel 的 `|| 0`），本文件负责前三处，第四处必须跟着改否则屏幕上仍是"0 条"。
export interface StatsData {
  total: number | null;
  categories: Record<string, number | null>;
  degraded: string[];
}

export function aggregateStats(
  total: number | null, per: (number | null)[], failed: string[],
): { status: number; data: StatsData | { error: string } } {
  const categories: Record<string, number | null> = {};
  CATEGORIES.forEach((c, i) => { categories[c] = per[i] ?? null; });
  const degraded = [...failed];
  // 只有"total 和每一个分类都不知道"才等于上游不可用；只缺 total（或只缺某一类）仍是 200 + null，
  // 因为那时页面上其余数字依然可信。判据写成 `total === null` 会让一次瞬时超时把整页打回 502。
  const allDown = total === null && CATEGORIES.every((_, i) => (per[i] ?? null) === null);
  if (allDown) return { status: 502, data: { error: "upstream_unavailable" } };
  return { status: 200, data: { total, categories, degraded } };
}

export async function stats(b: Backend): Promise<EndpointResult> {
  // 不再为 !b.url 单开一条"200 + 全 0"的捷径：Secret 没配上与上游全挂是同一件事——全部未知，
  // 走 aggregateStats 得到 502。原代码在这里返回 200 + 全 0，正是缺陷本体。
  if (!b.url) {
    return aggregateStats(null, CATEGORIES.map(() => null), ["total", ...CATEGORIES]);
  }
  const count = async (where: string | null): Promise<number | null> => {
    const q = where ? `&${where}` : "";
    try {
      const r = await fetch(`${b.url}/rest/v1/knowledge_base?select=id&limit=0${q}`, {
        headers: { ...b.h, Prefer: "count=exact" }, signal: AbortSignal.timeout(8000),
      });
      // 非 200（401/404/5xx）同样是"不知道"，不得从 content-range 里蒙一个数或当 0
      if (!r.ok) return null;
      const m = (r.headers.get("content-range") ?? "").match(/\/(\d+)$/);
      return m ? Number(m[1]) : null;   // 解析不出来同样是"不知道"，不是 0
    } catch { return null; }
  };
  const res = await Promise.all([count(null), ...CATEGORIES.map((c) => count(`category=eq.${c}`))]);
  const failed: string[] = [];
  if (res[0] === null) failed.push("total");
  CATEGORIES.forEach((c, i) => { if (res[i + 1] === null) failed.push(c); });
  return aggregateStats(res[0], res.slice(1), failed);
}

// 同类歧义仍在 cve / attack 两个端点（本文件 :72 与 :86 的 `!b.url` 返回 200 + results: []，
// 把"后端没配"说成"检索到 0 条"），#25 只管 stats，本轮未修，记在作品帖缺陷清单里。

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
