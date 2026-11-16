import { useState, useEffect } from "react";

interface Stats {
  // null = 这一格没统计到（上游超时/非 200/头里没有 content-range），不是"0 条"。
  // 后端 routes.ts 的 aggregateStats 已经不再把失败兜成 0；这里若继续写 `|| 0`，
  // 屏幕照样显示"0 条"，缺陷 5 就只修了一半（11-14 预检数出来的第四处静默归零）。
  total: number | null;
  categories: Record<string, number | null>;
  degraded?: string[];
}

// 未知就显示未知：把 null/undefined 和真的 0 分开，0 在这里是可信数字。
const fmt = (n: number | null | undefined) => (n === null || n === undefined ? "—" : n.toLocaleString("zh-CN"));

export function StatsPanel() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const res = await fetch("/functions/v1/app?action=stats");
      const data = await res.json();
      if (!res.ok) {
        // 失败不留旧值、也不当成 0：502 表示后端一条都没统计到，其余状态码原样报出来
        setError(res.status === 502
          ? "知识库统计上游不可用（Supabase 未响应），下方数字不代表条目数为 0。"
          : `统计接口异常（HTTP ${res.status}）`);
        setStats(null);
      } else {
        setError(data?.degraded?.length
          ? `部分分类未能统计：${data.degraded.join("、")}（显示为 —，不是 0）`
          : "");
        setStats(data);
      }
    } catch (e) {
      setError("统计请求未能完成，下方数字不代表条目数为 0。");
      console.error("Stats load failed:", e);
    } finally {
      setLoading(false);
    }
  };

  const categoryLabels: Record<string, string> = {
    cve: "CVE 漏洞",
    attack: "ATT&CK 技术",
    cwe: "CWE 弱点",
    paper: "安全论文",
    general: "通用知识",
  };

  const categoryColors: Record<string, string> = {
    cve: "bg-red-500",
    attack: "bg-orange-500",
    cwe: "bg-purple-500",
    paper: "bg-blue-500",
    general: "bg-green-500",
  };

  if (loading) {
    return (
      <div className="text-center py-12 text-[var(--muted-foreground)]">
        加载统计信息...
      </div>
    );
  }

  // 后端整段不可用时 stats 是 null：这时不能把分类格子整个删掉——空列表会被读成"这个库没有分类"，
  // 与"统计不出来"是两回事。按已知分类渲染五格，数字一律 —。
  const rows: [string, number | null][] = stats
    ? Object.entries(stats.categories)
    : Object.keys(categoryLabels).map((k) => [k, null] as [string, number | null]);

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-amber-50 border border-amber-300 text-amber-900 rounded-lg p-4 text-sm">
          {error}
        </div>
      )}
      {/* Overview */}
      <div className="bg-[var(--card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-bold mb-4">知识库概览</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-3xl font-bold text-blue-500">{fmt(stats?.total)}</div>
            <div className="text-xs text-[var(--muted-foreground)] mt-1">总条目数</div>
          </div>
          {rows.map(([key, count]) => (
            <div key={key} className="text-center">
              <div className="text-3xl font-bold text-[var(--foreground)]">{fmt(count)}</div>
              <div className="text-xs text-[var(--muted-foreground)] mt-1">
                {categoryLabels[key] || key}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Category Breakdown */}
      <div className="bg-[var(--card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-bold mb-4">分类详情</h2>
        <div className="space-y-3">
          {rows.map(([key, count]) => {
            // total 或该分类未知时不算百分比：`null / number` 与 `number / null` 都会变成 NaN%，
            // 而 NaN 会让进度条 style.width 变成 "NaN%"，等于把一次上游超时画成一条奇怪的实线。
            const known = typeof count === "number" && typeof stats?.total === "number" && stats.total > 0;
            const percentage = known ? (count! / stats!.total!) * 100 : 0;
            return (
              <div key={key}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium">{categoryLabels[key] || key}</span>
                  <span className="text-xs text-[var(--muted-foreground)]">
                    {fmt(count)}{known ? ` (${percentage.toFixed(1)}%)` : ""}
                  </span>
                </div>
                <div className="h-2 bg-[var(--surface)] rounded-full overflow-hidden">
                  <div
                    className={`h-full ${categoryColors[key] || "bg-gray-500"} transition-all`}
                    style={{ width: `${known ? percentage : 0}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Data Sources */}
      <div className="bg-[var(--card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-bold mb-4">数据来源</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="p-4 bg-[var(--surface)] rounded-lg">
            <div className="font-medium text-sm mb-1">NVD - 国家漏洞数据库</div>
            <div className="text-xs text-[var(--muted-foreground)]">
              https://nvd.nist.gov/
            </div>
          </div>
          <div className="p-4 bg-[var(--surface)] rounded-lg">
            <div className="font-medium text-sm mb-1">MITRE ATT&CK</div>
            <div className="text-xs text-[var(--muted-foreground)]">
              https://attack.mitre.org/
            </div>
          </div>
          <div className="p-4 bg-[var(--surface)] rounded-lg">
            <div className="font-medium text-sm mb-1">CISA KEV 在野利用目录</div>
            <div className="text-xs text-[var(--muted-foreground)]">
              https://www.cisa.gov/known-exploited-vulnerabilities-catalog
            </div>
          </div>
          <div className="p-4 bg-[var(--surface)] rounded-lg">
            <div className="font-medium text-sm mb-1">MITRE CWE 弱点目录</div>
            <div className="text-xs text-[var(--muted-foreground)]">
              https://cwe.mitre.org/data/definitions/
            </div>
          </div>
          <div className="p-4 bg-[var(--surface)] rounded-lg">
            <div className="font-medium text-sm mb-1">arXiv cs.CR</div>
            <div className="text-xs text-[var(--muted-foreground)]">
              https://arxiv.org/list/cs.CR/recent
            </div>
          </div>
          <div className="p-4 bg-[var(--surface)] rounded-lg">
            <div className="font-medium text-sm mb-1">联网检索（时效性问题）</div>
            <div className="text-xs text-[var(--muted-foreground)]">
              本地未覆盖或涉及时效时启用，来源标注"未经知识库校验"
            </div>
          </div>
        </div>
      </div>

      {/* About */}
      <div className="bg-[var(--card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-bold mb-4">关于 SecCopilot</h2>
        <div className="text-sm text-[var(--muted-foreground)] space-y-2">
          <p>
            SecCopilot 是面向安全研究者的 AI 智能助手，知识来源分三层：本地精编知识库（ATT&CK 技术、CISA KEV 在野利用漏洞、CWE 弱点、arXiv 安全论文），
            冷门 CVE 现查 NVD 官方 API，以及涉及时效问题时的联网检索。
          </p>
          <p>
            本项目使用 Qoder 开发，部署于 Qoder Sites，采用 RAG（检索增强生成）技术：向量检索定位权威条目，大语言模型仅依据检索到的资料作答，
            每条回答都区分标注"知识库来源"与"网络来源"，网络结果未经知识库校验时明确提示，避免把社区博客当作权威结论。
          </p>
        </div>
      </div>
    </div>
  );
}
