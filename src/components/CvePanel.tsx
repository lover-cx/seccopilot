import { useState } from "react";

interface CveResult {
  id: number;
  cve_id: string;
  title: string;
  content: string;
  severity: string;
  cvss_score: number;
  source_url: string;
  published_date: string;
}

export function CvePanel() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<CveResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);

  const handleSearch = async () => {
    if (!query.trim() || loading) return;

    setLoading(true);
    setSearched(true);

    try {
      const res = await fetch(`/functions/v1/app?action=cve&q=${encodeURIComponent(query.trim())}`);
      const data = await res.json();
      setResults(data.results || []);
    } catch (error) {
      console.error("CVE search failed:", error);
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  // KEV 行的事实写在 content 首行（RPC 不返回 metadata），解析出来渲染徽标与修复期限，
  // 这样"在野利用"这个最有价值的信号不会被当成普通漏洞描述埋没。
  const kevInfo = (content: string) => {
    if (!content || !content.startsWith("在野利用（CISA KEV）")) return null;
    const line = content.split("\n")[0];
    const g = (label: string) => {
      const m = line.match(new RegExp(label + "：([^｜]+)"));
      return m ? m[1].trim() : "";
    };
    return {
      vendor: g("厂商"), product: g("产品"), added: g("KEV 收录"),
      due: g("修复期限"), ransom: g("勒索软件利用"),
      // 关联弱点单独成行，不在前缀行里
      cwes: (content.match(/关联弱点：([^\n]+)/)?.[1] ?? "")
        .split(/[、,，]/).map((s) => s.trim()).filter((s) => /^CWE-\d+$/.test(s)),
    };
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case "critical": return "bg-red-500 text-white";
      case "high": return "bg-orange-500 text-white";
      case "medium": return "bg-yellow-500 text-black";
      case "low": return "bg-green-500 text-white";
      default: return "bg-gray-500 text-white";
    }
  };

  const getCvssColor = (score: number) => {
    if (score >= 9.0) return "text-red-500";
    if (score >= 7.0) return "text-orange-500";
    if (score >= 4.0) return "text-yellow-500";
    return "text-green-500";
  };

  return (
    <div className="space-y-4">
      {/* Search */}
      <div className="flex gap-2">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSearch()}
          placeholder="搜索 CVE 编号、漏洞名称、受影响产品..."
          className="flex-1 bg-[var(--card)] border border-[var(--border)] rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500"
        />
        <button
          onClick={handleSearch}
          disabled={loading || !query.trim()}
          className="px-6 py-2 bg-blue-500 text-white rounded-lg text-sm font-medium hover:bg-blue-600 disabled:opacity-50 transition-colors"
        >
          {loading ? "搜索中..." : "搜索"}
        </button>
      </div>

      {/* Results */}
      <div className="space-y-3">
        {!searched && (
          <div className="text-center py-12 text-[var(--muted-foreground)]">
            <div className="text-4xl mb-4">🔓</div>
            <p className="text-sm">输入 CVE 编号或关键词搜索漏洞信息</p>
            <p className="text-xs mt-2">示例：CVE-2021-44228、Log4j、Kubernetes</p>
          </div>
        )}

        {searched && results.length === 0 && !loading && (
          <div className="text-center py-12 text-[var(--muted-foreground)]">
            <p className="text-sm">未找到相关漏洞信息</p>
          </div>
        )}

        {results.map((cve) => {
          const kev = kevInfo(cve.content);
          return (
          <div key={cve.id} className="bg-[var(--card)] border border-[var(--border)] rounded-lg p-4 hover:border-blue-500 transition-colors">
            <div className="flex items-start justify-between gap-4 mb-2">
              <div className="flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <a
                    href={cve.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-500 hover:underline font-mono text-sm font-medium"
                  >
                    {cve.cve_id || "未知 CVE"}
                  </a>
                  {cve.severity && (
                    <span className={`px-2 py-0.5 text-xs rounded ${getSeverityColor(cve.severity)}`}>
                      {cve.severity.toUpperCase()}
                    </span>
                  )}
                  {kev && (
                    <span className="px-2 py-0.5 text-xs rounded bg-amber-500 text-white" title="CISA 已知被利用漏洞目录收录">
                      在野利用
                    </span>
                  )}
                </div>
                <h3 className="text-sm font-medium mt-1">{cve.title}</h3>
              </div>
              {cve.cvss_score ? (
                <div className={`text-lg font-bold ${getCvssColor(cve.cvss_score)}`}>
                  {cve.cvss_score.toFixed(1)}
                </div>
              ) : kev ? (
                <div className="text-xs text-[var(--muted-foreground)] text-right leading-tight">
                  KEV<br />条目
                </div>
              ) : null}
            </div>
            <p className="text-xs text-[var(--muted-foreground)] line-clamp-3 mb-2">
              {kev ? cve.content.split("\n").slice(1).join("\n") : cve.content}
            </p>
            {kev && (
              <div className="text-xs text-[var(--muted-foreground)] space-y-1">
                <div>
                  {kev.vendor}{kev.product ? ` / ${kev.product}` : ""}｜CISA 收录：{kev.added}｜修复期限：{kev.due}
                </div>
                {kev.ransom === "Known" && (
                  <div className="text-red-500">已被勒索软件活动利用</div>
                )}
                {kev.cwes.length > 0 && (
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span>关联弱点：</span>
                    {kev.cwes.map((c) => (
                      <a
                        key={c}
                        href={`https://cwe.mitre.org/data/definitions/${c.replace("CWE-", "")}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-purple-500 hover:underline"
                        title="在 CWE 目录中查看该弱点（知识库已收录）"
                      >
                        {c}
                      </a>
                    ))}
                  </div>
                )}
              </div>
            )}
            {cve.published_date && (
              <div className="text-xs text-[var(--muted-foreground)]">
                发布日期：{cve.published_date}
              </div>
            )}
          </div>
          );
        })}
      </div>
    </div>
  );
}
