import { useState, useEffect } from "react";

interface AttackResult {
  id: number;
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string;
  detection: string;
  mitigation: string;
  source_url: string;
}

const TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

// Format tactic from "initial-access" to "Initial Access"
function formatTactic(tactic: string): string {
  return tactic
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

// ATT&CK 原文里带 <code>/<a> 等标签，直接当文本渲染会露出一堆标签，这里统一清洗
function stripHtml(text: string): string {
  if (!text) return "";
  return text
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|li)>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function AttackPanel() {
  const [selectedTactic, setSelectedTactic] = useState("");
  const [techniqueQuery, setTechniqueQuery] = useState("");
  const [results, setResults] = useState<AttackResult[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadAttacks();
  }, [selectedTactic]);

  const loadAttacks = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (selectedTactic) params.set("tactic", selectedTactic);
      if (techniqueQuery) params.set("technique", techniqueQuery);

      const res = await fetch(`/functions/v1/app?action=attack&${params.toString()}`);
      const data = await res.json();
      setResults(data.results || []);
    } catch (error) {
      console.error("Attack search failed:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleTechniqueSearch = () => {
    loadAttacks();
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="space-y-3">
        <div>
          <label className="text-xs text-[var(--muted-foreground)] block mb-1">按战术阶段筛选：</label>
          <div className="flex flex-wrap gap-1">
            <button
              onClick={() => setSelectedTactic("")}
              className={`px-3 py-1 text-xs rounded border transition-colors ${
                !selectedTactic
                  ? "bg-blue-500 text-white border-blue-500"
                  : "border-[var(--border)] hover:border-blue-500"
              }`}
            >
              全部
            </button>
            {TACTICS.map((tactic) => (
              <button
                key={tactic}
                onClick={() => setSelectedTactic(tactic)}
                className={`px-3 py-1 text-xs rounded border transition-colors ${
                  selectedTactic === tactic
                    ? "bg-blue-500 text-white border-blue-500"
                    : "border-[var(--border)] hover:border-blue-500"
                }`}
              >
                {tactic}
              </button>
            ))}
          </div>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={techniqueQuery}
            onChange={(e) => setTechniqueQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleTechniqueSearch()}
            placeholder="搜索技术编号，如 T1059..."
            className="flex-1 bg-[var(--card)] border border-[var(--border)] rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={handleTechniqueSearch}
            className="px-4 py-2 bg-blue-500 text-white rounded-lg text-sm hover:bg-blue-600 transition-colors"
          >
            搜索
          </button>
        </div>
      </div>

      {/* Results */}
      <div className="space-y-2">
        {loading && (
          <div className="text-center py-8 text-[var(--muted-foreground)] text-sm">
            加载中...
          </div>
        )}

        {!loading && results.length === 0 && (
          <div className="text-center py-12 text-[var(--muted-foreground)]">
            <div className="text-4xl mb-4">⚔️</div>
            <p className="text-sm">选择战术阶段或输入技术编号查看 ATT&CK 技术详情</p>
          </div>
        )}

        {results.map((attack) => (
          <div key={attack.id} className="bg-[var(--card)] border border-[var(--border)] rounded-lg p-4 hover:border-blue-500 transition-colors">
            <div className="flex items-start justify-between gap-4 mb-2">
              <div className="flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm text-blue-500 font-medium">
                    {attack.technique_id}
                  </span>
                  <span className="px-2 py-0.5 text-xs bg-[var(--surface)] rounded">
                    {formatTactic(attack.tactic)}
                  </span>
                </div>
                <h3 className="text-sm font-medium mt-1">{attack.technique_name}</h3>
              </div>
            </div>
            <p className="text-xs text-[var(--muted-foreground)] line-clamp-2 mb-2 whitespace-pre-line">
              {stripHtml(attack.description)}
            </p>
            {stripHtml(attack.mitigation) && (
              <div className="text-xs">
                <span className="text-green-500 font-medium">缓解措施：</span>
                <span className="text-[var(--muted-foreground)] ml-1">{stripHtml(attack.mitigation)}</span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
