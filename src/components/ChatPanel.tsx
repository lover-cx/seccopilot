import { useState } from "react";

interface Source {
  title: string;
  url: string;
  category: string;
  similarity: number;
  live?: boolean; // 本地库未覆盖时，本次实时查询上游官方库（如 NVD）得到的来源
}

interface WebSource {
  index: number;
  title: string;
  url: string;
  site: string;
  rank: number; // 1=权威安全源，2=官方文档/媒体，3=社区内容
}

interface Message {
  role: "user" | "assistant";
  content: string;
  sources?: Source[];
  webSources?: WebSource[];
  note?: string;
}

type Mode = "auto" | "on" | "off";

const MODE_LABELS: Record<Mode, string> = {
  auto: "自动联网",
  on: "强制联网",
  off: "仅知识库",
};

const MODE_HINTS: Record<Mode, string> = {
  auto: "本地知识库充分命中时只用本地；命中不足或问题涉及时效信息时自动联网",
  on: "每次都联网检索（演示与评测用）",
  off: "只用本地知识库，结果可复现、零联网开销",
};

const CATEGORY_LABELS: Record<string, string> = {
  "": "全部",
  cve: "CVE 漏洞",
  attack: "ATT&CK",
  cwe: "CWE 弱点",
  paper: "安全论文",
};

// 模型输出的是 Markdown，直接当纯文本显示会看到 ** 和 ###。
// 这里做最小转换：去掉代码围栏，标题行加粗，**x** 转成 <strong>，其余原样保留。
function renderRich(text: string) {
  const cleaned = text.replace(/```[a-zA-Z]*\n?/g, "").replace(/`/g, "");
  return cleaned.split("\n").map((line, i) => {
    const isHeading = /^\s*#{1,6}\s/.test(line);
    const plain = line.replace(/^\s*#{1,6}\s*/, "");
    const parts = plain.split(/\*\*(.+?)\*\*/g);
    return (
      <div key={i} className={isHeading ? "font-medium mt-2" : undefined}>
        {parts.map((p, j) => (j % 2 === 1 ? <strong key={j}>{p}</strong> : p))}
        {plain === "" ? "\u00A0" : null}
      </div>
    );
  });
}

export function ChatPanel() {
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [loading, setLoading] = useState(false);
  const [category, setCategory] = useState<string>("");
  const [mode, setMode] = useState<Mode>("auto");

  const handleSubmit = async () => {
    if (!question.trim() || loading) return;

    const asked = question.trim();
    setMessages((prev) => [...prev, { role: "user", content: asked }]);
    setLoading(true);
    setQuestion("");

    try {
      // 用原生 fetch：后端在降级时仍返回可展示的回答文本（503 也要读出 body），不能一见非 2xx 就丢弃
      const res = await fetch("/functions/v1/app?action=chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: asked, category: category || null, mode }),
      });
      const data = await res.json();

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.answer || "抱歉，未能生成回答。",
          sources: data.sources || [],
          webSources: data.web_sources || [],
          note: data.note,
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "请求失败，请检查网络连接后重试。" },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const exampleQuestions = [
    "MITRE ATT&CK 中初始访问有哪些技术？",
    "Log4j 漏洞 (CVE-2021-44228) 的利用链有哪些？",
    "如何检测 PowerShell 恶意脚本执行？",
    "2026 年新披露的 Log4j 相关 CVE 有哪些？修复版本是什么？",
    "最近有哪些已被在野利用的高危漏洞？",
    "XZ Utils 后门漏洞的原理是什么？",
  ];

  return (
    <div className="space-y-4">
      {/* 检索范围与联网策略 */}
      <div className="flex gap-2 flex-wrap items-center">
        <span className="text-sm text-[var(--muted-foreground)] py-1">知识库范围：</span>
        {["", "cve", "attack", "cwe", "paper"].map((cat) => (
          <button
            key={cat}
            onClick={() => setCategory(cat)}
            className={`px-3 py-1 text-xs rounded-full border transition-colors ${
              category === cat
                ? "bg-blue-500 text-white border-blue-500"
                : "border-[var(--border)] text-[var(--muted-foreground)] hover:border-blue-500"
            }`}
          >
            {CATEGORY_LABELS[cat] ?? cat}
          </button>
        ))}
        <span className="w-px h-4 bg-[var(--border)] mx-1"></span>
        <span className="text-sm text-[var(--muted-foreground)] py-1">来源策略：</span>
        {(Object.keys(MODE_LABELS) as Mode[]).map((m) => (
          <button
            key={m}
            title={MODE_HINTS[m]}
            onClick={() => setMode(m)}
            className={`px-3 py-1 text-xs rounded-full border transition-colors ${
              mode === m
                ? "bg-emerald-500 text-white border-emerald-500"
                : "border-[var(--border)] text-[var(--muted-foreground)] hover:border-emerald-500"
            }`}
          >
            {MODE_LABELS[m]}
          </button>
        ))}
      </div>

      {/* Messages */}
      <div className="space-y-4 min-h-[400px] max-h-[600px] overflow-y-auto scrollbar-thin">
        {messages.length === 0 && (
          <div className="text-center py-12">
            <div className="text-4xl mb-4">🔒</div>
            <h3 className="text-lg font-medium mb-2">安全研究智能助手</h3>
            <p className="text-sm text-[var(--muted-foreground)] mb-1">
              三层知识来源：本地精编知识库 → 上游官方库实时查询 → 网络检索
            </p>
            <p className="text-xs text-[var(--muted-foreground)] mb-6">
              RAG 检索增强生成，回答逐条标注可核验出处
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-w-2xl mx-auto">
              {exampleQuestions.map((q, i) => (
                <button
                  key={i}
                  onClick={() => setQuestion(q)}
                  className="text-left p-3 text-sm rounded-lg border border-[var(--border)] hover:border-blue-500 hover:bg-[var(--surface)] transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[80%] rounded-lg p-4 ${
                msg.role === "user"
                  ? "bg-blue-500 text-white"
                  : "bg-[var(--card)] border border-[var(--border)]"
              }`}
            >
              <div className="text-sm break-words">
                {msg.role === "assistant" ? renderRich(msg.content) : msg.content}
              </div>

              {msg.sources && msg.sources.length > 0 && (
                <div className="mt-3 pt-3 border-t border-[var(--border)]">
                  <div className="text-xs font-medium mb-2 text-[var(--muted-foreground)]">
                    知识库来源：
                  </div>
                  <ul className="space-y-1">
                    {msg.sources.map((source, j) => (
                      <li key={j} className="text-xs">
                        <a
                          href={source.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-500 hover:underline"
                        >
                          [L{j + 1}] {source.title}
                        </a>
                        {source.live ? (
                          <span className="ml-2 px-1.5 py-0.5 text-[10px] rounded bg-amber-500/15 text-amber-600">
                            实时上游
                          </span>
                        ) : (
                          <span className="ml-2 text-[var(--muted-foreground)]">
                            ({Math.round(source.similarity * 100)}% 相关)
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {msg.webSources && msg.webSources.length > 0 && (
                <div className="mt-3 pt-3 border-t border-[var(--border)]">
                  <div className="text-xs font-medium mb-1 text-[var(--muted-foreground)]">
                    网络来源
                    <span className="ml-1 font-normal">（检索结果，未经知识库校验）</span>
                  </div>
                  <ul className="space-y-1">
                    {msg.webSources.map((w) => (
                      <li key={w.url} className="text-xs">
                        <a
                          href={w.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-emerald-600 hover:underline"
                        >
                          [{w.index}] {w.title}
                        </a>
                        <span className="ml-2 text-[var(--muted-foreground)]">{w.site}</span>
                        {w.rank === 3 && (
                          <span className="ml-2 px-1.5 py-0.5 text-[10px] rounded bg-[var(--surface)] text-[var(--muted-foreground)]">
                            社区内容
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {msg.note && (
                <div className="mt-2 text-[11px] text-[var(--muted-foreground)]">{msg.note}</div>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="bg-[var(--card)] border border-[var(--border)] rounded-lg p-4">
              <div className="flex items-center gap-2 text-sm text-[var(--muted-foreground)]">
                <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                {mode === "off"
                  ? "正在检索本地知识库..."
                  : "正在检索知识库，必要时联网核实时效信息..."}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Input */}
      <div className="sticky bottom-0 bg-[var(--background)] pt-4">
        <div className="flex gap-2">
          <textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="输入安全问题，如：CVE-2021-44228 的修复方案是什么？"
            className="flex-1 bg-[var(--card)] border border-[var(--border)] rounded-lg p-3 text-sm resize-none focus:outline-none focus:border-blue-500"
            rows={2}
            disabled={loading}
          />
          <button
            onClick={handleSubmit}
            disabled={loading || !question.trim()}
            className="px-6 py-3 bg-blue-500 text-white rounded-lg text-sm font-medium hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? "..." : "提问"}
          </button>
        </div>
        <p className="text-xs text-[var(--muted-foreground)] mt-2">
          按 Enter 发送，Shift + Enter 换行 · 当前策略：{MODE_LABELS[mode]}
        </p>
      </div>
    </div>
  );
}
