import { useState, useEffect } from "react";
import { ChatPanel } from "./components/ChatPanel";
import { CvePanel } from "./components/CvePanel";
import { AttackPanel } from "./components/AttackPanel";
import { StatsPanel } from "./components/StatsPanel";

type Tab = "chat" | "cve" | "attack" | "stats";

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("chat");

  const tabs: { id: Tab; label: string; icon: string }[] = [
    { id: "chat", label: "智能问答", icon: "💬" },
    { id: "cve", label: "CVE 漏洞", icon: "🔓" },
    { id: "attack", label: "ATT&CK", icon: "⚔️" },
    { id: "stats", label: "知识库", icon: "📊" },
  ];

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)]">
      {/* Header */}
      <header className="border-b border-[var(--border)] bg-[var(--card)]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center text-white font-bold text-lg">
                S
              </div>
              <div>
                <h1 className="text-xl font-bold">SecCopilot</h1>
                <p className="text-xs text-[var(--muted-foreground)]">安全研究智能助手</p>
              </div>
            </div>
            <div className="text-xs text-[var(--muted-foreground)]">
              2026 Qoder 高校创造力大赛
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="border-b border-[var(--border)] bg-[var(--card)]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex gap-1 overflow-x-auto">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-3 text-sm font-medium whitespace-nowrap border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? "border-blue-500 text-blue-500"
                    : "border-transparent text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                }`}
              >
                <span className="mr-2">{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === "chat" && <ChatPanel />}
        {activeTab === "cve" && <CvePanel />}
        {activeTab === "attack" && <AttackPanel />}
        {activeTab === "stats" && <StatsPanel />}
      </main>

      {/* Footer */}
      <footer className="border-t border-[var(--border)] bg-[var(--card)] py-4 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center text-xs text-[var(--muted-foreground)]">
          SecCopilot - 集成 CVE 漏洞库 · MITRE ATT&CK · 安全论文知识库
        </div>
      </footer>
    </div>
  );
}
