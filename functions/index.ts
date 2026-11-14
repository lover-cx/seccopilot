// SecCopilot – Qoder Sites Edge Function 入口（Deno）
// 路由：
//   GET  /functions/v1/app?action=stats   → 知识库统计
//   GET  /functions/v1/app?action=cve     → CVE 检索（本地精编库）
//   GET  /functions/v1/app?action=attack  → ATT&CK 战术/技术浏览
//   POST /functions/v1/app?action=chat    → RAG 问答（本地库 → 实时上游 → 联网检索三层来源）
//
// 所需 Secrets：APP_SUPABASE_URL、APP_SUPABASE_ANON_KEY、DASHSCOPE_API_KEY
// 业务实现见 handler.ts 与 lib/*（每个模块单一职责，可独立阅读与替换）。

import { handler } from "./handler.ts";

Deno.serve(handler);
