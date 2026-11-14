// 路由分发：action → 对应处理器。所有上游密钥在此集中读取，业务模块只接参数。
import { normalizeMode, runChat } from "./lib/chat.ts";
import { attack, cve, stats } from "./lib/routes.ts";
import type { Backend } from "./lib/kb.ts";

const HEADERS = { "Content-Type": "application/json", "Cache-Control": "no-store" };
const J = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: HEADERS });

const UNCONFIGURED = {
  answer: "服务尚未配置完成，请联系管理员。",
  sources: [], web_sources: [], search_used: false, mode: "auto", coverage: "local", note: "缺少生成服务密钥",
};

export const handler = async (request: Request): Promise<Response> => {
  try {
    const url = new URL(request.url);
    const action = url.searchParams.get("action");
    const SB_URL = Deno.env.get("APP_SUPABASE_URL") ?? "";
    const SB_KEY = Deno.env.get("APP_SUPABASE_ANON_KEY") ?? "";
    const DASH_KEY = Deno.env.get("DASHSCOPE_API_KEY") ?? "";

    const backend: Backend = {
      url: SB_URL,
      h: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, "Content-Type": "application/json" },
    };

    if (request.method === "GET" && action === "stats") {
      const r = await stats(backend);
      return J(r.data, r.status);
    }
    if (request.method === "GET" && action === "cve") {
      const r = await cve(backend, url.searchParams.get("q"));
      return J(r.data, r.status);
    }
    if (request.method === "GET" && action === "attack") {
      const r = await attack(backend, url.searchParams.get("tactic"), url.searchParams.get("technique"));
      return J(r.data, r.status);
    }
    if (request.method === "POST" && action === "chat") {
      const body = (await request.json().catch(() => null)) as { question?: unknown; category?: unknown; mode?: unknown } | null;
      const question = String(body?.question ?? "").trim().slice(0, 500);
      if (!question) return J({ error: "invalid_question" }, 400);
      if (!DASH_KEY) return J(UNCONFIGURED);
      const out = await runChat(
        backend, DASH_KEY, question,
        body?.category ? String(body.category) : null,
        normalizeMode(body?.mode),
      );
      return J(out.body, out.status);
    }

    return J({ error: "not_found" }, 404);
  } catch (e) {
    return J({ error: "internal_error", detail: String((e as Error)?.message ?? e).slice(0, 200) }, 500);
  }
};
