// DashScope 上游调用：向量嵌入 + 文本生成（可选联网搜索）
// 说明：联网搜索必须走原生协议（/api/v1/services/aigc/text-generation/generation）。
// OpenAI 兼容模式实测不返回 search_info，拿不到网络来源列表，无法做可点击引用。

const DS = "https://dashscope.aliyuncs.com/api/v1/services";
const MODELS = ["qwen-flash", "qwen-plus"]; // 便宜的先跑，失败或空结果再降级

export interface WebSource {
  index: number;
  title: string;
  url: string;
  site: string;
  rank: number; // 1=权威安全源，2=官方文档/主流媒体，3=社区 UGC（默认过滤）
}

export interface GenInput {
  system: string;
  user: string;
  search: boolean;
}

export interface GenResult {
  answer: string;
  web: WebSource[];
  searchUsed: boolean;
  model: string;
}

const jsonHeaders = (key: string) => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${key}`,
});

async function postJson(url: string, headers: Record<string, string>, body: unknown, timeoutMs: number): Promise<any> {
  const r = await fetch(url, { method: "POST", headers, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) return null;
  return await r.json().catch(() => null);
}

// ── 向量嵌入 ─────────────────────────────────────────────────────────────────
export async function embed(key: string, text: string): Promise<number[] | null> {
  const d = await postJson(
    `${DS}/embeddings/text-embedding/text-embedding`,
    jsonHeaders(key),
    { model: "text-embedding-v3", input: { texts: [text] }, parameters: { dimension: 1024 } },
    15000,
  );
  const v = d?.output?.embeddings?.[0]?.embedding;
  return Array.isArray(v) && v.length === 1024 ? v as number[] : null;
}

// ── 网络来源可信度分层 ───────────────────────────────────────────────────────
// 实测默认检索结果里 CSDN 之类 UGC 占比很高，安全研究场景不能把它们当权威来源，
// 因此对返回来源做域名分层：高权重优先展示，UGC 默认过滤（仅在没有任何可信来源时保留并标记）。
const AUTHORITY = [
  "nvd.nist.gov", "cisa.gov", "cve.mitre.org", "cwe.mitre.org", "attack.mitre.org",
  "arxiv.org", "owasp.org", "logging.apache.org", "msrc.microsoft.com", "product-security.apple.com",
  "us-cert.cisa.gov", "knvdcert.de", "cert.gov.hk", "www.cnvd.org.cn", "nsc.org.cn",
];
const UGC = [
  "csdn.net", "jianshu.com", "zhihu.com", "blog.", "cnblogs.com", "juejin.cn", "51cto.com",
  "bilibili.com", "douyin.com", "sohu.com", "163.com", "qq.com", "sina.com", "360.cn", "freebuf",
  "toutiao.com", "baike.baidu.com", "developer.baidu.com",
];

export function rankOf(url: string): number {
  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch { return 3; }
  if (AUTHORITY.some((a) => host === a || host.endsWith(`.${a}`) || host.includes(a))) return 1;
  if (UGC.some((u) => host.includes(u))) return 3;
  return 2;
}

export function rankWebSources(raw: any[]): WebSource[] {
  const list: WebSource[] = [];
  for (const w of raw) {
    const url = String(w?.url ?? "");
    if (!/^https?:\/\//.test(url)) continue;
    list.push({
      index: Number(w?.index) || list.length + 1,
      title: String(w?.title ?? "").slice(0, 160),
      url,
      site: String(w?.site_name ?? "").slice(0, 60),
      rank: rankOf(url),
    });
  }
  list.sort((a, b) => a.rank - b.rank || a.index - b.index);
  const trusted = list.filter((w) => w.rank <= 2);
  return (trusted.length ? trusted : list).slice(0, 5);
}

// ── 文本生成（可联网）────────────────────────────────────────────────────────
export async function generate(key: string, input: GenInput): Promise<GenResult | null> {
  // 需要联网时先试联网；联网链路失败则退回纯本地上下文生成，绝不让整条回答失败。
  const attempts: boolean[] = input.search ? [true, false] : [false];
  for (const withSearch of attempts) {
    for (const model of MODELS) {
      const parameters: Record<string, unknown> = { result_format: "message", temperature: 0.5, max_tokens: 1500 };
      if (withSearch) {
        // 实测 max 比 turbo 更容易命中 NVD/厂商公告这类权威页；turbo 常返回旧闻的复现博客。
        parameters.enable_search = true;
        parameters.search_options = {
          search_strategy: "max",
          forced_search: true,
          enable_source: true,
          enable_citation: true,
          citation_format: "[<number>]",
        };
      }
      const d = await postJson(
        `${DS}/aigc/text-generation/generation`,
        jsonHeaders(key),
        {
          model,
          input: { messages: [{ role: "system", content: input.system }, { role: "user", content: input.user }] },
          parameters,
        },
        withSearch ? 45000 : 30000,
      );
      const text = d?.output?.choices?.[0]?.message?.content;
      if (typeof text !== "string" || !text.trim()) continue;
      const searchRan = withSearch && Boolean(d?.usage?.plugins?.search);
      return {
        answer: text,
        web: searchRan ? rankWebSources((d?.output?.search_info?.search_results) ?? []) : [],
        searchUsed: searchRan,
        model,
      };
    }
  }
  return null;
}
