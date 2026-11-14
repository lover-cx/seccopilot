// 本机没有 Deno 时，用 Node 直接跑同一份 Function 代码做冒烟测试。
// Node 24 原生支持 TypeScript 类型剥离，因此这里只需补一个最小的 Deno 运行时垫片。
//
// 用法：npm run dev:function:node   然后 curl http://127.0.0.1:8000/functions/v1/app?action=stats
//
// 要打真实检索必须自己注入代理（2026-11-12 实测；此前我们以为本地测不了链路）：
//   Node 24 的全局 fetch 默认不认 *_PROXY，要显式开 NODE_USE_ENV_PROXY=1；
//   Supabase 直连是不通的（ECONNRESET），得走本机 Clash；DashScope 与 NVD 反过来必须绕开代理，
//   否则超时。完整一条命令（Git Bash）：
//   NODE_USE_ENV_PROXY=1 HTTP_PROXY=http://127.0.0.1:7897 HTTPS_PROXY=http://127.0.0.1:7897 \
//     NO_PROXY=dashscope.aliyuncs.com,nvd.nist.gov,services.nvd.nist.gov npm run dev:function:node
// 起起来之后，回归与评测都能直接打它：
//   SITE=http://127.0.0.1:8000 npm test
//   SITE=http://127.0.0.1:8000 EVAL_JSON=dev/eval-report-local.json node scripts/eval.mjs
// 注意这样量到的是"仓库当前源码"的行为，不是线上已发布版本的行为，写报告时两者不能混为一谈。
import http from "node:http";
import fs from "node:fs";
import process from "node:process";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/(\w:)/, "$1");

// 密钥从 data/.env 读取（该文件不入库）；线上由 Sites Secrets 提供
function readDotEnv(file: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
  return out;
}

const dot = fs.existsSync(`${ROOT}data/.env`) ? readDotEnv(`${ROOT}data/.env`) : {};
const ENV: Record<string, string> = {
  APP_SUPABASE_URL: dot.SUPABASE_URL ?? "",
  APP_SUPABASE_ANON_KEY: dot.SUPABASE_KEY ?? "",
  DASHSCOPE_API_KEY: dot.DASHSCOPE_API_KEY ?? "",
};

(globalThis as any).Deno = {
  env: { get: (k: string) => ENV[k] ?? process.env[k] },
  serve: (
    handler: (request: Request) => Promise<Response> | Response,
    opts?: { port?: number },
  ) => {
    const port = opts?.port ?? 8000;
    http
      .createServer(async (req, res) => {
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(c as Buffer);
        const url = `http://127.0.0.1:${port}${req.url ?? "/"}`;
        const request = new Request(url, {
          method: req.method,
          headers: req.headers as Record<string, string>,
          body: ["GET", "HEAD"].includes(req.method ?? "GET") ? undefined : Buffer.concat(chunks),
        });
        try {
          const response = await handler(request);
          res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
          res.end(Buffer.from(await response.arrayBuffer()));
        } catch (e) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "local_shim_failure", detail: String((e as Error).message) }));
        }
      })
      .listen(port, "127.0.0.1", () => console.log(`SecCopilot Function (Node shim) → http://127.0.0.1:${port}/functions/v1/app`));
  },
};

await import("../functions/index.ts");
