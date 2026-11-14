// Deno 运行时的最小环境声明，仅用于本地 tsc 类型检查（本机不安装 Deno）。
// 运行时真实类型由 Deno 提供；这里只覆盖本项目 Function 用到的面。
declare const Deno: {
  env: { get(key: string): string | undefined };
  serve(handler: (request: Request) => Promise<Response> | Response, options?: { hostname?: string; port?: number }): void;
};
