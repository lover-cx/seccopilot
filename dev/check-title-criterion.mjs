// 一次性核对入口的**包装**：真正的重算在 `node scripts/eval.mjs --check-title`，判分口径只有那一份。
//
// 为什么不再是自己实现一遍：这个脚本原来把 `PAT` / `TITLE` 两条正则抄在这里重算留档，
// 而 Task 7 恰好同时**放宽编号并集（1 条 → 5 条）并加严类型判据（全篇匹配 → 按编号配对）**。
// 抄一份的写法在那天就会漂移：脚本说"翻转 0 行"而 eval.mjs 换了尺子，这句话立刻变成假的。
// 现在它只负责把默认的四份留档传进去，命令和退出码保持原样，文档里的用法不用改。
//
// 用法：node dev/check-title-criterion.mjs [其它留档.json …]
import { spawnSync } from "node:child_process";

const DEFAULTS = [
  "docs/eval-archive/deployed-prompt-only-2026-11-12.json",
  "docs/eval-archive/local-guards-run1-2026-11-12.json",
  "docs/eval-archive/local-guards-run2-2026-11-12.json",
  "docs/eval-report.json",
];
const files = process.argv.slice(2).filter((a) => a.endsWith(".json"));
const r = spawnSync(process.execPath, ["scripts/eval.mjs", "--check-title", ...(files.length ? files : DEFAULTS)], { stdio: "inherit" });
process.exit(r.status ?? 1);
