#!/usr/bin/env node
/**
 * 跨 shell 的只读回归入口：`npm run test:offline`。
 *
 * 为什么要单独有这个文件而不是让人写 `SKIP_LLM=1 npm test`：那是 **POSIX shell 的前缀赋值语法**。
 * 2026-11-15 有人在 cmd.exe 里照抄，`SKIP_LLM=1 npm test 2>&1 | tail -6` 一声不吭地什么都没输出——
 * cmd 里那行既不会赋值环境变量、也没有 `tail`，于是"没报错"被当成"通过了"。掉线的检查比红掉的
 * 检查更危险，所以把开关收进 Node 里：谁调用都是同一条命令，同一份语义。
 *
 * 零网络、零模型费用：只做一件事——把 `SKIP_LLM=1` 塞进环境，再原样转发参数给 `node --test`。
 */
import { spawnSync } from "node:child_process";

const r = spawnSync(
  process.execPath,
  ["--test", "scripts/regression.test.mjs", ...process.argv.slice(2)],
  { stdio: "inherit", env: { ...process.env, SKIP_LLM: "1" } }
);

if (r.error) {
  process.stderr.write(`启动 node --test 失败：${r.error.message}\n`);
  process.exit(2);
}
process.exit(r.status ?? 1);
