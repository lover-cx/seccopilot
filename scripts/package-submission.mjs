#!/usr/bin/env node
/**
 * 提交包打包：`npm run package:submit`
 *
 * 为什么不用命令行直接写 `git archive ... -- . ':(exclude)docs/superpowers'`：那条是 bash 写法，
 * 单引号与续行反斜杠在 cmd.exe 里会被原样吞掉（2026-11-15 实测报 `No such file or directory`）。
 * 这里用 spawn 传参数数组，不过 shell，引号与魔法 pathspec 都不再依赖 shell。
 *
 * 包内容**由构造等于 HEAD 的已跟踪文件集合**，所以未提交的改动、被 .gitignore 挡掉的
 * `data/.env` 与 129 MB 数据、`.superpowers/` 账本，结构上都进不来；打完立刻用
 * audit-submission.mjs 的同一套判据审计一遍 HEAD。
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";

const OUT_DIR = resolve(".superpowers/submission");
const NAME = process.argv.includes("--include-plans")
  ? "seccopilot-code-with-plans.zip"
  : "seccopilot-code.zip";
const OUT = resolve(OUT_DIR, NAME);

const head = spawnSync("git", ["rev-parse", "--short", "HEAD"], { encoding: "utf8" }).stdout.trim();
const dirty = spawnSync("git", ["status", "--porcelain"], { encoding: "utf8" }).stdout.trim();
if (dirty) {
  console.log("工作区不干净。包仍然只从 HEAD 打（未提交的改动不会进包），但先确认这些改动是不是本该提交：");
  console.log(dirty.split("\n").map((l) => "  " + l).join("\n"));
}

mkdirSync(OUT_DIR, { recursive: true });
const args = ["archive", "--format=zip", `--prefix=seccopilot/`, `-o`, OUT, "HEAD"];
if (NAME === "seccopilot-code.zip") args.push("--", ".", ":(exclude)docs/superpowers");

const r = spawnSync("git", args, { encoding: "utf8" });
if (r.status !== 0) {
  process.stderr.write(`git archive 失败：${r.stderr}\n`);
  process.exit(2);
}

const bytes = readFileSync(OUT);
const sha = createHash("sha256").update(bytes).digest("hex");
console.log(`已打包 HEAD ${head}`);
console.log(`路径：${OUT}`);
console.log(`大小：${(statSync(OUT).size / 1024).toFixed(0)} KB`);
console.log(`sha256：${sha}`);
console.log("可复现性：同一 HEAD 重打两次拿到同一个 sha256（11-15 实测 bash 打的与 Node 打的都是 6a9c5f1e…），因为 `git archive` 用固定时间戳写 zip 条目。所以包哈希可以直接当提交物的身份凭证用。");
console.log("\n接着跑审计（同一套判据，审的是 HEAD 树）：");
console.log(`  node scripts/audit-submission.mjs${NAME.includes("plans") ? " --include-plans" : ""}`);
