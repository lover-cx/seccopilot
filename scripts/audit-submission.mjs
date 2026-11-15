#!/usr/bin/env node
/**
 * 提交包审计：证明「将要进提交包的那些 blob」里没有凭据、没有大文件、没有本机留档。
 *
 * 为什么审 git 树而不是审已经打好的 zip：`git archive HEAD` 的内容**由构造等于** HEAD 的
 * 已跟踪文件集合，所以审 HEAD 就是审包；反过来审 zip 需要先解压再遍历，多一步就多一步
 * 出错面（11-15 在 cmd.exe 里就是因为这条命令是 bash 语法而静默没跑）。
 * 真要核对 zip 本身，另给一条命令见 README 第九节：Windows 自带的 tar.exe 能列 zip 条目。
 *
 * 用法（cmd / PowerShell / Git Bash 都一样）：
 *   node scripts/audit-submission.mjs                  # 默认口径 = 提交包（排除 docs/superpowers）
 *   node scripts/audit-submission.mjs --include-plans   # 连内部计划文档一起审
 *   node scripts/audit-submission.mjs --selfcheck       # 证明这些判据能判红（不发网络、不打模型）
 * 退出码：0 = 干净；1 = 命中禁止项；2 = 用法/git 不可用。
 */
import { spawnSync } from "node:child_process";

const CWD = process.cwd();
const EXCLUDE_PLANS_DEFAULT = !process.argv.includes("--include-plans");
const SELFCHECK = process.argv.includes("--selfcheck");

/** 凭据形状。宁可多扫——漏一条的代价是把 key 交给平台。 */
const SECRET_PATTERNS = [
  ["dashscope_sk", /sk-[A-Za-z0-9]{20,}/],
  ["aws_akia", /\bAKIA[0-9A-Z]{16}\b/],
  ["pem_private_key", /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/],
  ["jwt_like", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/],
  ["service_role", /_service_role/],
  ["conn_string_pw", /postgres(?:ql)?:\/\/[^\s"'@]*:[^\s"'@]+@/],
];

/**
 * 绝对不该出现在提交包里的路径。
 * `dev/` 那条只挡留档类扩展名，**不挡 `dev/README.md`**——它是 .gitignore 里显式放行的
 * 说明文件（`!dev/README.md`），第一版规则顺手把 `.md` 一起挡了，于是审计脚本把自己的
 * 仓库判成"不要上传"，这是误伤而非缺陷。
 */
const FORBIDDEN_PATHS = [
  [/(^|\/)\.env$/, "本机凭据（.env.example 除外）"],
  [/(^|\/)node_modules\//, "依赖目录"],
  [/(^|\/)\.superpowers\//, "SDD 临时账本"],
  [/^data\/.*\.(json|jsonl|sql|gz|csv|parquet)$/i, "批量数据/转储"],
  [/^dev\/.*\.(json|txt|log)$/i, "本机探针留档"],
  [/(^|\/)(dist|build)\//, "构建产物"],
];

function git(args) {
  const r = spawnSync("git", args, { cwd: CWD, encoding: "buffer", maxBuffer: 1 << 28 });
  if (r.status !== 0) {
    process.stderr.write(`git ${args.join(" ")} 失败：${(r.stderr || "").toString("utf8")}\n`);
    process.exit(2);
  }
  return r.stdout;
}

function selfcheck() {
  // 每条凭据判据都必须至少命中一次自己的样本；命中不到就是这把尺子是空的。
  const samples = {
    dashscope_sk: "DASHSCOPE_API_KEY=sk-0123456789abcdefghijklmnopqrstuv",
    aws_akia: "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
    pem_private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n",
    jwt_like: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.abcdefghijklmnopqrstuvwxyz123456",
    service_role: "SUPABASE_KEY=xxx_service_role_yyy",
    conn_string_pw: "postgres://user:notapa55word@host:5432/db",
  };
  let bad = 0;
  for (const [name, re] of SECRET_PATTERNS) {
    const hit = re.test(samples[name]);
    if (!hit) { console.log(`MISS  ${name} 抓不到自己的样本`); bad++; }
    else console.log(`ok    ${name}`);
  }
  // 假阳性方向：真实仓库里出现过、但**不是**凭据的串，不该被判红。
  const safe = [
    "sk-开头的占位说明", "https://api.openai.com/v1", "text-embedding-v3",
    "qwen-flash", "anon key（明文写这几个字）",
  ];
  for (const s of safe) {
    const hit = SECRET_PATTERNS.some(([, re]) => re.test(s));
    if (hit) { console.log(`FALSE-POSITIVE 误伤：${s}`); bad++; }
  }
  // 路径判据两个方向：这两条不是多余的——第一版 `^dev/.*\.(md)` 把 .gitignore 显式放行的
  // dev/README.md 判成禁止项，审计脚本把自己的仓库拦下来说"不要上传"。
  const mustFlag = ["data/.env", "data/kb_raw.json", "data/dump.sql", "dev/test-run5.log",
    "node_modules/x/index.js", "dist/index.html", ".superpowers/progress.md"];
  const mustNotFlag = ["dev/README.md", "dev/function-node.ts", "dev/probe-kevgate.mjs",
    "data/.env.example", "data/SETUP.md", "docs/eval-archive/online-kev-2026-11-14.json"];
  for (const p of mustFlag) {
    if (!FORBIDDEN_PATHS.some(([re]) => re.test(p))) { console.log(`MISS  路径判据抓不到 ${p}`); bad++; }
  }
  for (const p of mustNotFlag) {
    if (FORBIDDEN_PATHS.some(([re]) => re.test(p))) { console.log(`FALSE-POSITIVE 路径判据误伤 ${p}`); bad++; }
  }
  console.log(bad ? `\n自检未过：${bad} 项` :
    `\n自检通过：${SECRET_PATTERNS.length} 条凭据判据 + ${mustFlag.length} 条路径必须命中、${safe.length + mustNotFlag.length} 条良性样本零误伤`);
  process.exit(bad ? 1 : 0);
}

if (SELFCHECK) selfcheck();

const listed = git(["ls-tree", "-r", "HEAD"]).toString("utf8").trim().split("\n");
const entries = [];
for (const line of listed) {
  const m = line.match(/^(\S+) (\S+) (\S+)\t(.+)$/);
  if (!m) continue;
  entries.push({ mode: m[1], type: m[2], oid: m[3], path: m[4] });
}

const excluded = EXCLUDE_PLANS_DEFAULT
  ? entries.filter((e) => e.path.startsWith("docs/superpowers/"))
  : [];
const packed = EXCLUDE_PLANS_DEFAULT
  ? entries.filter((e) => !e.path.startsWith("docs/superpowers/"))
  : entries;

let hits = 0;
const report = [];
for (const e of packed) {
  const why = FORBIDDEN_PATHS.find(([re]) => re.test(e.path));
  if (why) { report.push(["PATH", e.path, why[1]]); hits++; }
  const blob = git(["cat-file", "blob", e.oid]);
  for (const [name, re] of SECRET_PATTERNS) {
    if (re.test(blob)) { report.push(["SECRET", e.path, name]); hits++; }
  }
  if (blob.length > 2 * 1024 * 1024) { report.push(["SIZE", e.path, `${(blob.length / 1024 / 1024).toFixed(1)} MB > 2MB`]); hits++; }
}

console.log(`审计对象：HEAD 树  |  总条目 ${entries.length}  |  进包 ${packed.length}` +
  (EXCLUDE_PLANS_DEFAULT ? `  |  已排除 docs/superpowers ${excluded.length} 条` : "  |  含 docs/superpowers"));
console.log(`凭据/禁止项命中：${hits}`);
for (const [kind, path, why] of report) console.log(`  ✗ [${kind}] ${path} —— ${why}`);

const trackedEnv = packed.filter((e) => /\.env$/.test(e.path));
console.log(`\ndata/.env 在包里的条数：${trackedEnv.length}（必须是 0）`);
console.log(`data/ 进包的文件：${packed.filter((e) => e.path.startsWith("data/")).map((e) => e.path.split("/").pop()).join(", ") || "(无)"}`);
console.log(hits === 0 ? "\n结论：可以上传。" : "\n结论：不要上传，先处理上面这些命中。");
process.exit(hits === 0 ? 0 : 1);
