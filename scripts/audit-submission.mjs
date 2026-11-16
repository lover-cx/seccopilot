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
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const CWD = process.cwd();
const EXCLUDE_PLANS_DEFAULT = !process.argv.includes("--include-plans");
const SELFCHECK = process.argv.includes("--selfcheck");

/** 凭据形状。宁可多扫——漏一条的代价是把 key 交给平台。 */
// 最后一条用 `[_]` 而不是直接写下划线，是**被迫**的：审计会扫每个 blob，包括本脚本自己，
// 所以任何"看起来像凭据"的字面串——包括注释里写的、正则源码里写的——都会把自己判红。
// 第一版就是这么翻车的（见下面 selfcheck 里的 SELF-HIT 项）。语义不受影响，仍然匹配同一种串。
const SECRET_PATTERNS = [
  ["dashscope_sk", /sk-[A-Za-z0-9]{20,}/],
  ["aws_akia", /\bAKIA[0-9A-Z]{16}\b/],
  ["pem_private_key", /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/],
  ["jwt_like", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/],
  ["supa_svc_role", /_service[_]role/],
  ["conn_string_pw", /postgres(?:ql)?:\/\/[^\s"'@]*:[^\s"'@]+@/],
];

/**
 * 文本卫生判据：不报错、但评委看得见的东西。
 * 2026-11-16 实测加进来的：为了把历史推上 GitHub 做了一次 rebase，GitHub 建仓时自动生成的
 * Initial commit 与我们首个提交的 README 冲突，一段冲突标记未解决就落进最终树，挂在公开仓库
 * 首页底部。它不让任何命令失败——`tsc`、`npm run build`、回归套件全绿——所以只能靠这条判据抓。
 * 判据本身用运行时拼接构造，理由与下面的样本一样：这个脚本会扫自己的 blob。
 */
const HYGIENE_PATTERNS = [
  ["conflict_marker", new RegExp("^(?:" + "<".repeat(7) + " |" + ">".repeat(7) + " )", "m")],
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
  //
  // 样本一律**运行时拼接**，源文件里不留完整的假密钥字面串。原因不是怕别人看到，而是这套判据
  // 会扫 HEAD 里的每个 blob，**包括这个脚本自己**——第一版直接写字面串，审计脚本把自己判成 6 条
  // 命中、结论"不要上传"。当时最省事的修法是"跳过自己"，但那正是本项目反复在批评的动作：
  // 工具给自己开一条例外，规则就再也没扫过它自己。所以改的是样本的写法，判据与适用范围一个字没动。
  const join = (...parts) => parts.join("");
  const samples = {
    dashscope_sk: join("sk-", "0123456789", "abcdefghijklmnopqrstuv"),
    aws_akia: join("AKIA", "IOSFODNN7EXAMPLE"),
    pem_private_key: join("-----BEGIN ", "OPENSSH PRIVATE KEY-----", "\nb3BlbnNzaA==\n"),
    jwt_like: join("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".", "eyJyb2xlIjoiYWRtaW4ifQ", ".", "abcdefghijklmnopqrstuvwxyz123456"),
    supa_svc_role: join("SUPABASE_KEY=xxx_", "service", "_role", "_yyy"),
    conn_string_pw: join("postgres://", "user:notapa55word@host:5432/db"),
  };
  let bad = 0;
  for (const [name, re] of SECRET_PATTERNS) {
    const hit = re.test(samples[name]);
    if (!hit) { console.log(`MISS  ${name} 抓不到自己的样本`); bad++; }
    else console.log(`ok    ${name}`);
  }
  // 文本卫生判据也要两个方向都钉住。样本同样运行时拼接——写死就把这个脚本自己判成"有冲突标记"。
  const conflictSample = "<".repeat(7) + " HEAD\n正文\n" + ">".repeat(7) + " a7ed77d (chore: 建立 git 仓库)\n";
  const benign = [
    "标题\n======\n下划线式标题是 Markdown 合法写法，不是冲突标记",
    "箭头 -> 与中文破折号 ——：都不该命中",
    "README 里引用一段 diff：'+' 开头行、'-' 开头行",
  ];
  for (const [name, re] of HYGIENE_PATTERNS) {
    if (!re.test(conflictSample)) { console.log(`MISS  ${name} 抓不到冲突标记样本`); bad++; }
    else console.log(`ok    ${name}`);
    for (const s of benign) {
      if (re.test(s)) { console.log(`FALSE-POSITIVE ${name} 误伤：${s.split("\n")[0]}`); bad++; }
    }
  }
  // 顺手钉住"本脚本自己不命中"，否则下一次有人把样本改回字面串，又要靠人工发现。
  const selfBlob = readFileSync(fileURLToPath(import.meta.url), "utf8");
  const selfHits = SECRET_PATTERNS.filter(([, re]) => re.test(selfBlob)).map(([n]) => n);
  if (selfHits.length) { console.log(`SELF-HIT  本脚本源码里的字面串命中自己的判据：${selfHits.join(", ")}`); bad++; }
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
  for (const [name, re] of HYGIENE_PATTERNS) {
    if (re.test(blob)) { report.push(["HYGIENE", e.path, name]); hits++; }
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
