# SecCopilot 竞赛冲刺实施计划（2026-11-14 → 2026-11-30 18:00）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 2026-11-30 18:00 前，把"三层来源 + 联网搜索"的安全研究助手做成**线上可演示、缺陷可复现、数字可重跑**的参赛作品：修掉今天线上实测暴露的 KEV 退化回答，收口三项已确认但待批准的契约修改，重新发布并让线上评测与本地评测同口径，最后产出演示视频与天池作品帖。

**Architecture:** 保持不变——React/Vite 前端 + 一个 Deno edge Function（`/functions/v1/app`，`action=chat|cve|attack|stats`）+ Supabase pgvector。知识来源仍是三层：本地库（5,397 条）→ 实时上游 API（NVD CVE 2.0；本次新增 CISA KEV 目录）→ DashScope 原生协议联网检索。本次新增的部分只落在 `functions/lib/kb.ts`（第 2 层多一个上游）与 `functions/lib/chat.ts`（生成后的 KEV 硬校验），不改前端契约字段名，只**扩展** `stats` 的失败表达与 `note` 的措辞分支。

**Tech Stack:** TypeScript（Deno 运行时 + Node 24 type-stripping 双跑）、React 19 + Vite 8、Supabase REST/RPC、DashScope text-generation（`enable_search`）、Node 内置 `node:test`（零依赖）、Node 脚本做评测与证据核对。

**Spec:** `docs/superpowers/specs/2026-11-10-seccopilot-websearch-and-data-design.md`（联网搜索 + 数据扩充 + 评测的原始设计）；本计划是对它的**冲刺补丁**，缺陷清单与判分口径以 `docs/competition-post.md` 第六节、`README.md` 为准。

## Global Constraints

- 竞赛硬截止：**2026-11-30 18:00**；今天 **2026-11-14**。
- `prepare_site` **不要传 `projectId`**；`actionId` 必须是合法 UUID v4（现值 `30699951-0bc3-4743-8550-54bd233792f3`）。
- Secrets 只用 `APP_SUPABASE_URL` / `APP_SUPABASE_ANON_KEY` / `DASHSCOPE_API_KEY`；`SUPABASE_`、`POSTGRES_`、`QODER_` 前缀与 `DATABASE_URL` 是平台保留名。
- 数据脚本只读 `data/.env`（内含 `DEEPSEEK_API_KEY`、`DASHSCOPE_API_KEY`、`SUPABASE_URL`、`SUPABASE_KEY`、`HTTP_PROXY`）。**仓库公开前必须轮换那把 DashScope key**，且 `data/.env` 永不入库。
- 出口网络：Supabase 走本机 Clash 代理 `http://127.0.0.1:7897`；DashScope **必须不走**代理。本地 harness 用 `NODE_USE_ENV_PROXY=1 HTTP_PROXY/HTTPS_PROXY=http://127.0.0.1:7897 NO_PROXY=dashscope.aliyuncs.com,nvd.nist.gov,services.nvd.nist.gov`。
- curl/脚本打 Function 必须带 `Origin`（线上为 `https://seccopilot-kpa8w0w9u7e.qoder.zone`），基址是 `${SITE}/functions/v1/app`；打站点根路径会拿到 SPA HTML，`POST /` 返回 405。
- 同一校验连续两次同样超时即判定平台侧问题，直接报阻塞，不反复重试（发布通道 2026-11-12 已在 `verify_artifact` 上失败 5 次）。
- 证据纪律：任何要发布的数字必须能追到留档 + 可重跑脚本；**未发布的修复不得写成已达成的分数**；两轮结果较差的那一轮作为主口径；自己写错的结论要在文档里撤回而不是删掉。
- 运行时：`engines.node` = `^22.13.0 || >=24.0.0`；测试零依赖（只用 `node:test` + `node:assert/strict`）；`SKIP_LLM=1 npm test` 必须继续可跑（12 项、跳 17 项、零模型费用）。
- 已发布站点线上证据文件是 `docs/eval-archive/deployed-prompt-only-2026-11-12.json`；`docs/eval-report.json` 当前装的是本地 harness 闸门版留档，**不要让子集运行覆盖它**。

---

## File Structure

新建：

- `.gitignore` — 由仓库里已有的 `gitignore.template` 落地，追加 `data/` 大文件与 `dev/` 一次性探针留档的排除策略（Task 1）。
- `scripts/probe-online-kev.mjs` — 把"线上 KEV 那道题现在答成什么样"变成可重跑、可计数、带留档的测量（Task 2）。
- `scripts/refresh-time-grounds.mjs` — 按当前日期重核时效题基准（NVD published / KEV catalogVersion / ATT&CK 版本），输出该改的 `expect` 与 `ground`（Task 7）。
- `dev/kev-feed-cache.json` — 已存在（今天拉的真实 CISA 目录，1,854,379 字节，catalogVersion `2026.11.13`，count 1781），作为 Task 3 的离线基准数据；不入库。

修改：

- `functions/lib/kb.ts` — 新增第 2 层的 KEV 上游：`kevCatalog()`（带 TTL 缓存）与 `kevLookup(ids)`（Task 3）。
- `functions/lib/chat.ts` — 新增 `kevAssertedIds(answer)` 纯函数 + 生成后的 KEV 硬校验与更正文本；`note` 增加"检索执行了但零来源"分支（Task 4、Task 6）。
- `functions/lib/routes.ts` — `stats()` 不再把上游失败 `catch` 成 0；抽出可单测的 `aggregateStats()`（Task 5）。
- `functions/handler.ts` — 承接 `stats` 的非 200 返回（Task 5）。
- `src/components/StatsPanel.tsx` — 上游失败时不再渲染成"0 条"，改渲染缺口说明（Task 5）。
- `scripts/regression.test.mjs` — 新增 KEV 现查/硬校验纯函数用例、联网空来源不得声称联网的用例、stats 不静默归零的用例（Task 3–6）。
- `scripts/eval.mjs` — 时效题基准刷新 + `EVAL_DAY` 常量（Task 7）。
- `docs/competition-post.md`、`docs/demo-script.md`、`README.md`、`docs/eval-report.md` — 每轮实测后同步数字与措辞（Task 2、8、9、11）。
- `.qoder.site` 描述符（`.SecCopilot.qoder.site`）由 Sites 工具自己写，**不要手改**。

明确不动：`vendor/`、`dist/`（当前 377 KB）、`data/*.jsonl`（`phase2_emb.jsonl` 103 MB，整个 `data/` 129 MB）、Supabase schema。

---

## 时间线（每个任务给了建议落点，允许并行但要按依赖顺序提交）

| 日期 | 任务 |
| --- | --- |
| 11-14 | Task 1（git）、Task 2（线上退化留档） |
| 11-15 ~ 11-16 | Task 3（KEV 现查）、Task 4（回答硬校验） |
| 11-17 | Task 5（stats）、Task 6（note 措辞）——两者都要用户批准后才动契约 |
| 11-18 ~ 11-19 | Task 7（时效基准刷新）、Task 8（发布 + 发布后回归） |
| 11-20 ~ 11-21 | Task 9（线上同题评测 + 文档数字同步） |
| 11-22 ~ 11-25 | Task 10（演示视频，含一次重录预算） |
| 11-26 ~ 11-28 | Task 11（作品帖 + 最终检查单） |
| 11-29 ~ 11-30 | 冻结：只允许文档级修复，不再改 Function |

---

### Task 1: 把项目变成 git 仓库，并把密钥和大文件挡在提交之外

**为什么先做这个：** 项目目录现在不是 git 仓库（`git rev-parse` → `fatal: not a git repository`），本计划后面每个任务都以提交收尾；同时"公开仓库"是作品帖的前置条件，而 `data/.env` 里有真实 DashScope key。先建仓库、先证明密钥没进去，后面的 commit 纪律才成立。

**Files:**
- Create: `.gitignore`
- Reference: `gitignore.template`（仓库已有，内容含 `node_modules/`、`dist/`、`.env`、`.env.*`、`!.env.example`、`.DS_Store`、`*.tsbuildinfo`、`.qoder-sites/`、`.qoder-sites.json`）

**Interfaces:**
- Consumes: 无。
- Produces: 一个干净工作树；后续任务的 `git add` / `git commit` 可用；`git ls-files` 成为"密钥没入库"的证据来源。

- [ ] **Step 1: 落地 .gitignore（模板 + 大文件与一次性留档）**

写入 `F:\Qoder\seccopilot\.gitignore`：

```gitignore
node_modules/
dist/
.env
.env.*
!.env.example
.DS_Store
*.tsbuildinfo
.qoder-sites/
.qoder-sites.json

# 数据与探针留档：体积大（data/ 129 MB，phase2_emb.jsonl 单文件 103 MB）或含凭据，不入库
data/*.json
data/*.jsonl
data/.env
dev/*
!dev/README.md

# SDD 工作区（本计划的 ledger / brief / review package，是临时草稿）
.superpowers/

# 本地服务日志与临时产物
*.log
coverage/
```

> 说明 ①：忽略一个目录要用 `dev/*` 而不是 `dev/`——写 `dev/` 会让 git 不再进入该目录，后面的 `!dev/README.md` 就永远不生效（本计划第一次草稿犯过这个错，Task 1 Step 2 的验证要检查 `git ls-files dev/README.md` 有输出）。
> 说明 ②：`dev/` 其余内容不入库（全是本机一次性探针与留档，含 `online-kev-2026-11-14.json`、`kev-feed-cache.json`），但**文档里引用过的 `dev/*.mjs` 脚本必须能被复现**，所以 Step 3 会把它们需要的输入口径写进 `dev/README.md`（唯一入库的 dev 文件）。若用户更希望 `dev/` 脚本全部入库、只挡数据，把上面两行换成 `dev/*.json`、`dev/*.txt`、`dev/*.log`、`dev/*.md`，其余步骤不变。

- [ ] **Step 2: 初始化并做首个提交**

```bash
cd /f/Qoder/seccopilot
git init -b main
git config user.name && git config user.email   # 只读确认，不修改配置
git add .gitignore gitignore.template README.md PROVENANCE.md package.json package-lock.json \
  tsconfig.json tsconfig.functions.json vite.config.ts postcss.config.mjs index.html components.json \
  components hooks lib public src functions scripts supabase-schema.sql supabase-retrieval-fix.sql
git add '.SecCopilot.qoder.site'
git status --porcelain | head -30
```

Expected: `git status --porcelain` 里**没有** `data/.env`、没有任何 `node_modules/`、没有 `dist/`、没有 `data/*.json*`。

- [ ] **Step 3: 写 dev/README.md，说明未入库目录里有哪些可复现脚本**

```markdown
# dev/（未入库）

本目录是本机一次性探针与实测留档，体积大且部分含真实站点响应，默认不提交。
仓库里文档引用过的可复现脚本，输入与判据如下；重新生成请按此顺序：

| 脚本 | 输入 | 作用 | 需要的外部条件 |
| --- | --- | --- | --- |
| probe-kev-on-batch.mjs | 本地 harness :8000 | 同一 KEV 问题连跑 N 次，统计"提到 CVE-2026-21509 且给出收录日期" | 代理（Supabase）+ DashScope 不走代理 |
| check-kev-samples.mjs | kev-on-batch.json / kev-off-batch.json / kev-on-*.txt | 离线重算 KEV 遵守率，区分"检索到"与"照着说" | 无网络 |
| check-title-criterion.mjs | docs/eval-archive/*.json | 核对 title 判据的判定翻转数（当前 8 行 0 翻转） | 无网络 |
| probe-websearch-shape.mjs | DashScope 原生协议 | 看 plugins/search 执行位与 search_info 来源数是否一致 | DashScope key |
```

- [ ] **Step 4: 提交并验证密钥未入库**

```bash
git add dev/README.md
git commit -m "$(cat <<'EOF'
chore: 建立 git 仓库与忽略规则，先挡住 data/.env 与 129 MB 数据目录

竞赛作品帖若附仓库链接，data/.env 里的 DashScope key 会随首个提交永久进历史，
所以仓库化的第一步是证明它不在追踪列表里；dev/ 留档不入库，改为提交一份
说明其输入与判据的 dev/README.md。
EOF
)"
git ls-files | grep -Ei "\.env$|\.env\." || echo "OK：没有 .env 被追踪"
git ls-files dev/README.md          # 必须有一行输出，否则说明 dev/* 的忽略写法挡掉了例外
git ls-files | wc -l
```

Expected: 打印 `OK：没有 .env 被追踪`，并且 `git ls-files dev/README.md` 输出 `dev/README.md`；`git log --oneline` 有 1 条提交；工作树 `git status --porcelain` 为空（`dev/` 其余内容、`data/`、`.superpowers/` 已被忽略）。

- [ ] **Step 5: 把"公开前必须轮换 key"写进作品帖任务清单**

在 `docs/competition-post.md` 的"附：30 秒复现"小节末尾追加：

```markdown
- 仓库若公开：先轮换 `data/.env` 里的 DashScope key（本目录已 gitignore，但历史提交风险要一次性堵死），
  并在 Sites 侧更新 `DASHSCOPE_API_KEY` Secret 后重新发布——密钥轮换会让旧 key 立刻失效，顺序不能反。
```

```bash
git add docs/competition-post.md && git commit -m "docs: 记录公开仓库前必须轮换 DashScope key 的顺序约束"
```

---

### Task 2: 把今天线上的 KEV 退化回答变成可重跑的测量，并记为第 9 条缺陷

**测量到的事实（2026-11-14，本机出口）：** 线上站点 `POST /functions/v1/app?action=chat`、问题"2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？"、`mode` 默认 → `{coverage:'mixed', search_used:true, nSrc:5, nWeb:2, note:'本地知识库未有效覆盖本题，回答主要依据网络检索'}`，回答正文是"知识库与网络检索均未覆盖 2026 年 CISA 关于 Office 产品漏洞的新增信息。"——**正文里一个 CVE 编号都没有**，而 `search_used=true` 且本地检索结果里明明有 5 条含 CVE-2026-21509 的资料。两个网络来源是"微博正文"与一条乱码的新华网链接。这与本地 harness 那 10 次全命中（`dev/kev-on-batch.json`）形成反差：**那道旗标题在线上目前是答不好的**。留档见 `dev/online-kev-2026-11-14.json`。

不做这件事的后果：演示视频和作品帖都会点开这道题，而它现在线上给的是零编号的"未覆盖"。

**Files:**
- Create: `scripts/probe-online-kev.mjs`
- Modify: `docs/competition-post.md`（第六节缺陷清单加第 9 条）、`README.md`（脚本清单加一条）

**Interfaces:**
- Consumes: `${SITE}/functions/v1/app?action=chat`；环境变量 `SITE`（默认线上站点）、`N`（默认 6）。
- Produces: `dev/online-kev-<YYYY-MM-DD>.json`（逐次留档 + 汇总），退出码 0 = 每次都给出编号与收录日期、非 0 = 存在不合规；stdout 最后一行是可复制进文档的结论文本。

- [ ] **Step 1: 写探针脚本（失败时先让它跑出今天的真实结果）**

新建 `scripts/probe-online-kev.mjs`：

```js
// 线上 KEV 旗标题探针：同一问题连跑 N 次，逐次留档并判定"给出编号 + 给出 KEV 收录日期"。
// 用法：SITE=https://seccopilot-kpa8w0w9u7e.qoder.zone N=6 node scripts/probe-online-kev.mjs
//       SITE=http://127.0.0.1:8000 node scripts/probe-online-kev.mjs     # 修完代码后本机自证
// 判据与 scripts/eval.mjs 的 KEV 题保持一致：CVE-2026-21509 + 2026-01-26（或中文写法），
// 外加"类型对得上"（Security Feature Bypass / 安全功能绕过）。
// 退出码：不合规次数 > 0 → 1。留档落 dev/online-kev-<date>.json（dev/ 不入库）。
import { writeFileSync } from "node:fs";

const SITE = (process.env.SITE ?? "https://seccopilot-kpa8w0w9u7e.qoder.zone").replace(/\/+$/, "");
const N = Number(process.env.N ?? 6);
const Q = "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";
const HEADERS = { Origin: SITE, Referer: `${SITE}/`, "Content-Type": "application/json" };
const ID = /CVE-2026-21509/i;
const DATE = /2026[-/年]0?1[-/月]26/;              // 2026-01-26 / 2026/01/26 / 2026年1月26日
const TYPE = /Security Feature Bypass|安全功能绕过/i;
const DOWNGRADE = /资料未说明|未说明其在野利用|未在野利用|未明确标注|无公开|尚无/;

const OUT = `dev/online-kev-${new Date().toISOString().slice(0, 10)}.json`;
const rows = [];
for (let i = 0; i < N; i++) {
  let row;
  try {
    const r = await fetch(`${SITE}/functions/v1/app?action=chat`, {
      method: "POST", headers: HEADERS, body: JSON.stringify({ question: Q, category: null }),
      signal: AbortSignal.timeout(90000),
    });
    const d = await r.json();
    const a = String(d.answer ?? "");
    row = {
      i: i + 1, http: r.status, coverage: d.coverage, searchUsed: d.search_used, note: d.note,
      nSrc: (d.sources ?? []).length, nWeb: (d.web_sources ?? []).length,
      srcHasId: (d.sources ?? []).some((s) => ID.test(String(s.title ?? "") + String(s.content ?? ""))),
      hasId: ID.test(a), hasDate: DATE.test(a), hasType: TYPE.test(a),
      degraded: DOWNGRADE.test(a), webTitles: (d.web_sources ?? []).map((w) => w.title).slice(0, 5),
      answer: a.slice(0, 1500),
    };
  } catch (e) {
    row = { i: i + 1, error: String(e?.message ?? e).slice(0, 200) };
  }
  rows.push(row);
  console.log(JSON.stringify({ ...row, answer: undefined, webTitles: undefined }).slice(0, 260));
  writeFileSync(OUT, JSON.stringify({ site: SITE, q: Q, rows }, null, 1), "utf-8");
}
const ok = rows.filter((r) => r.hasId && r.hasDate && r.hasType && !r.degraded).length;
const retrievalOk = rows.filter((r) => r.srcHasId).length;
console.log(`\n${SITE}：${ok}/${rows.length} 次给出「编号 + 收录日期 + 类型」且未降级；`
  + `其中 ${retrievalOk} 次的检索结果里本来就有 CVE-2026-21509。`);
console.log(`留档：${OUT}`);
process.exit(ok === rows.length ? 0 : 1);
```

- [ ] **Step 2: 跑一次，确认它复现了今天的退化（先红了才知道探针在测东西）**

```bash
cd /f/Qoder/seccopilot && N=3 node scripts/probe-online-kev.mjs; echo "exit=$?"
```

Expected: 每次 `hasId:false`、`nSrc:5`、`srcHasId:true`，最后一行 `0/3 次给出…；其中 3 次的检索结果里本来就有 CVE-2026-21509`，`exit=1`。若某次 `hasId:true`（线上模型有随机性），把 3 次扩到 6 次再判：`N=6 node scripts/probe-online-kev.mjs`。

- [ ] **Step 3: 把测量结果写成第 9 条缺陷**

在 `docs/competition-post.md` 第六节缺陷清单末尾追加（**注意：这条描述的是 2026-11-14 线上表现，修复在 Task 3/4，未发布前不得写成已修**）：

```markdown
9. **线上旗标题现在给不出编号（2026-11-14 实测）。** 同一个问题在本地 harness 连跑 10 次全部给出
   CVE-2026-21509 与收录日期（`dev/kev-on-batch.json`），今天打线上却是"知识库与网络检索均未覆盖……"，
   正文零编号，`search_used=true` 而两条网络来源是"微博正文"和一条乱码链接；`N=3 node scripts/probe-online-kev.mjs`
   三次全红、`srcHasId` 三次全真——**检索拿到了，回答没用上**。上一版我们查过检索侧（留档重跑 10 次每次都捞回
   含该编号的 5 条资料），所以这次把根因指向两处：线上跑的还是加闸门之前的 prompt；本地 KEV 快照停在
   2026.11.09，目录里 2026 年微软 Office 已有 3 条（21509、21514、124194），第 3 条是 11-10 新增、本地库没有。
   分别由 Task 3（KEV 现查目录）和 Task 4（回答后硬校验）处理；发布通道没通之前，这条只能以"实测到的退化"存在。
```

- [ ] **Step 4: README 登记脚本并重跑一次作为文档证据**

`README.md` 脚本清单追加：

```markdown
- `node scripts/probe-online-kev.mjs`：线上（或 `SITE=http://127.0.0.1:8000` 本机）KEV 旗标题连跑 N 次
  （`N=` 可调，默认 6），逐次记录"给出编号 / 给出收录日期 / 类型对得上 / 是否降级表述 / 检索结果里本来有没有该编号"，
  留档 `dev/online-kev-<date>.json`，有不合规即退出码 1。2026-11-14 线上 `N=3` 结果 0/3 合规、3/3 检索命中，
  即第 9 条缺陷的证据。
```

```bash
node scripts/probe-online-kev.mjs 2>&1 | tail -3
git add scripts/probe-online-kev.mjs docs/competition-post.md README.md
git commit -m "feat(probe): 线上 KEV 旗标题探针；docs: 记为第 9 条缺陷（未发布修复，只记实测退化）"
```

Expected: 退出码 1 且 tail 里给出 `0/N` 与 `srcHasId` 计数。

---

### Task 3: 第 2 层知识来源新增 CISA KEV 现查目录（本地快照过期时不再靠记忆）

**已验证的上游事实（今天拉的真目录，缓存在 `dev/kev-feed-cache.json`）：** `catalogVersion` = `2026.11.13`、`count` = 1781、响应 1,854,379 字节、本机经代理 2.5 秒返回；字段名是 `cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, forensicTriage, notes, cwes`（**不是 `vendor`**）。2026 年微软 Office 在目录里有 3 条：`CVE-2026-21509`（2026-01-26 / 期限 2026-02-16）、`CVE-2026-21514`（2026-02-10）、`CVE-2026-124194`（2026-11-10，Outlook Missing User Interaction）。本地 `data/phase2_raw.json` 有前两条、**没有第三条**（快照停在 2026.11.09）。

**Files:**
- Modify: `functions/lib/kb.ts`（在 `nvdLive` 之后追加 KEV 目录层，约 40 行）
- Modify: `scripts/regression.test.mjs`（新增 2 个用例：1 个纯函数、1 个真实目录）

**Interfaces:**
- Consumes: 无（只依赖 `fetch`，与 `nvdLive` 同样的写法与超时风格）。
- Produces（Task 4 依赖这些确切名字与返回结构）：
  - `export interface KevEntry { cveID: string; vendorProject: string; product: string; vulnerabilityName: string; dateAdded: string; dueDate: string; requiredAction: string }`
  - `export async function kevCatalog(): Promise<Map<string, KevEntry> | null>` — 网络失败或结构异常返回 `null`（**"拿不到目录"必须与"目录里没有"区分**，这是本项目第 4 次踩同一类坑：有 bug 的探针把两者混为一谈）。
  - `export async function kevLookup(ids: string[]): Promise<{ confirmed: KevEntry[]; absent: string[]; unavailable: boolean }>`
  - `export function kevFromCatalog(entries: KevEntry[], ids: string[]): Doc[]`（纯函数，把目录条目转成 `Doc`，`id: \`kev:${cveID}\`、`category: "cve"`、`live: true`、正文沿用本地 KEV 前缀格式，让现有 `kevFacts()` 的 `KEV_MARK_RE` 能直接识别）
  - `export const KEV_SNAPSHOT_VERSION = "2026.11.09"`（本地库快照版本，仅用于措辞"本地快照 vX 未收录"）

- [ ] **Step 1: 先写会失败的纯函数用例**

在 `scripts/regression.test.mjs` 里，紧跟现有 `test("kevFacts：在野利用只能引用带 KEV 标注的资料", ...)` 之后插入：

```js
// 纯函数回归：本地 KEV 快照停在 2026.11.09，而目录里 2026 年微软 Office 已有 3 条
// （21509、21514、124194，第三条 2026-11-10 新增）。现查目录必须能把它转成带 KEV 标注的资料，
// 否则 kevFacts() 的闸门会把它当"无 KEV 证据"处理——那就是第 9 条缺陷的根因之一。
test("kevFromCatalog：目录条目转成带 KEV 前缀的资料（本地快照缺的那条也能进闸门）", () => {
  if (!kevFromCatalog) return t_skip();
  const entries = new Map([
    ["CVE-2026-21509", { cveID: "CVE-2026-21509", vendorProject: "Microsoft", product: "Office",
      vulnerabilityName: "Microsoft Office Security Feature Bypass Vulnerability",
      dateAdded: "2026-01-26", dueDate: "2026-02-16", requiredAction: "Apply patch." }],
    ["CVE-2026-124194", { cveID: "CVE-2026-124194", vendorProject: "Microsoft", product: "Office",
      vulnerabilityName: "Microsoft Office Outlook Missing User Interaction Vulnerability",
      dateAdded: "2026-11-10", dueDate: "2026-11-24", requiredAction: "Apply patch." }],
  ]);
  const docs = kevFromCatalog([...entries.values()], ["CVE-2026-21509", "CVE-2026-124194"]);
  assert.equal(docs.length, 2, "两条都应在目录里命中");
  assert.match(docs[0].content, /^在野利用（CISA KEV）｜厂商：Microsoft｜产品：Office｜KEV 收录：2026-01-26｜修复期限：2026-02-16/);
  assert.equal(docs[0].live, true, "现查目录的资料必须标 live，前端才不会当成本库条目");
  assert.equal(docs[0].source_url, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?selected_cve=CVE-2026-21509");
  // 闸门认识它：本地资料里只有这条快照没有的编号时，kevFacts 也应把它列进证据清单
  const msg = kevFacts("2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？", docs);
  assert.match(msg, /CVE-2026-124194（收录 2026-11-10）/);
  // 目录里没有的编号 → 空文档，不是异常
  assert.equal(kevFromCatalog([...entries.values()], ["CVE-2099-00001"]).length, 0);
});
```

本文件已经有一个共享的动态导入块（现约 306–316 行：`let gapFacts = null; … try { const m = await import("../functions/lib/chat.ts"); … } catch { … }`，各用例用 `if (!kevFacts) return t_skip();` 守卫）。**不要新造 loader 函数**，按同一形状扩展它——在同一个 try 块里补一行 kb.ts 的导入，并把符号存到顶层 `let`：

```js
let kevFromCatalog = null;
let kevLookup = null;
try {
  const kb = await import("../functions/lib/kb.ts");
  kevFromCatalog = kb.kevFromCatalog;
  kevLookup = kb.kevLookup;
} catch { /* Node 版本不支持 .ts 直读时跳过本用例 */ }
```

用例首两行相应写成：

```js
test("kevFromCatalog：目录条目转成带 KEV 前缀的资料（本地快照缺的那条也能进闸门）", () => {
  if (!kevFromCatalog) return t_skip();
```

上面用例里 `kevFromCatalog(...)` 直接调用顶层符号（共 2 处），不要再加 `mod.` 前缀。

- [ ] **Step 2: 跑到它失败**

```bash
cd /f/Qoder/seccopilot && node --test --experimental-strip-types --test-name-pattern "kevFromCatalog" scripts/regression.test.mjs
```

Expected: FAIL，报错形如 `The keyword 'kevFromCatalog' is not exported from ...`（或 `kevFromCatalog is not a function`）。若 SKIP 掉而不是 FAIL，说明 loader 写错了，先修 loader——**跳过不等于通过**。

- [ ] **Step 3: 实现目录层**

在 `functions/lib/kb.ts` 末尾（`nvdLive` 之后）追加：

```ts
// ── 第 2 层：CISA KEV 现查目录（"在野利用"是有门槛的断言，本地快照会过期）──────
// 实测 2026-11-14：本地 KEV 快照是 2026.11.09，而目录已是 2026.11.13、1781 条，
// 2026 年微软 Office 有 3 条（21509、21514、124194），最后一条 11-10 才新增、本地库没有。
// 目录只有一个 URL、无鉴权、约 1.8 MB，因此按 isolate 缓存 6 小时；拉不到时返回 null，
// 让上层说"本地快照 vX 未收录"而不是"KEV 未收录"——把"没查到"说成"不存在"是本项目明令禁止的。
export const KEV_SNAPSHOT_VERSION = "2026.11.09";
const KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const KEV_TTL_MS = 6 * 60 * 60 * 1000;

export interface KevEntry {
  cveID: string; vendorProject: string; product: string; vulnerabilityName: string;
  dateAdded: string; dueDate: string; requiredAction: string;
}

let kevCache: { at: number; map: Map<string, KevEntry> } | null = null;

export async function kevCatalog(force = false): Promise<Map<string, KevEntry> | null> {
  if (!force && kevCache && Date.now() - kevCache.at < KEV_TTL_MS) return kevCache.map;
  try {
    const r = await fetch(KEV_FEED, { signal: AbortSignal.timeout(12000) });
    if (!r.ok) return null;
    const d = await r.json();
    const list = d?.vulnerabilities;
    if (!Array.isArray(list) || !d?.catalogVersion) return null; // 结构异常 ≠ 空目录
    const map = new Map<string, KevEntry>();
    for (const v of list) {
      if (!v?.cveID) continue;
      map.set(String(v.cveID).toUpperCase(), {
        cveID: String(v.cveID).toUpperCase(),
        vendorProject: v.vendorProject ?? "", product: v.product ?? "",
        vulnerabilityName: v.vulnerabilityName ?? "",
        dateAdded: v.dateAdded ?? "", dueDate: v.dueDate ?? "",
        requiredAction: v.requiredAction ?? "",
      });
    }
    kevCache = { at: Date.now(), map };
    return map;
  } catch { return null; }
}

/** 纯函数：目录条目 → 本地库同款正文前缀，使 kevFacts() 的 KEV_MARK_RE 直接可用。 */
export function kevFromCatalog(entries: KevEntry[], ids: string[]): Doc[] {
  const want = new Set(ids.map((x) => x.toUpperCase()));
  return entries
    .filter((e) => want.has(e.cveID.toUpperCase()) && e.dateAdded)
    .map((e) => ({
      id: `kev:${e.cveID}`,
      title: `${e.cveID}: ${clip(e.vulnerabilityName, 90)}`,
      content: `在野利用（CISA KEV）｜厂商：${e.vendorProject}｜产品：${e.product}`
        + `｜KEV 收录：${e.dateAdded}｜修复期限：${e.dueDate}\n`
        + `漏洞名：${e.vulnerabilityName}\n处置要求：${clip(e.requiredAction, 200)}`,
      source_url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?selected_cve=${e.cveID}`,
      category: "cve", similarity: 1, anchor: true, live: true,
    }));
}

/** 按编号现查：confirmed=目录里有（带日期），absent=目录里确实没有，unavailable=目录没拉到。 */
export async function kevLookup(ids: string[]): Promise<{ confirmed: KevEntry[]; absent: string[]; unavailable: boolean }> {
  const uniq = [...new Set(ids.map((x) => x.toUpperCase()))];
  if (!uniq.length) return { confirmed: [], absent: [], unavailable: false };
  const map = await kevCatalog();
  if (!map) return { confirmed: [], absent: [], unavailable: true };
  const confirmed: KevEntry[] = [];
  const absent: string[] = [];
  for (const id of uniq) {
    const e = map.get(id);
    if (e) confirmed.push(e); else absent.push(id);
  }
  return { confirmed, absent, unavailable: false };
}
```

> `clip` 与 `Doc` 已在 `kb.ts` 内存在（`clip` 被 `nvdLive` 使用）；若 `clip` 尚未导出，就在同文件内使用，无需导出。若 `Doc` 类型没有 `live`/`anchor` 字段，看 `chat.ts:17` 附近定义并按需补可选字段，不要改成不同名字。

- [ ] **Step 4: 跑真实目录用例（打的是 cisa.gov，不是模型）**

`scripts/regression.test.mjs` 再插入：

```js
// 这条会真的打 cisa.gov（约 1.8 MB / 6 小时缓存），所以和 LLM 用例一样受 SKIP_LLM 管：
// SKIP_LLM=1 npm test 必须保持"零网络、零模型费用"，这是 Global Constraints 里的硬约定。
test("kevCatalog：现查目录能确认 CVE-2026-21509 的收录日期，且 124194 只在目录里", async (t) => {
  if (SKIP_LLM) return t.skip("SKIP_LLM=1");
  if (!kevLookup) return t_skip();
  const r = await kevLookup(["CVE-2026-21509", "CVE-2026-124194", "CVE-2099-00001"]);
  if (r.unavailable) { console.warn("  [warn] CISA 目录当前不可达（本机需 HTTPS_PROXY；线上未验证）"); return; }
  const byId = Object.fromEntries(r.confirmed.map((e) => [e.cveID, e]));
  assert.equal(byId["CVE-2026-21509"]?.dateAdded, "2026-01-26", "旗标题的收录日期必须与判分口径一致");
  assert.match(byId["CVE-2026-21509"]?.vulnerabilityName ?? "", /Security Feature Bypass/);
  assert.equal(byId["CVE-2026-124194"]?.dateAdded, "2026-11-10", "本地快照没有、目录里有的那条应被确认");
  assert.ok(r.absent.includes("CVE-2099-00001"), "目录里确实没有的编号应落 absent，不是报错");
  assert.ok(!r.absent.includes("CVE-2026-21509"), "确认过的编号不得同时出现在 absent 里");
});
```

> `return` 前没有断言的那条分支（`r.unavailable`）是**故意留的软分支**：目录不可达不能把整套回归变红，但也不能假装通过——它必须打印 `[warn]`，且 Task 4 的第 ③ 分支负责在这种状态下改变措辞。

```bash
cd /f/Qoder/seccopilot && node --test --experimental-strip-types --test-name-pattern "kevCatalog" scripts/regression.test.mjs
```

Expected: PASS。若打印 `[skip] CISA 目录当前不可达`，先确认代理（`HTTPS_PROXY=http://127.0.0.1:7897`）；连续两次同样失败即按平台/网络侧问题记录，不要继续重试。

- [ ] **Step 5: 全量只读回归不回归，然后提交**

```bash
cd /f/Qoder/seccopilot && SKIP_LLM=1 npm test 2>&1 | tail -6
npm run check:function
git add functions/lib/kb.ts scripts/regression.test.mjs
git commit -m "feat(kb): 第 2 层新增 CISA KEV 现查目录（含 6 小时缓存与不可达/不存在区分）

本地 KEV 快照停在 2026.11.09，2026 年微软 Office 的第三条（CVE-2026-124194，11-10 收录）
本地库没有，导致旗标题只能答'未覆盖'。kevFromCatalog 沿用本地 KEV 正文前缀，
好让既有 kevFacts 闸门不改判据即可识别现查条目。"
```

Expected: `SKIP_LLM=1 npm test` 至少 `# pass 12` 以上（新增 1 个纯函数用例后应为 13 跑、17 跳），`# fail 0`；`check:function` 无错误。

---

### Task 4: 生成后对"在野利用"断言做硬校验（检索拿到了却没说 → 代码层兜底）

**为什么不能只靠 prompt：** 本地 harness 10 次采样里检索每次都含 CVE-2026-21509、闸门也把它列进证据清单，但线上那一版仍是零编号（第 9 条缺陷）。措辞与闸门是"请求模型照做"，硬校验是"不照做就在代码层更正"。这两件事要分开提交，因为评审者可能接受现查目录、却不同意改动回答正文。

**Files:**
- Modify: `functions/lib/chat.ts`（新增 `kevAssertedIds`、`kevCorrection`，并在 `runChat` 生成之后调用）
- Modify: `scripts/regression.test.mjs`（1 个纯函数用例 + 把现有 KEV 断言用例改为复用同一判据）
- Modify: `docs/competition-post.md`、`README.md`（写明新增的机制与自测边界）

**Interfaces:**
- Consumes: `kevLookup(ids)`、`KEV_MARK_RE`、`KEV_HINT`、`Doc`（Task 3 与现有代码）。
- Produces（回归用例和后续任务都用这些名字）：
  - `export function kevAssertedIds(answer: string): string[]` — 逐句判定"在野利用断言 + CVE 编号"，返回去重编号数组。判据与 `scripts/regression.test.mjs:~405` 那段 `bad` 过滤**必须同源**（本项目已经因为判分器与代码各写一遍判据踩过两次坑）。
  - `export function kevCorrection(question: string, answer: string, docs: Doc[], catalog: { confirmed: KevEntry[]; absent: string[]; unavailable: boolean }): KevCheck`
    ——**判据的触发条件看 `question`，不看 `answer`**。理由就是这条任务要修的那个缺陷本身：线上退化回答是"知识库与网络检索均未覆盖 2026 年 CISA 关于 Office 产品漏洞的新增信息。"，正文里既没有"在野"也没有 KEV 字样；如果 guard 去扫正文，这类回答会被判成"与 KEV 无关"直接放行，硬校验永远不触发。第一版草稿正是这样写的，核对时才发现。

- [ ] **Step 1: 写失败用例（把判据钉成代码）**

```js
// 纯函数回归：2026-11-14 线上实测——检索结果里有 CVE-2026-21509（srcHasId 3/3），
// 回答正文却是"知识库与网络检索均未覆盖…"、零编号。闸门只负责"给证据"，
// 这里补"生成后检查断言"：凡是句子里把某个编号说成在野利用，就必须能对上 KEV 事实。
test("kevAssertedIds + kevCorrection：断言与 KEV 事实对不上时给出代码层更正", () => {
  if (!kevAssertedIds || !kevCorrection) return t_skip();
  const Q = "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";

  // 判据同源：与回归用例里那句"在野利用断言"完全一致（同句有日期=合格，否定式=合格）
  assert.deepEqual(
    kevAssertedIds("CVE-2026-83542 已被确认在野利用。CVE-2026-21509 于 2026-01-26 进入 CISA KEV。"
      + "CVE-2026-119618 尚无公开的在野利用报告。"),
    ["CVE-2026-83542"], "带日期的合格表述与否定式表述都不该进违规清单");

  const doc = { id: 1, title: "CVE-2026-21509: Microsoft Office Security Feature Bypass Vulnerability",
    content: "在野利用（CISA KEV）｜厂商：Microsoft｜产品：Office｜KEV 收录：2026-01-26｜修复期限：2026-02-16\n正文…",
    source_url: "u", category: "cve", similarity: 1 };
  const kev21509 = { cveID: "CVE-2026-21509", vendorProject: "Microsoft", product: "Office",
    vulnerabilityName: "Microsoft Office Security Feature Bypass Vulnerability",
    dateAdded: "2026-01-26", dueDate: "2026-02-16", requiredAction: "Apply patch." };

  // ① 正文整条未提及（就是线上今天的样子）：必须补代码核验的 KEV 事实
  const empty = kevCorrection(Q, "知识库与网络检索均未覆盖 2026 年 CISA 关于 Office 产品漏洞的新增信息。", [doc],
    { confirmed: [kev21509], absent: [], unavailable: false });
  assert.equal(empty.corrected, true, "回答漏掉已确认的在野利用条目时应补更正");
  assert.match(empty.answer, /CVE-2026-21509/);
  assert.match(empty.answer, /2026-01-26/);
  assert.match(empty.answer, /代码核验|代码更正/, "更正文本必须声明来源是代码，不是模型判断");

  // ② 未经确认的编号被说成在野利用：必须降级，且不得静默删掉编号
  //    注意这句里不能出现任何 20xx-xx-xx：同句有日期会被判据当作"已给 KEV 证据"而放行，
  //    写个披露日期进来会把用例变成假绿（第一版草稿就踩了，判据与既有套件同源，改判据不是选项）。
  const bad = kevCorrection(Q, "以下漏洞已被确认在野利用：CVE-2026-83542。", [doc],
    { confirmed: [], absent: ["CVE-2026-83542"], unavailable: false });
  assert.match(bad.answer, /CVE-2026-83542/, "不得静默删除编号，那会让人以为我们查不到");
  assert.match(bad.answer, /不在 KEV 目录中/, "应降级为'不在 KEV 目录中（CISA 未收录）'");

  // ③ 目录拉不到时不下"不存在"的结论（第 4 条缺陷那一类）
  const off = kevCorrection("最近有哪些已被确认在野利用的 Apache 产品漏洞？",
    "CVE-2026-83542 已被确认在野利用。", [], { confirmed: [], absent: [], unavailable: true });
  assert.match(off.answer, /目录当前不可达|未能核验/);
  assert.ok(!/不存在|未被确认利用/.test(off.answer), "不可达时不得断言其不在 KEV");
  assert.equal(off.corrected, false, "无法核验时不改写结论，只加核验状态说明");

  // ④ 与 KEV 无关的问题一律不动正文：硬校验不能变成给所有回答加段落
  const other = kevCorrection("CWE-79 是什么弱点？如何缓解？",
    "CWE-79 是跨站脚本，缓解方式是输出编码。", [], { confirmed: [], absent: [], unavailable: false });
  assert.equal(other.corrected, false);
  assert.equal(other.reason, "not_kev");
  assert.equal(other.answer, "CWE-79 是跨站脚本，缓解方式是输出编码。");
});
```

符号从文件里已有的那个共享动态导入块取（与 Task 3 Step 1 同处扩展），不要新造 loader：

```js
let kevAssertedIds = null;
let kevCorrection = null;
// 加在现有 try 块内：const m = await import("../functions/lib/chat.ts"); 之后
kevAssertedIds = m.kevAssertedIds;
kevCorrection = m.kevCorrection;
```

- [ ] **Step 2: 跑到失败**

```bash
node --test --experimental-strip-types --test-name-pattern "kevAssertedIds" scripts/regression.test.mjs
```

Expected: FAIL，`kevAssertedIds is not a function`（或断言直接报 `kevAssertedIds` 未定义）。

- [ ] **Step 3: 实现判据与更正**

在 `functions/lib/chat.ts` 中，`kevFacts()`（现约 250–270 行）之后追加：

```ts
// 与 scripts/regression.test.mjs 里那条 KEV 断言用例同一判据（改这里必须同步改那里，
// 判分器与代码各写一遍判据是本项目踩过两次的坑）。
const SENT_SPLIT = /(?<=[。；;\n])/;
const KEV_ASSERT = /在野|已被利用|确认利用|被确认|active exploitation|ransomware/i;
const KEV_NEGATE = /未经|无法确认|不确定|未见|不属于|尚无|未进入|不在|不满足|没有公开|无公开|尚无/;

/** 返回"被断言为在野利用、但正文未同时给出 KEV 日期"的编号（去重、大写）。 */
export function kevAssertedIds(answer: string): string[] {
  const out = new Set<string>();
  for (const s of String(answer).split(SENT_SPLIT)) {
    if (!KEV_ASSERT.test(s) || KEV_NEGATE.test(s)) continue;
    if (/20\d\d-\d\d-\d\d/.test(s)) continue;            // 同句已给日期：合格
    for (const m of s.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []) out.add(m.toUpperCase());
  }
  return [...out];
}

/** 断言里提到、但本库资料没给 KEV 标注的编号（用来决定要不要现查目录）。 */
function kevUnannotatedIds(answer: string, docs: Doc[]): string[] {
  const annotated = new Set<string>();
  for (const d of docs) {
    if (!KEV_MARK_RE.test(String(d.content ?? ""))) continue;
    for (const m of String(`${d.title} ${d.content}`).match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []) {
      annotated.add(m.toUpperCase());
    }
  }
  return kevAssertedIds(answer).filter((id) => !annotated.has(id));
}

export interface KevCheck {
  answer: string; corrected: boolean; reason: string;
}

/**
 * 生成后硬校验：KEV 是有门槛的断言，检索/闸门给了证据不等于模型照着说。
 * 三条分支——(1) 目录确认但正文没提 → 追加代码核验的补充；
 * (2) 正文断言但目录确实没有 → 降级表述，不删编号；
 * (3) 目录不可达 → 只声明"未能核验"，绝不写"KEV 未收录"。
 * 本地快照版本写进措辞（KEV_SNAPSHOT_VERSION），让"我们没查到"与"现实中不存在"分得开。
 */
export function kevCorrection(
  question: string, answer: string, docs: Doc[],
  catalog: { confirmed: KevEntry[]; absent: string[]; unavailable: boolean },
): KevCheck {
  const text = String(answer ?? "");
  // 触发条件看问题，不看正文——见本任务 Interfaces 里的说明：退化回答恰恰是把 KEV 字样丢掉了。
  if (!KEV_HINT.test(String(question ?? "")) && kevAssertedIds(text).length === 0) {
    return { answer: text, corrected: false, reason: "not_kev" };
  }
  if (catalog.unavailable) {
    return {
      answer: `${text}\n\n【KEV 核验状态】CISA KEV 目录当前不可达，本轮未能核验上述编号的在野利用状态；`
        + `下方结论仅依据本地知识库快照（版本 ${KEV_SNAPSHOT_VERSION}）中带有 KEV 标注的条目，不代表该漏洞不在 KEV 目录中。`,
      corrected: false, reason: "catalog_unavailable",
    };
  }
  const asserted = kevAssertedIds(text);
  const addenda: string[] = [];

  // (2) 断言了但目录确实没有 → 降级
  const wronglyAsserted = catalog.absent.filter((id) => asserted.includes(id));
  if (wronglyAsserted.length) {
    addenda.push(`【代码更正】${wronglyAsserted.join("、")} 不在 KEV 目录中（CISA 未收录），`
      + `因此不构成"已被确认在野利用"；上文若把它列为在野利用，以本更正为准（KEV 目录版本以本次查询为准）。`);
  }
  // (1) 目录或本地资料已确认、正文却没给编号或没给日期 → 补一条可核验事实。
  //     docs 在这里才真正被使用：本地 KEV 标注里的日期同样算"已确认"，
  //     这样即使线上边缘运行时拉不到 CISA 目录（Task 8 之前未验证过），旗标题仍能被兜住。
  const fromDocs: KevEntry[] = docs
    .filter((d) => KEV_MARK_RE.test(String(d.content ?? "")))
    .map((d) => {
      const c = String(d.content);
      return {
        cveID: (String(d.title).match(/CVE-\d{4}-\d{4,7}/i)?.[0]
          ?? c.match(/CVE-\d{4}-\d{4,7}/i)?.[0] ?? "").toUpperCase(),
        vendorProject: c.match(/厂商：([^｜\n]+)/)?.[1] ?? "",
        product: c.match(/产品：([^｜\n]+)/)?.[1] ?? "",
        vulnerabilityName: String(d.title).replace(/^CVE-\d{4}-\d{4,7}:\s*/i, ""),
        dateAdded: c.match(/KEV 收录：(20\d\d-\d\d-\d\d)/)?.[1] ?? "",
        dueDate: c.match(/修复期限：(20\d\d-\d\d-\d\d)/)?.[1] ?? "",
        requiredAction: "",
      };
    }).filter((e) => e.cveID && e.dateAdded);
  const known = new Map<string, KevEntry>();
  for (const e of [...fromDocs, ...catalog.confirmed]) if (!known.has(e.cveID)) known.set(e.cveID, e);
  const missing = [...known.values()]
    .filter((e) => !text.toUpperCase().includes(e.cveID) || !text.includes(e.dateAdded));
  if (missing.length) {
    const listed = missing.map((e) => `${e.cveID}（${e.vendorProject} ${e.product}，${e.vulnerabilityName}，KEV 收录 ${e.dateAdded}、修复期限 ${e.dueDate}）`);
    addenda.push(`【代码核验的 KEV 事实】本地资料与 CISA 目录交叉核验后确认在野利用：${listed.join("；")}。`
      + `此条由代码依据 KEV 目录字段给出，不依赖模型是否记得。`);
  }
  if (!addenda.length) return { answer: text, corrected: false, reason: "clean" };
  return { answer: `${text}\n\n${addenda.join("\n\n")}`, corrected: true, reason: "corrected" };
}
```

并在文件顶部 import 里加入 `kevLookup`、`KevEntry`、`KEV_SNAPSHOT_VERSION`（与现有 `nvdLive` 同行从 `./kb.ts` 导入）。

- [ ] **Step 4: 在 runChat 里接线**

`functions/lib/chat.ts` 生成之后（现 `const searchUsed = gen.searchUsed;` 之前）插入：

```ts
  // 生成后硬校验：只在问题像 KEV 题、或正文里出现无 KEV 标注的编号时才现查目录，
  // 避免每次对话都拉 1.8 MB 的 feed（有 6 小时缓存，但冷启动代价仍是真的）。
  const needKevCheck = KEV_HINT.test(question) || kevAssertedIds(gen.answer).length > 0;
  let payloadAnswer = gen.answer;
  let kevReason = "skipped";
  if (needKevCheck) {
    // 只查"正文断言了、本地资料却没 KEV 标注"的编号；本地已标注的那批由 kevCorrection
    // 自己从 docs 里解析（见其 fromDocs 分支），所以目录不可达时旗标题照样兜得住。
    const cat = await kevLookup(kevUnannotatedIds(gen.answer, docs));
    const chk = kevCorrection(question, gen.answer, docs, cat);
    payloadAnswer = chk.answer;
    kevReason = chk.reason;
  }
```

> 这里**不要**再往 `cat.confirmed` 里塞本地条目（第一版草稿这么写，等于把同一份"从正文前缀解析 KEV 字段"的逻辑写两遍）；解析只存在于 `kevCorrection` 的 `fromDocs` 里一处。

然后把返回体里的 `answer: gen.answer` 改为 `answer: payloadAnswer`，并在 `note` 计算之后追加一句核验状态（保持 `note` 只有一条，措辞见 Task 6）：

```ts
  const kevNote = kevReason === "clean" ? "" : kevReason === "catalog_unavailable"
    ? "（KEV 目录不可达，未核验在野利用状态）"
    : kevReason === "corrected" ? "（已按 CISA KEV 目录核验并更正/补充在野利用结论）" : "";
```

`return { status: 200, body: { answer: payloadAnswer, ..., note: note + kevNote } }`。

- [ ] **Step 5: 本机 harness 实测同一道旗标题**

```bash
cd /f/Qoder/seccopilot
NODE_USE_ENV_PROXY=1 HTTP_PROXY=http://127.0.0.1:7897 HTTPS_PROXY=http://127.0.0.1:7897 \
  NO_PROXY=dashscope.aliyuncs.com,nvd.nist.gov,services.nvd.nist.gov \
  npm run dev:function:node > dev/harness-8000.log 2>&1 &
sleep 8 && curl -s -o /dev/null -w "harness=%{http_code}\n" http://127.0.0.1:8000/functions/v1/app?action=stats
SITE=http://127.0.0.1:8000 N=4 node scripts/probe-online-kev.mjs; echo "exit=$?"
```

Expected: `harness=200`；探针 4 次里 `hasId && hasDate && hasType` 全真（`corrected` 兜底生效），退出码 0。若仍 <4，把 4 次结果写进 `docs/competition-post.md` 而不是调判据放行——**这是硬校验，允许它红**。

- [ ] **Step 6: 全量回归 + 提交**

```bash
SKIP_LLM=1 npm test 2>&1 | tail -6 && SITE=http://127.0.0.1:8000 npm test 2>&1 | tail -8
npm run check:function && npm run build > /dev/null && echo build=ok
git add functions/lib/chat.ts scripts/regression.test.mjs docs/competition-post.md README.md
git commit -m "feat(chat): 生成后按 KEV 目录硬校验在野利用断言

检索把 CVE-2026-21509 放进证据清单、回答却不照著说（线上 0/3 合规），说明提示词与
闸门都不足以兜住这个断言。kevAssertedIds 与回归用例共用同一判据，kevCorrection 分三种
情形：已确认但正文漏了→补事实；断言但目录确实没有→降级且不删编号；目录不可达→只声明
未核验，绝不把'没查到'写成'不存在'。"
```

Expected: `SKIP_LLM=1` 全绿；本机全量 `# fail 0`（若网络来源类用例红，按第 8 条缺陷口径记录，不改判据）。

---

### Task 5: `stats` 不再把上游失败算成 0（待用户批准的契约修改 #25）

**现状（`functions/lib/routes.ts:17-25`）：** 每个分类计数都是 `try { … } catch { return 0; }`，6 次请求里任何一次超时/非 200 都变成"这一类 0 条"，而 `total` 又来自另一次请求，于是页面可以一边显示"共 5,397 条"一边显示"paper 0 条"。**上游失败必须可见**——这条已记在缺陷清单里（第 ①类根因），一直没动是因为它改响应契约、要前端配合。

**动契约前需要用户确认（一句话即可）：** 失败分类返回 `null` 并在响应里带 `degraded: string[]`，全部失败返回 502 `{error:"upstream_unavailable"}`。若用户不同意改契约，退路是保留 200 但把 `total` 也置为 `null` 并附 `degraded`，其余步骤不变。

**Files:**
- Modify: `functions/lib/routes.ts:14-31`
- Modify: `functions/handler.ts:27-30`
- Modify: `src/components/StatsPanel.tsx:3-26`（渲染 `null` 与缺口说明）
- Modify: `scripts/regression.test.mjs`（"stats 返回完整计数" 改判据 + 新增纯函数用例）

**Interfaces:**
- Consumes: `Backend`（`{url, h}`）。
- Produces: `export function aggregateStats(total: number | null, per: (number | null)[], failed: string[]): { data: { total: number | null; categories: Record<string, number | null>; degraded: string[] }; status: number }`；响应形状 `{total, categories, degraded}`（新增 `degraded`，其余字段语义收紧为"可能为 `null`"）。

- [ ] **Step 1: 写失败的纯函数用例**

```js
test("aggregateStats：上游失败不得变成 0 条", () => {
  if (!aggregateStats) return t_skip();
  const C = ["cve", "attack", "cwe", "paper", "general"];
  // ① 健康：求和与 total 一致，degraded 为空
  const ok = aggregateStats(5397, [1774, 867, 956, 1800, 0], []);
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.data.categories, { cve: 1774, attack: 867, cwe: 956, paper: 1800, general: 0 });
  assert.deepEqual(ok.data.degraded, []);
  // ② paper 请求失败 → 必须是 null，不是 0（0 会被读成"这一类没有数据"）
  const partial = aggregateStats(5397, [1774, 867, 956, null, 0], ["paper"]);
  assert.equal(partial.data.categories.paper, null, "失败分类必须显式 null");
  assert.notEqual(partial.data.categories.paper, 0);
  assert.deepEqual(partial.data.degraded, ["paper"]);
  assert.equal(partial.status, 200, "部分失败仍是 200，但缺口可见");
  // ③ total 也失败 → null，且不得让前端把 null 当 0 求和
  const noTotal = aggregateStats(null, [1774, 867, 956, 1800, 0], ["total"]);
  assert.equal(noTotal.data.total, null);
  assert.ok(noTotal.data.degraded.includes("total"));
  // ④ 全失败 → 502，不给"看起来正常"的 0
  const dead = aggregateStats(null, [null, null, null, null, null], ["total", ...C]);
  assert.equal(dead.status, 502);
  assert.equal(dead.data.error, "upstream_unavailable");
});
```

与 Task 3/4 一样，扩展文件里已有的共享动态导入块，不新造 loader：

```js
let aggregateStats = null;
// 新增一个与 chat.ts 导入块同形状的 try 块（routes.ts 里只有纯函数，导入它不会发请求）
try {
  const r = await import("../functions/lib/routes.ts");
  aggregateStats = r.aggregateStats;
} catch { /* Node 版本不支持 .ts 直读时跳过本用例 */ }
```

- [ ] **Step 2: 跑到失败**

```bash
node --test --experimental-strip-types --test-name-pattern "aggregateStats" scripts/regression.test.mjs
```

Expected: FAIL（`aggregateStats is not a function`）。

- [ ] **Step 3: 实现（替换 routes.ts 的 14–31 行）**

```ts
// ── stats：分类计数（用 Content-Range 头，避免真的把行取回来）─────────────────
// 关键约定：某一类没取到就是 null，不是 0。0 会被读成"这一类没有数据"，
// 而真实情况是上游超时/非 200——把失败说成 0 是我们记在清单里的第 ① 类根因（缺陷 5）。
export interface StatsData {
  total: number | null;
  categories: Record<string, number | null>;
  degraded: string[];
}

export function aggregateStats(
  total: number | null, per: (number | null)[], failed: string[],
): { status: number; data: StatsData | { error: string } } {
  const categories: Record<string, number | null> = {};
  CATEGORIES.forEach((c, i) => { categories[c] = per[i] ?? null; });
  const degraded = [...failed];
  const allDown = total === null && per.every((x) => x === null);
  if (allDown) return { status: 502, data: { error: "upstream_unavailable" } };
  return { status: 200, data: { total, categories, degraded } };
}

export async function stats(b: Backend): Promise<EndpointResult> {
  // 注意：不要为 !b.url 单独开一条"200 + 全 0/全 null"的捷径——未配置与上游全挂是同一件事，
  // 都应走 aggregateStats 得到 502。原代码在这里返回 200 + 全 0，正是缺陷本体。
  const count = async (where: string | null): Promise<number | null> => {
    const q = where ? `&${where}` : "";
    try {
      const r = await fetch(`${b.url}/rest/v1/knowledge_base?select=id&limit=0${q}`, {
        headers: { ...b.h, Prefer: "count=exact" }, signal: AbortSignal.timeout(8000),
      });
      if (!r.ok) return null;
      const m = (r.headers.get("content-range") ?? "").match(/\/(\d+)$/);
      return m ? Number(m[1]) : null;   // 解析不出来同样是"不知道"，不是 0
    } catch { return null; }
  };
  const res = await Promise.all([count(null), ...CATEGORIES.map((c) => count(`category=eq.${c}`))]);
  const failed: string[] = [];
  if (res[0] === null) failed.push("total");
  CATEGORIES.forEach((c, i) => { if (res[i + 1] === null) failed.push(c); });
  return aggregateStats(res[0], res.slice(1), failed);
}
```

- [ ] **Step 4: handler 与前端承接非 200 / null**

`functions/handler.ts:27-30` 不改（`J(r.data, r.status)` 已会带上 502）。`src/components/StatsPanel.tsx`：

```tsx
interface Stats {
  total: number | null;
  categories: Record<string, number | null>;
  degraded?: string[];
}
```

在 `loadStats()` 里按状态区分，不再把失败留成旧值：

```tsx
      const res = await fetch("/functions/v1/app?action=stats");
      const data = await res.json();
      if (!res.ok) {
        setError(res.status === 502 ? "知识库统计上游不可用（Supabase 未响应），下方数字不代表条目数为 0。" : `统计接口异常（HTTP ${res.status}）`);
        setStats(null);
      } else {
        setError(data?.degraded?.length ? `部分分类未能统计：${data.degraded.join("、")}（显示为 —，不是 0）` : "");
        setStats(data);
      }
```

渲染处（第 62、77 行的 `Object.entries(...)`）把计数改为 `count === null || count === undefined ? "—" : count`，并在总数处同样处理：`stats?.total ?? "—"`。新增 `const [error, setError] = useState("");` 与错误提示段（红字或黄色警告条，沿用组件现有 Tailwind 风格）。

- [ ] **Step 5: 更新既有 stats 用例，使其区分 null**

`scripts/regression.test.mjs` 的 `test("stats 返回完整计数")` 内，把求和改为忽略 `null` 并显式断言没有"0 冒充失败"：

```js
  const d = await get("stats");
  assert.ok(Array.isArray(d.degraded), "响应应带 degraded 列表（哪些分类没统计到）");
  const nums = Object.entries(d.categories).filter(([, v]) => typeof v === "number");
  assert.equal(d.degraded.length, Object.keys(d.categories).length - nums.length, "degraded 应与 null 分类一一对应");
  assert.equal(nums.length, Object.keys(d.categories).length, "健康站点不应有分类为 null");
  const sum = nums.reduce((a, [, v]) => a + v, 0);
  assert.equal(sum, d.total, `分类求和 ${sum} 应等于 total ${d.total}`);
  for (const c of ["cve", "attack", "cwe", "paper"]) assert.ok(d.categories[c] > 0, `${c} 计数不得为 0（0 视为上游失败或数据缺失）`);
```

- [ ] **Step 6: 验证（含一次人为制造失败，证明不是只测好路径）**

```bash
node --test --experimental-strip-types --test-name-pattern "aggregateStats" scripts/regression.test.mjs
SKIP_LLM=1 npm test 2>&1 | tail -6
SITE=http://127.0.0.1:8000 npm test 2>&1 | grep -E "stats|fail|pass" | head -8
# 人为失败：让本地 harness 指向一个不存在的 Supabase（仅本机，不影响线上）
APP_SUPABASE_URL=https://127.0.0.1:9 APP_SUPABASE_ANON_KEY=x DASHSCOPE_API_KEY=x node dev/function-node.ts > dev/harness-broken.log 2>&1 &
sleep 8; curl -s -o /dev/null -w "broken-stats=%{http_code}\n" -H "Origin: http://127.0.0.1:8000" "http://127.0.0.1:8000/functions/v1/app?action=stats"
kill %1 2>/dev/null
```

Expected: 单元用例 PASS；正常站点 `# fail 0`；人为失败时 `broken-stats=502`（**这条是本次修复的验收核心：以前它返回 200 + 全 0**）。

- [ ] **Step 7: 文档 + 提交**

`docs/competition-post.md` 缺陷清单第 ① 类根因那段补一句"已实现、待发布"，`README.md` 的 stats 说明补 `degraded` 与 `—` 渲染；然后：

```bash
git add functions/lib/routes.ts functions/handler.ts src/components/StatsPanel.tsx scripts/regression.test.mjs docs/competition-post.md README.md
git commit -m "fix(stats): 上游失败返回 null/502 而非 0，前端把缺口显示为 —

统计接口原先把 fetch 失败 catch 成 0，某一类会静默显示 0 条（记在缺陷清单里没藏）。
现在失败分类显式 null + degraded 列表，全部失败 502 upstream_unavailable；
本机把 APP_SUPABASE_URL 指向不存在的端口实测得到 502（旧代码同条件给 200 + 全 0）。
这是响应契约变更，需前端配合，发布前线上仍是旧行为。"
```

---

### Task 6: 收口第 8 条缺陷——检索执行了却没有来源时，`note` 不得声称结合了网络检索（待批准 #26）

**现状（`functions/lib/chat.ts:352-356`）：** `searchUsed = Boolean(usage.plugins.search)` 只表示"插件执行过"；`note` 却按 `searchUsed` 分支写"结合本地知识库与网络检索作答"或"回答主要依据网络检索"。今天线上那 2 条来源里是"微博正文"和乱码链接，而 `dev/probe-websearch-shape.mjs` 的记录显示：11-12 下午起出现过 `search_used:true` 而 `web_sources: []` 的响应——**那一页写着"结合了网络检索"，下面一条来源都点不出来**。这条改动要同时收紧 `coverage` 与 `note`，并给回归用例加断言。

**动契约前需要用户确认：** 当 `search_used === true && web_sources.length === 0` 时，`coverage` 由 `web` 降级为 `mixed`/`local`（按本地是否有资料），`note` 改说"网络检索插件已执行但本次未返回可核验来源，回答未使用可点击网络来源"。

**Files:**
- Modify: `functions/lib/chat.ts`（`coverage`/`note` 计算）
- Modify: `scripts/regression.test.mjs:~184`（`chat：响应含联网搜索契约字段`）
- Modify: `src/components/*`（若前端按 `coverage === "web"` 显示"来源：网络检索"标签，需同步；先在 Step 1 确认是否存在该分支）

**Interfaces:**
- Consumes: `gen.web`、`gen.searchUsed`、`docs.length`。
- Produces: `export function webGrounding(searchUsed: boolean, webCount: number, localDocs: number): { coverage: "local" | "mixed" | "web"; note: string }`（纯函数，便于用例与本地自测都打同一个口径）。

- [ ] **Step 1: 先查前端是否依赖 `coverage === "web"`**

```bash
cd /f/Qoder/seccopilot && grep -rn "coverage" src components lib | head -20
```

Expected 输出决定 Step 5 范围：若前端只把 `coverage` 当展示标签，改后端即可；若它按 `"web"` 走单独分支（例如隐藏本地来源组），把该分支改成"依据 `web_sources.length > 0`"。

- [ ] **Step 2: 写失败的纯函数用例**

```js
test("webGrounding：插件执行了但零来源时不得声称结合网络检索", () => {
  if (!webGrounding) return t_skip();
  const a = webGrounding(true, 3, 5);
  assert.equal(a.coverage, "mixed");
  assert.match(a.note, /网络检索/, "有来源时正常表述");
  assert.ok(!/未返回/.test(a.note));

  const b = webGrounding(true, 0, 5);
  assert.equal(b.coverage, "mixed", "本地有资料时不能只说 web");
  assert.match(b.note, /插件已执行/);
  assert.match(b.note, /未返回可核验来源|未能给出可核验来源/);
  assert.ok(!/结合本地知识库与网络检索作答/.test(b.note), "零来源不得写成'结合了网络检索'");

  const c = webGrounding(true, 0, 0);
  assert.equal(c.coverage, "local", "什么来源都没有 → 不能说这轮有外部依据");
  assert.match(c.note, /未返回可核验来源/);

  const d = webGrounding(false, 0, 4);
  assert.equal(d.coverage, "local");
  assert.ok(!/网络检索/.test(d.note), "没联网就不要提网络检索（mode=off 用例同一底线）");
});
```

符号沿用 Task 4 已经扩展过的 chat.ts 导入块，只多加一行：

```js
let webGrounding = null;
// 加在现有 chat.ts 的 try 块里：webGrounding = m.webGrounding;
```

- [ ] **Step 3: 跑到失败**

```bash
node --test --experimental-strip-types --test-name-pattern "webGrounding" scripts/regression.test.mjs
```

Expected: FAIL（`webGrounding is not a function`）。

- [ ] **Step 4: 实现并接线**

`functions/lib/chat.ts`（在 `runChat` 之前）：

```ts
/** 联网检索的"可核验性"与"执行位"不是一回事：plugins.search 只说明插件跑过。 */
export function webGrounding(searchUsed: boolean, webCount: number, localDocs: number):
  { coverage: ChatPayload["coverage"]; note: string } {
  if (!searchUsed) {
    return { coverage: "local",
      note: localDocs ? "回答基于本地知识库" : "本地知识库未有效覆盖本题，且当前模式不联网；下列来源仅为近似条目，请勿当作权威结论" };
  }
  if (webCount === 0) {
    return { coverage: localDocs ? "mixed" : "local",
      note: localDocs
        ? "网络检索插件已执行但本次未返回可核验来源，回答依据的是本地知识库条目"
        : "网络检索插件已执行但本次未返回可核验来源，因此本轮无法给出可点击的网络出处" };
  }
  return { coverage: localDocs ? "mixed" : "web",
    note: localDocs ? "结合本地知识库与网络检索作答；网络来源未经知识库校验" : "本地知识库未有效覆盖本题，回答主要依据网络检索" };
}
```

替换 `runChat` 里以 `const coverage: ChatPayload["coverage"] = !searchUsed ? "local" : ...` 开头、到 `note` 三元表达式结束的那一段（原 353–356 行；Task 4 已在其前后插入了 KEV 校验，**按内容定位，不要按行号**）：

```ts
  const grounding = webGrounding(searchUsed, gen.web.length, docs.length);
  const coverage = grounding.coverage;
  const note = grounding.note;
```

（Task 4 引入的 `kevNote` 仍追加在 `note` 之后，顺序不变。）

- [ ] **Step 5: 收紧联网契约用例**

`scripts/regression.test.mjs` 的 `test("chat：响应含联网搜索契约字段")` 里，把"字段齐备"和"空来源不得声称联网"合到一条用例（这条 11-12 起稳定红，是第 8 条缺陷的用例侧表达）：

```js
  assert.equal(d.search_used, true, "含 2026 时效信号的问题应触发联网检索");
  if (d.web_sources.length === 0) {
    // 第 8 条缺陷：插件执行位为真但来源为空时，措辞与 coverage 都不能声称"依据网络检索"
    assert.notEqual(d.coverage, "web", "零来源不得标为 web");
    assert.match(d.note, /未返回可核验来源|未检索到可核验来源/, `零来源时的措辞：${d.note}`);
    assert.ok(!/结合本地知识库与网络检索作答|主要依据网络检索/.test(d.note), `不得声称结合网络：${d.note}`);
    console.warn("  [warn] 本轮联网检索插件执行了但没有可核验来源（第 8 条缺陷）");
  } else {
    assert.ok(d.web_sources.length > 0);
    for (const w of d.web_sources.slice(0, 5)) {
      for (const f of ["index", "title", "url", "site"]) assert.ok(f in w, `网络来源字段不完整：${JSON.stringify(w)}`);
      assert.match(w.url, /^https:\/\//, "网络来源应有绝对 URL");
    }
    assert.ok(d.web_sources.some((w: any) => /nvd\.nist\.gov|cisa\.gov|mitre\.org|microsoft\.com|logging\.apache\.org|arxiv\.org/.test(String(w.url))),
      "至少应有一条权威安全来源，只有社区 UGC 不算合格联网");
  }
```

- [ ] **Step 6: 本机验证两条路径（有来源 / 零来源）都要跑**

```bash
SITE=http://127.0.0.1:8000 node --test --test-name-pattern "响应含联网搜索契约字段" scripts/regression.test.mjs
# 零来源路径：本机直连 DashScope 拿不到来源时，用 dev/probe-websearch-shape.mjs 记录真实响应形状
node dev/probe-websearch-shape.mjs 2>&1 | tail -12
SKIP_LLM=1 npm test 2>&1 | tail -6
```

Expected: 契约用例在有来源时绿；若上游给空数组，同一用例应绿（因为断言走的是 `note`/`coverage` 分支）——**这就是本次修改的目的：用例本身不再因为上游抖动而红**。把 `probe-websearch-shape.mjs` 的输出摘要写进 `docs/competition-post.md` 第 8 条缺陷段（已有段落后追加，不改原结论）。

- [ ] **Step 7: 提交**

```bash
git add functions/lib/chat.ts scripts/regression.test.mjs docs/competition-post.md README.md src/components
git commit -m "fix(chat): 联网插件执行但零来源时降级 coverage/note 措辞；联网契约用例分两路断言

search_used 只表示 plugins.search 执行过，原先据此写'结合了网络检索'，
出现页面上有措辞、下面点不出来源的情况（第 8 条缺陷）。webGrounding() 把执行位与
可核验来源数分开判，零来源时明确'插件已执行但未返回可核验来源'；用例不再因上游抖动稳定红。"
```

---

### Task 7: 时效题基准刷新到评测日（11-10 的基准现在已经不准了）

**为什么必须做：** `scripts/eval.mjs` 的 ground truth 是 2026-11-10 逐条核过 NVD 写死的，其中"本周有没有新披露的高危漏洞？"的 `ground` 直接写着"评测日为 2026-11-10"。今天（11-14）KEV 目录已到 `2026.11.13`、新增 8 条，且 2026 年微软 Office 从 2 条变 3 条（CVE-2026-124194，11-10 收录）。那道旗标题的 `expect.pattern` 只认 `CVE-2026-21509`：一个把三条都列全、却没写 21509 的正确回答会被判错；反过来 11-10 之后"本周"的窗口也移动了。**基准过期不是产品缺陷，是尺子过期——必须主动刷新并留核校记录，否则报告里的分数含义会变。**

**Files:**
- Create: `scripts/refresh-time-grounds.mjs`
- Modify: `scripts/eval.mjs`（新增 `EVAL_DAY` 常量、更新两处 `expect`/`ground`）
- Modify: `docs/eval-report.md`（"时效题基准"表由脚本生成，替换过期表述）

**Interfaces:**
- Consumes: NVD CVE 2.0 接口（`services.nvd.nist.gov`，无 key 时限流约 5 请求/30 秒，脚本必须串行 + 间隔，沿用 `scripts/verify-suspects.mjs:65` 的 `sleep(7000)` 做法）、CISA KEV feed（本机走代理）。
- Produces: stdout 打印"该改成什么"的建议片段（人复制进 eval.mjs），并落 `dev/time-grounds-<date>.json`；退出码 0 = 基准全部仍成立，1 = 有变化需要人工确认。

- [ ] **Step 1: 写刷新脚本**

新建 `scripts/refresh-time-grounds.mjs`：

```js
// 核时效题基准是否过期：逐条对 NVD published / KEV 目录 / ATT&CK 版本，输出该改的行。
// 用法：node scripts/refresh-time-grounds.mjs        # 只核对，不改文件
//       PROXY=1 node scripts/refresh-time-grounds.mjs  # cisa.gov 走本机 Clash（127.0.0.1:7897）
// NVD 无 key 限流约 5 次/30 秒，因此串行 + 7 秒间隔（与 scripts/verify-suspects.mjs 同一做法）。
import { writeFileSync } from "node:fs";

const KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fetchKev = async () => {
  const opt = process.env.PROXY ? { proxy: "http://127.0.0.1:7897" } : {};
  const r = await fetch(KEV_FEED, { ...opt, signal: AbortSignal.timeout(30000) });
  if (!r.ok) throw new Error(`KEV feed HTTP ${r.status}`);
  return r.json();
};
const nvd = async (id) => {
  const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, { signal: AbortSignal.timeout(20000) });
  if (r.status === 404) return { id, exists: false };
  const d = await r.json();
  const c = d?.vulnerabilities?.[0]?.cve;
  if (!c) return { id, exists: false };
  return { id, exists: true, published: c.published?.slice(0, 10), kevAdd: c.cisaExploitAdd ?? null,
    title: (c.descriptions ?? []).find((x) => x.lang === "en")?.value?.slice(0, 120) };
};

const checked = { at: new Date().toISOString(), nvd: [], kev: {}, changes: [] };
const IDS = ["CVE-2026-21509", "CVE-2026-21514", "CVE-2026-124194", "CVE-2026-34477", "CVE-2026-49844"];
for (let i = 0; i < IDS.length; i++) {
  const r = await nvd(IDS[i]);
  checked.nvd.push(r);
  console.log(`${IDS[i]} exists=${r.exists} published=${r.published ?? "-"} kevAdd=${r.kevAdd ?? "-"}`);
  if (i < IDS.length - 1) await sleep(7000);
}
const feed = await fetchKev();
checked.kev = { catalogVersion: feed.catalogVersion, count: feed.count };
console.log(`\nKEV 目录：版本 ${feed.catalogVersion}，共 ${feed.count} 条`);
const office2026 = feed.vulnerabilities.filter((x) => /^CVE-2026/.test(x.cveID) && /Office/i.test(x.product) && /Microsoft/i.test(x.vendorProject));
console.log(`2026 年微软 Office 的 KEV 条目 ${office2026.length} 条：`);
for (const o of office2026) console.log(`  ${o.dateAdded} ${o.cveID} ${o.vulnerabilityName}`);
if (office2026.length > 1) checked.changes.push(`旗标题 expect.pattern 应覆盖 ${office2026.map((x) => x.cveID).join("|")}（现只认 CVE-2026-21509）`);
const thisWeek = feed.vulnerabilities.filter((x) => x.dateAdded > new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10));
console.log(`最近 7 天 KEV 新增 ${thisWeek.length} 条（"本周有没有新披露高危漏洞"的参考事实）`);

writeFileSync(`dev/time-grounds-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(checked, null, 1), "utf-8");
if (checked.changes.length) {
  console.log(`\n需要人工确认的基准变化：\n- ${checked.changes.join("\n- ")}`);
  process.exit(1);
}
console.log("\n基准仍成立。");
```

- [ ] **Step 2: 跑，拿到真实过期证据**

```bash
cd /f/Qoder/seccopilot && PROXY=1 node scripts/refresh-time-grounds.mjs; echo "exit=$?"
```

Expected: 打印 `KEV 目录：版本 2026.11.13，共 1781 条`、2026 年微软 Office 3 条（含 `2026-11-10 CVE-2026-124194`）、`exit=1` 与"旗标题 expect.pattern 应覆盖 …"。（版本/条数会随目录更新变化，以脚本当天输出为准写文档。）

- [ ] **Step 3: 按输出改基准（两处，且都在注释里记下核校日期与来源）**

`scripts/eval.mjs`：

```js
// 时效题基准核对日：2026-11-14（node scripts/refresh-time-grounds.mjs，留档 dev/time-grounds-2026-11-14.json）。
// 核对时 KEV 目录版本 2026.11.13 / 1781 条；2026 年微软 Office 有 3 条 KEV：
//   CVE-2026-21509（2026-01-26）、CVE-2026-21514（2026-02-10）、CVE-2026-124194（2026-11-10，本地库无）。
// 判据从"只认 21509"改为"三条任一 + 类型对得上"，并额外要求给出该条自身的收录日期：
// 基准过期时尺子会变严或变松，所以日期与来源写在这里，重跑时先看这里再看分数。
{ kind: "time", q: "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？",
    expect: { pattern: "CVE-2026-(21509|21514|124194)", title: "Security Feature Bypass|安全功能绕过|Missing User Interaction|缺乏用户交互" },
    ground: "KEV 目录 2026.11.13 里 2026 年微软 Office 共 3 条：21509（收录 2026-01-26，安全功能绕过）、21514（2026-02-10）、124194（2026-11-10，Outlook 缺乏用户交互）；本地库快照 2026.11.09 只含前两条，故 off 模式答出 21509 即为合格，答出 124194 只能来自现查目录" },
```

"本周有没有新披露的高危漏洞？"那条把 `ground` 改为：

```js
    ground: `核对日 2026-11-14：KEV 目录 2026.11.13，最近 7 天新增见 dev/time-grounds-2026-11-14.json；把 8 月及更早的收录记录说成"本周"即判错（off 模式实测踩过），承认"本地库未覆盖近 7 天、无法确认"同样合格` },
```

同时把 `failIf` 里的"早于本周"边界从写死 `2026-0[1-8]-` 改成按核对日推导的常量，避免下个月又过期：

```js
const EVAL_DAY = process.env.EVAL_DAY ?? new Date().toISOString().slice(0, 10); // 基准核对日，可覆盖
const WEEK_START = (() => { const d = new Date(`${EVAL_DAY}T00:00:00Z`); d.setUTCDate(d.getUTCDate() - 7); return d.toISOString().slice(0, 10); })();
```

并把"本周"那条的 `expect.failIf` 从写死的月份模式换成**按窗口做数值比较的 `withinWeek` 判据**。草稿里我原本写的是 `` `2026-0[1-9]-|${WEEK_START.slice(0, 7)}-0[1-7]` ``，那是错的：它只覆盖每月 1–7 号，会把 8 号之前的日期全部漏判——日期比较不该用正则拼月份。

在 `QUESTIONS` 上方定义常量，并在 `timeAccuracy(e, answer)` 里加分支（那里的 `e` 就是题目对象的 `expect`）：

```js
const EVAL_DAY = process.env.EVAL_DAY ?? new Date().toISOString().slice(0, 10); // 基准核对日，可覆盖
const WEEK_START = (() => { const d = new Date(`${EVAL_DAY}T00:00:00Z`); d.setUTCDate(d.getUTCDate() - 7); return d.toISOString().slice(0, 10); })();
```

```js
  // withinWeek：把"本周/近 7 天"当结论、却只能拿出窗口外的日期，就是错。
  // 沿用既有 QUALIFY 的逐句判定：把历史日期明确标注为"早于本周/不在本周"是合格回答，不得误伤。
  // 旧口径写死 "2026-0[1-8]-"，换个月就自动失效——既可能漏判也可能误伤，数值比较不依赖月份写法。
  if (e.withinWeek) {
    const dates = String(a).match(/20\d\d-\d\d-\d\d/g) ?? [];
    const outside = dates.filter((d) => d < WEEK_START || d > EVAL_DAY);
    bad = outside.length > 0 && String(a).split(/(?<=[。；;\n])/).some((s) =>
      /(本周|这一周|近\s*7\s*天|过去\s*7\s*天)/.test(s) && !QUALIFY.test(s)
      && outside.some((d) => s.includes(d)));
  }
```

"本周"那条的 `expect` 改成 `{ pattern: "CVE-2026-\\d{4,7}", withinWeek: true, admit: <原 admit 不动> }`，并**删掉原 `failIf`**（`timeAccuracy` 里 `bad` 的初值仍由 failIf 分支给出，`withinWeek` 覆盖它即可）。

**新增判据必须同时进 `--selfcheck`**，否则等于允许它空转——这条纪律就写在 eval.mjs 的 selfcheck 注释里（判分器已经骗过我们两次）：

```js
    { name: "把窗口外的收录日期说成本周（应当判红）",
      e: { pattern: "CVE-2026-\\d{4,7}", withinWeek: true },
      a: "本周有新披露的高危漏洞：CVE-2026-34486，KEV 收录于 2026-08-04。", want: false },
    { name: "同样日期但明说早于本周（应当判绿）",
      e: { pattern: "CVE-2026-\\d{4,7}", withinWeek: true,
           admit: "(未覆盖|无法确认)[^。；]{0,24}(本周|近\\s*7\\s*天)" },
      a: "本地库最近一条是 CVE-2026-34486，KEV 收录于 2026-08-04，早于本周（2026-11-14），无法确认本周新增。", want: true },
```

selfcheck 头部把 `EVAL_DAY` 钉成 `2026-11-14`（`process.env.EVAL_DAY ||= "2026-11-14"`）再判——否则"绿"那条会随真实日期漂移，用例本身就成了日期的函数。

最后在 `score()` 生成的报告头打印 `EVAL_DAY` 与 `WEEK_START`，让每份报告自己说明用的是哪个窗口。

- [ ] **Step 4: 用 `--selfcheck` 与翻转对照证明尺子变化可控**

```bash
node scripts/eval.mjs --selfcheck
node dev/check-title-criterion.mjs
BASELINE_JSON=docs/eval-archive/deployed-prompt-only-2026-11-12.json EVAL_JSON=dev/eval-grounds-1114.json \
  node scripts/eval.mjs --rescore --only=on > dev/grounds-rescore.log 2>&1; tail -12 dev/grounds-rescore.log
```

Expected: `判分器自检通过 7/7（含 3 个"必须判红"的方向）`；`共核对 N 行，判定翻转 0 行`；rescore 报告里逐行列出判定翻转（若旗标题从 `false` 翻成 `true`，那是基准覆盖变宽的正常结果，**必须写进报告而不是挑好看的那遍**）。

- [ ] **Step 5: 提交（尺子变更单独一个提交，便于评审者只看这一处）**

```bash
git add scripts/refresh-time-grounds.mjs scripts/eval.mjs
git commit -m "chore(eval): 时效题基准核对到 2026-11-14（KEV 2026.11.13，Office 3 条）

2026-11-10 写死的基准已过期：KEV 目录里 2026 年微软 Office 从 2 条变 3 条，
CVE-2026-124194（11-10 收录）本地库没有。expect.pattern 覆盖三条并集、title 判据补对应类型，
'本周'的日期边界改由 EVAL_DAY 推导而不是写死 2026-0[1-8]-。刷新脚本会串行打 NVD（限流 5 次/30 秒）
和 CISA 目录，核对结果落 dev/time-grounds-<date>.json。"
```

---

### Task 8: 打开发布通道并做发布后回归（含"资源体积"假设的实测）

**已测到的当前状态（2026-11-14）：** `.SecCopilot.qoder.site` 的 `publication` 里 `releaseId` 已存在、最后一次记录的状态是 `readiness: publication_completed` / `published: true` / `canPublish: false`；而 11-12 曾连续 5 次在 `verify_artifact` 超时（`task_deadline_exceeded`）。同时今天线上那道 KEV 题的表现说明**线上跑的仍是加闸门之前的版本**——所以现在必须重试发布，否则 Task 3/4/5/6 的代码只活在本地。

**已排除的假设：** `dist/` 只有 377 KB，所以"data/ 129 MB 导致 artifact 超限"目前**没有证据**；平台只有在明确报 `artifact_size_exceeded` 时才能说超限（本计划不把它写成原因）。要做的只是把大目录排除掉，减少上传面。

**Files:**
- Create: `.qoderignore`（若 Sites 侧确认支持；否则跳过本文件，改由 Step 2 的实测结果决定）
- Modify: `PROVENANCE.md`（记录发布批次与代码提交的对应关系）

**Interfaces:**
- Consumes: MCP `mcp__plugin_sites_qoder_sites__prepare_site` / `publish_site` / `get_publish_status` / `get_operation`（参数名是 `operationId`，不是 `operation_id`；11-14 已因这个拼写被拒一次）。
- Produces: 线上站点包含 `git log` 里 `HEAD` 的那次提交；`dev/online-kev-<date>.json` 合规；`npm test` 默认站点全绿。

- [ ] **Step 1: 发布前把"可本机自证"的部分全绿**

```bash
cd /f/Qoder/seccopilot && npm run build && npm run check:function && SKIP_LLM=1 npm test 2>&1 | tail -4
SITE=http://127.0.0.1:8000 npm test 2>&1 | tail -8
SITE=http://127.0.0.1:8000 N=4 node scripts/probe-online-kev.mjs; echo "kev_exit=$?"
```

Expected: build 与 typecheck 无错误；本机全量回归只允许"网络来源质量"类失败（第 8 条缺陷已改断言，应也绿）；`kev_exit=0`。**任一红项都要在 `PROVENANCE.md` 记成"发布批次已知限制"，不能带着未说明的红项上线。**

- [ ] **Step 2: 上传面测量（把假设变成数据）**

```bash
cd /f/Qoder/seccopilot
printf "%s\n" "dist=$(du -sk dist | cut -f1)KB data=$(du -sk data | cut -f1)KB vendor=$(du -sk vendor 2>/dev/null | cut -f1)KB node_modules=$(du -sk node_modules | cut -f1)KB"
ls dist/assets | head -8
```

Expected: 得到四个目录的 KB 数。把结果写进 `PROVENANCE.md` 一行：`2026-11-XX 上传面测量：dist=…KB、data=…KB、vendor=…KB（node_modules 不参与上传）`。只有当平台真的返回 `artifact_size_exceeded` 时才创建 `.qoderignore`（内容 `data/`、`dev/`、`*.log`），并在文档里写"由本次错误码触发"，不要提前写成原因。

- [ ] **Step 3: 重试协议（严格按 memory 规则，两次同超时即停）**

1. `mcp__plugin_sites_qoder_sites__prepare_site`：传 `projectPath`，**不传 `projectId`**（沿用 11-12 学到的约束）。
2. 记录返回的 `operationId`，用 `get_operation({ operationId })` 轮询，间隔 ≥20 秒，最多 6 次。
3. `publish_site` 同样拿 operation 句柄轮询；`get_publish_status` 作为最终状态。
4. **判定：** 第一次失败就重试一次；第二次仍然是同一校验（`verify_artifact`）同样超时 → 停止重试，把两次 `operationId`、错误码与时间写进 `PROVENANCE.md`，向用户报阻塞，并继续 Task 9/10/11 里不依赖发布的工作（视频可先拍本地路径，作品帖草稿可先写好但不发）。
5. 不做的事：不换站点、不删站点重建、不释放后端、不用"本地预览"冒充线上。

- [ ] **Step 4: 发布成功后立刻做线上回归（把"线上跑的是哪一版"钉死）**

```bash
cd /f/Qoder/seccopilot && npm test 2>&1 | tail -10          # 默认打线上
N=6 node scripts/probe-online-kev.mjs; echo "kev_exit=$?"
git log -1 --format="%H %ad" --date=iso
```

在 `PROVENANCE.md` 追加一行：`线上 release <releaseId> ← 提交 <hash>（<日期>），回归 <pass>/<total>，KEV 探针 <ok>/6`。**如果 KEV 探针仍不合规，把不合规的那几次原文留档并写进缺陷清单，不要只更新分数。**

- [ ] **Step 5: 提交文档**

```bash
git add PROVENANCE.md .qoderignore 2>/dev/null || git add PROVENANCE.md
git commit -m "chore(release): 发布批次对应提交与线上回归结果留档"
```

---

### Task 9: 线上同题评测与文档数字同步（把报告的两列合回"同一版本"）

**为什么要重跑：** 现在 `docs/eval-report.md` 的一列来自本地 harness（`http://127.0.0.1:8000`，闸门版），另一列的对照基线来自 11-12 线上（`prompt-only`）。Task 3–6 发布后，两份数字描述的已经不是同一个版本；报告里必须写清"哪个版本、哪一天、尺子是哪一版"，否则数字没法读。

**Files:**
- Modify: `docs/eval-report.md`（由 `scripts/eval.mjs` 重新生成，不手改数字）
- Modify: `docs/eval-report.json` → 先备份为 `docs/eval-archive/deployed-<date>.json`，让线上证据不被覆盖
- Modify: `docs/competition-post.md`、`README.md`、`docs/demo-script.md`（数字与措辞同步）

**Interfaces:**
- Consumes: `SITE`（线上默认，无需设置）、`EVAL_JSON`、`BASELINE_JSON`、`EVAL_OUT`。
- Produces: `docs/eval-archive/deployed-<date>.json`（含 `meta.site`，Task 8 之后新留档都会带）与新生成的 `docs/eval-report.md`。

- [ ] **Step 1: 备份线上证据，再跑线上评测**

```bash
cd /f/Qoder/seccopilot
cp docs/eval-report.json dev/eval-report-before-$(date +%F).json   # 本机留底，不入库
EVAL_JSON=docs/eval-archive/deployed-$(date +%F).json EVAL_OUT=docs/eval-report.md \
  BASELINE_JSON=docs/eval-archive/deployed-prompt-only-2026-11-12.json node scripts/eval.mjs 2>&1 | tail -25
```

Expected: 21 题 × 2 模式跑完；报告头站点显示线上域名；附"对照基线"一节并列出判定翻转的行。**若某轮 `mode=on` 少题（11-12 出现过少一题、挂的正是 KEV），照原样写进报告，不要为了对齐题数改题库。**

- [ ] **Step 2: 可疑编号必须逐条回权威源**

```bash
node scripts/verify-suspects.mjs 2>&1 | tail -20
node scripts/verify-id-name-pairs.mjs 2>&1 | tail -20
```

Expected: 每个 CVE/CWE/ATT&CK 编号在 NVD / MITRE 命中；`verify-id-name-pairs.mjs` 核"编号与名称配对"。任何未命中项按编号写进 `docs/competition-post.md`（历史上 T1214 就是这条抓出来的：编号真、结论贴错也算缺陷）。

- [ ] **Step 3: 判分口径变化要用翻转表证明不是尺子带来的分数变化**

```bash
node scripts/eval.mjs --rescore --selfcheck > /dev/null; node scripts/eval.mjs --selfcheck
node dev/check-title-criterion.mjs
EVAL_JSON=docs/eval-archive/deployed-$(date +%F).json node scripts/eval.mjs --rescore --only=on 2>&1 | grep -A20 "判定翻转" | head -25
```

Expected: 自检 7/7；翻转核对为 0 行或明确列出；报告中"分数变化来自代码还是来自尺子"这一句必须引用这些数字。

- [ ] **Step 4: 文档同步（一次改完四处，避免数字打架）**

四处必须同批提交：`docs/eval-report.md`（脚本生成）、`docs/competition-post.md`、`README.md`、`docs/demo-script.md`。规则沿用既有纪律：

- 每个数字旁边写清来源留档文件名与日期；
- 较差的一轮作为主口径，另写"另外一轮更好"；
- 未发布的修复不许写成已达成分数；
- 自己写错的结论要写成"我们一度以为…，回查确认没有"这种带撤回的句式（现有文档里已有两处，别删）。

- [ ] **Step 5: 提交**

```bash
git add docs/eval-report.md docs/eval-report.json docs/eval-archive scripts/eval.mjs docs/competition-post.md README.md docs/demo-script.md
git commit -m "docs: 发布后线上同题评测留档与数字同步"
```

---

### Task 10: 5 分钟演示视频（拍之前先确认要演示的路径当天是绿的）

**为什么排在评测之后：** 今天线上的旗标题给不出编号。若照 `docs/demo-script.md` 现在的顺序拍，会把第 9 条缺陷拍进作品里。所以先测、再改脚本、再拍。

**Files:**
- Modify: `docs/demo-script.md`（按发布后实测结果调整台词数字，尤其 4:40 前后那张表）
- Create: `docs/demo/shotlist.md`（镜头清单 + 每题的实际回答摘要，便于重录时对比）

**Interfaces:**
- Consumes: 发布后的线上站点（真实演示走线上，本地 harness 只做兜底）；录屏工具用本机已有能力，不新装。
- Produces: `docs/demo/shotlist.md`；视频文件（放仓库外，作品帖上传用）。

- [ ] **Step 1: 生成镜头清单前先跑一遍"要演示的那几问"**

```bash
cd /f/Qoder/seccopilot
node scripts/probe-online-kev.mjs; echo "exit=$?"
for q in "T1059 是什么技术？" "MITRE ATT&CK 初始访问阶段有哪些技术？" "本周有没有新披露的高危漏洞？" "最近有哪些已被确认在野利用的 Apache 产品漏洞？"; do
  echo "--- $q"
  curl -s -X POST "https://seccopilot-kpa8w0w9u7e.qoder.zone/functions/v1/app?action=chat" \
    -H "Origin: https://seccopilot-kpa8w0w9u7e.qoder.zone" -H "Content-Type: application/json" \
    -d "{\"question\":\"$q\",\"mode\":\"auto\"}" 2>&1 | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const j=JSON.parse(s);console.log('coverage',j.coverage,'| src',(j.sources||[]).length,'| web',(j.web_sources||[]).length,'|',(j.answer||'').slice(0,140).replace(/\n/g,' '))})"
done
```

Expected: 每题都有可点击来源、KEV 题给出编号与日期。任何一题退化 → 把它从镜头清单里去掉或换成 `mode=off` 的本地覆盖题，并在 `docs/demo/shotlist.md` 写明"因当日实测退化未演示 X"。

- [ ] **Step 2: 写镜头清单（含每镜的实测摘要）**

`docs/demo/shotlist.md`：

```markdown
# 5:00 演示镜头清单（每镜附当日实测摘要，日期：____）

| 时间 | 镜 | 说什么 | 屏幕上必须出现 | 当日实测 |
| --- | --- | --- | --- | --- |
| 0:00–0:35 | 开场 | 三层来源 + 为什么要闸门 | stats 面板 5,397 条 | |
| 0:35–1:30 | 本地库问答 | CVE 元数据与 CWE 精确锚定 | 引用可点击、来源分组 | |
| 1:30–2:20 | 联网问答 | Log4j 2026 批次 | web_sources 含权威域名 | |
| 2:20–3:10 | KEV 旗标题 | 编号 + 收录日期 + 代码核验补充 | CVE-2026-21509（2026-01-26） | probe 退出码 |
| 3:10–3:50 | 拒答与降级 | 域外问题不编编号、零来源时不声称联网 | note 文案 | |
| 3:50–4:40 | 质量怎么保证 | 回归 + 评测 + 缺陷清单（含红项） | 表格与留档文件名 | |
| 4:40–5:00 | 收尾 | 局限与下一步 | | |
```

- [ ] **Step 3: 录制与一次重录预算**

按清单录屏（画面 + 旁白），文件命名 `seccopilot-demo-<版本>-<日期>.mp4`，存仓库外目录（避免大文件入库）。录完立刻做两项自检：时长 ≤5:00；关键三帧（stats 数字、KEV 回答、缺陷表）逐帧核对与文档一致。**只允许一次重录预算**，若第一次就因为线上退化而废，按 Step 1 换题后重录，不做第三次打磨。

- [ ] **Step 4: 文档同步 + 提交**

`docs/demo-script.md` 顶部加一行"配套镜头清单与当日实测见 `docs/demo/shotlist.md`"；数字若与 `docs/eval-report.md` 不同批，以报告为准改脚本。

```bash
git add docs/demo/shotlist.md docs/demo-script.md
git commit -m "docs(demo): 演示镜头清单，含录制前实测门槛"
```

---

### Task 11: 天池作品帖发布与最终检查单

**Files:**
- Modify: `docs/competition-post.md`（发布版定稿：数字以 Task 9 的留档为准）
- Modify: `README.md`（顶部加"在线地址 / 演示视频 / 仓库"三条）
- Modify: `PROVENANCE.md`（最终：提交 ↔ 线上 release ↔ 留档文件 对应表）

- [ ] **Step 1: 定稿前逐条核对（每一项都要有文件级证据，不能凭印象）**

```bash
cd /f/Qoder/seccopilot
node scripts/eval.mjs --selfcheck
node dev/check-title-criterion.mjs
node dev/check-kev-samples.mjs
node scripts/probe-online-kev.mjs; echo "exit=$?"
SKIP_LLM=1 npm test 2>&1 | tail -4
npm test 2>&1 | tail -6
```

Expected: 全部有输出且与文档里写的数字逐字对得上（脚本输出里的计数是文档里唯一允许的数字来源）。

- [ ] **Step 2: 作品帖正文的三条硬要求**

1. 在线地址指向发布后的站点，并写明"线上版本对应提交 `<hash>`、发布批次 `<releaseId>`"；
2. 缺陷清单原样保留（含红项与未修复项），不许"演示时只挑好的"；
3. 复现路径只写仓库里真实存在的命令，`data/.env` 与 `dev/` 未入库这一事实必须写清（否则评审者按文档跑不通）。

- [ ] **Step 3: 若决定公开仓库，先轮换 key，再推**

顺序不能反：先 Sites 侧更新 `DASHSCOPE_API_KEY` Secret → 本地 `data/.env` 换新 key → 本机 harness 冒烟一次 → 确认 `git ls-files | grep -Ei "\.env|jsonl"` 为空 → 推远端。

```bash
git ls-files | grep -Ei "\.env|data/|\.jsonl$" || echo "OK：无凭据与大数据被追踪"
git log --all --oneline | wc -l
```

Expected: 打印 `OK：无凭据与大数据被追踪`。若历史里出现过任何 key（`git log -p --all -S "sk-" | head`），不要直接公开，改为新建一个只含当前快照的初始提交。

- [ ] **Step 4: 发布作品帖（需要用户确认后执行）**

内容用 `docs/competition-post.md` 定稿；配图用 `docs/demo/shotlist.md` 里已核对过的三帧截图；视频链接指向 Task 10 产物。**发布动作本身要用户点确认**——本计划只准备可发布稿。

- [ ] **Step 5: 最终提交**

```bash
git add docs/competition-post.md README.md PROVENANCE.md
git commit -m "docs: 作品帖定稿与交付检查单（数字全部指向可重跑脚本与留档）"
```

---

## Self-Review（写完后按 spec 与纪律复查）

**Spec coverage：** `docs/superpowers/specs/2026-11-10-…-design.md` 的三条主线里，数据扩充与前端展示已完成（11-12 之前）；本次覆盖"联网可核验性"（Task 6）、"KEV 断言门槛"（Task 3/4）、"评测与交付"（Task 7–11）、"静默失败禁止"（Task 5 + Task 3 的 `unavailable` 区分 + Task 6 的空来源分支）。已知 spec 内未排期的项：general 类知识扩充、`stats` 面板图表化——两者都不影响截止，留给赛后。

**Placeholder scan：** 无 TBD/TODO；`docs/demo/shotlist.md` 表格里的"当日实测"列是留给录屏当天填的真实数据（明确要求填实测值，不许预填）；Task 8 Step 3 的轮询次数与 Task 10 Step 3 的重录预算都给了具体数字。

**Type consistency：** Task 3 定义 `KevEntry` / `kevCatalog` / `kevLookup` / `kevFromCatalog` / `KEV_SNAPSHOT_VERSION`，Task 4 使用的正是 `kevLookup(ids)` 返回的 `{confirmed, absent, unavailable}` 与 `KevEntry` 字段名（`cveID`、`vendorProject`、`dateAdded`、`dueDate`、`requiredAction`）；Task 4 的 `kevCorrection` 签名与用例里传的对象形状一致；Task 6 的 `webGrounding` 返回 `{coverage, note}` 与 `ChatPayload` 字段同名；Task 5 的 `aggregateStats` 返回 `{status, data}`，与 `routes.ts` 里既有的 `EndpointResult` 形状一致，`handler.ts` 无需改。

**必须记住的两条纪律（每个任务都适用）：** 未发布的修复不许写成已达成分数；判分口径变化必须用 `BASELINE_JSON=` 的翻转表证明分数变化来自代码。
