# SecCopilot - 安全研究智能助手

面向安全研究者的 AI 问答助手。回答只依据检索到的资料生成，并区分标注"知识库来源"与"网络来源"。

在线地址：<https://seccopilot-kpa8w0w9u7e.qoder.zone>

## 功能特性

- **智能问答（RAG）**：向量检索定位权威条目，大语言模型基于检索内容作答，每条回答附可点击来源
- **三层知识来源**：本地精编知识库 → 冷门 CVE 现查 NVD 官方 API → 时效性问题联网检索
- **来源策略开关**：自动联网 / 强制联网 / 仅知识库三态，可复现地对比"搜索前 vs 搜索后"
- **CVE 漏洞查询**：按编号、名称、受影响产品检索，展示 CVSS 与 CISA KEV 在野利用信息（含修复期限）
- **ATT&CK 战术浏览**：按战术浏览技术，含检测方法与缓解措施
- **知识库统计**：分类规模与占比

## 技术栈

- **前端**：React 19 + TypeScript 5.9 + TailwindCSS 4 + Vite 8
- **后端**：Qoder Sites Serverless Functions（Deno edge runtime，多文件目录）
- **向量数据库**：Supabase（PostgreSQL + pgvector，1024 维，IVFFlat）
- **嵌入与生成**：阿里云 DashScope 通义千问 —— `text-embedding-v3` 做向量，`qwen-flash`/`qwen-plus` 做生成
- **联网检索**：DashScope 原生协议 `enable_search`（非 OpenAI 兼容模式，后者不返回 `search_info`）

## 快速开始

### 1. 环境准备

```bash
npm ci                 # Node 依赖
cd data && pip install -r requirements.txt && cd ..
```

### 2. 配置环境变量

本地开发把密钥放在 `data/.env`（勿提交）；部署后在 Qoder Sites → 项目 → Settings 中以"变量"形式配置同名密钥：

- `APP_SUPABASE_URL` - Supabase 项目 URL
- `APP_SUPABASE_ANON_KEY` - Supabase 匿名密钥
- `DASHSCOPE_API_KEY` - DashScope 密钥（嵌入 + 生成 + 联网检索共用）

> `SUPABASE_`、`POSTGRES_`、`QODER_` 前缀与 `DATABASE_URL` 是平台保留名，因此这里带 `APP_` 前缀。

### 3. 初始化数据库

在 Supabase SQL Editor 中执行 `supabase-schema.sql`（建表、RPC `match_documents` / `search_cves` / `search_attacks` 与向量索引）。

### 4. 构建知识库数据

```bash
# 基础数据（ATT&CK + 精选 CVE）
cd data && python build_kb.py && python reimport.py && cd ..

# 扩充数据：CISA KEV + MITRE CWE + arXiv cs.CR
python data/collect_phase2.py all      # 只采集，产出 data/phase2_raw.json
python data/import_phase2.py --dry-run # 先看计划，不写库
python data/import_phase2.py           # 算向量并入库，可安全重跑
```

`import_phase2.py` 按语义主键（CVE 编号 / CWE 编号 / arXiv ID）跳过已存在记录，向量结果缓存在 `data/phase2_emb.jsonl`，中断后重跑不会重复计费。
网络要求：Supabase 走本机代理 `127.0.0.1:7897`，DashScope 直连。

### 5. 本地开发与自检

```bash
npm run dev                 # 前端
npm run check:function       # Function 类型检查（tsc -p tsconfig.functions.json）
npm run typecheck            # 前端类型检查

# 本地跑 Function（免装 Deno，端口 8000）。Node 24 的 fetch 默认不认代理变量，
# 要打真实 Supabase 必须显式注入；DashScope / NVD 反过来要用 NO_PROXY 绕开代理：
NODE_USE_ENV_PROXY=1 HTTP_PROXY=http://127.0.0.1:7897 HTTPS_PROXY=http://127.0.0.1:7897 \
  NO_PROXY=dashscope.aliyuncs.com,nvd.nist.gov,services.nvd.nist.gov npm run dev:function:node

npm test                     # 对线上站点跑回归套件（node --test）
SITE=http://127.0.0.1:8000 npm test      # 对仓库当前源码跑同一套回归
SKIP_LLM=1 npm test          # 只跑只读/纯函数用例，不调用大模型、零费用
```

### 6. 构建部署

```bash
npm run build   # tsc --noEmit + 静态导出到 dist/
```

发布通过 Qoder Sites 完成：`prepare_site`（新 actionId，`webDirectory: dist`、`functionDirectory: functions`、`databaseAccess: none`、声明上述三个密钥名）→ `publish_site` → `get_publish_status` 直到 `published: true`。

## 项目结构

```
seccopilot/
├── src/
│   ├── components/
│   │   ├── ChatPanel.tsx     # 问答 + 三态来源策略 + 双组引用展示
│   │   ├── CvePanel.tsx      # CVE 检索（含 KEV 在野利用徽标与修复期限）
│   │   ├── AttackPanel.tsx   # ATT&CK 战术浏览
│   │   └── StatsPanel.tsx    # 知识库统计
│   └── App.tsx
├── functions/                # Qoder Sites Function（Deno edge，多文件）
│   ├── index.ts              # 入口：Deno.serve(handler)
│   ├── handler.ts            # 路由与密钥读取
│   └── lib/
│       ├── chat.ts           # 三层检索编排 + 联网判定策略
│       ├── dashscope.ts      # 嵌入 / 生成 / 联网检索 / 来源域名分层
│       ├── kb.ts             # 向量、编号精确、关键词兜底、NVD 实时查询
│       └── routes.ts         # stats / cve / attack 只读接口
├── dev/function-node.ts      # Node 侧 Deno 适配，本地跑同一份 Function
├── scripts/regression.test.mjs   # 零依赖回归套件
├── data/                     # 采集、嵌入、入库脚本
└── supabase-schema.sql
```

## API 接口

```
POST /functions/v1/app?action=chat
Body: { "question": "...", "category": "cve|attack|cwe|paper|null", "mode": "auto|on|off" }
Response: {
  "answer": "...",
  "sources":      [{ "title", "url", "category", "similarity", "live" }],
  "web_sources":  [{ "index", "title", "url", "site", "rank" }],
  "search_used": true, "mode": "auto",
  "coverage": "local|mixed|web", "note": "..."
}

GET  /functions/v1/app?action=cve&q=<查询词>
GET  /functions/v1/app?action=attack&tactic=<战术>&technique=<T 编号>
GET  /functions/v1/app?action=stats
```

`mode` 缺省为 `auto`。自动策略下，本地命中不足或问题涉及时效（"最新""刚披露""CVE-2026-"等）才会联网，避免不必要的检索开销与权威引用被污染。

## 数据来源

| 类别 | 条数 | 来源 | 说明 |
| --- | --- | --- | --- |
| CVE 漏洞 | 1,774 | CISA KEV 官方目录 + 精选 NVD 高危条目 | 已确认在野利用，含厂商/产品/修复期限/勒索软件利用标记 |
| ATT&CK | 867 | MITRE ATT&CK | 战术/技术/检测/缓解 |
| CWE 弱点 | 956 | MITRE CWE 5.0 官方 XML | 漏洞 → 弱点 → 技术 → 缓解 链条 |
| 安全论文 | 1,800 | arXiv cs.CR | 按提交时间取最新条目摘要 |
| CVE 补充 | 按需 | NVD API 2.0 | 冷门编号现查，标记为"实时上游"，不落库 |
| 网络检索 | 按需 | DashScope `enable_search` | 时效性问题；来源标注"未经知识库校验" |

合计 5,397 条（`GET ?action=stats` 可实时核对）。

## 质量与验证

- `npm test`：29 项回归，默认打线上接口，`SITE=http://127.0.0.1:8000 npm test` 打本地跑的仓库当前源码（含联网响应契约、KEV 字段前缀、T1059 父技术排序、CWE 编号精确锚定、`mode=off` 不得声称联网、时效题日期基准、`mode=off` 不得把"本地库没记录"答成"现实中不存在"、问某阶段时不得列入别的技术、"在野利用"必须有 KEV 证据）；`SKIP_LLM=1 npm test` 跑 12 项只读/纯函数用例、跳 17 项。2026-11-12 本地源码跑了 5 次：**三次 27/29、判分口径修正后一次 29/29、下午上游网络来源变空之后又一次 27/29**（这一轮留了日志 `dev/test-run5.log`；前四轮的输出只在终端看过、没留档，所以现在每个探针都落文件），红项有三个根因——① `stats` 的分类计数被 `catch { return 0 }` 兜住（`functions/lib/routes.ts:25`），上游超时或并发排队时那一类静默变 0：有一轮分类求和 3597 ≠ total 5397，第五轮只有 `cwe` 拿到数、求和 956 ≠ 5397，而单独重打 6 次 `action=stats` 是第一次 `total: 0`、后五次 5397（真缺陷，未修：改法会动响应契约）；单独连测线上 3 次都是正确的 5,397；② 三条依赖模型输出的用例随检索/采样波动，其中两处经回答原文复核确认是判分器假阳性（把已否定的句子、已限定"本地知识库"的句子判成违规），口径改为按句判定并在用例里同时钉住"必须判红"和"必须判绿"两个样本；③ 下午起 `chat：响应含联网搜索契约字段` 稳定红——直接打 DashScope 原生协议（`dev/probe-websearch-shape.mjs`）看到 `usage.plugins.search` = `{"count":1,"strategy":"max"}` 而 `search_info.search_results` 是空数组：搜索插件执行了、上游没返回来源清单，于是 `mode=on` 的 10 次采样 `web_sources` 全 0 条，而响应仍是 `search_used: true`、`note` 仍写"结合本地知识库与网络检索作答"。这条用例把"插件执行过"当成"有可核验来源"，断言和 `note` 措辞都得改（会动用户可见文案，未改），详见 `docs/competition-post.md` 第六节第 8 条缺陷。线上已发布版本另有几项红，那是那三段代码闸门还没发布上去——用例红能定位到"代码没上去"，不是"代码不管用"。
- `node scripts/eval.mjs`：21 题在 `mode=off` / `mode=on` 下各跑一遍，输出引用命中、时效题是否答中该题 ground truth（逐条对过 NVD 接口，见报告末尾"时效题基准"表）、域外题拒答是否正确，以及回答编号是否出现在引用来源里（疑似幻觉检测）；回答原文一并落到留档（默认 `docs/eval-report.json`，`EVAL_JSON=` 可换路径）便于人工复核，报告写入 `docs/eval-report.md`。`--rescore` 只按当前判分口径重算时效题、不重打模型；`BASELINE_JSON=` 会在报告里附"同一份判分代码打两份留档"的对照表和逐行判定翻转清单——改判分口径时必须用它证明分数变化来自代码而不是来自尺子。`--only=` 只接受模式名（`off` / `on` / `auto`），`--grep="子串"` 才按题目关键字取子集；两者都会被校验：非法模式名、关键字零命中、以及 `--grep` 没配 `EVAL_JSON=` 时直接退出——今天有人把 `--only=` 当题目过滤器用，未知值被 Function 侧 `normalizeMode` 归成 `auto`，于是静默跑完整套 21 题、留档里的 `mode` 字段还是个假模式名（子集留档若覆盖 `docs/eval-report.json`，就会把当前报告所依据的那一整轮 42 条回答换成一题的样本——现在这份文件装的是"本地 harness·闸门版第二遍"，线上已发布版本的证据在 `docs/eval-archive/deployed-prompt-only-2026-11-12.json`）。时效题判据里 KEV 那道还带 `title`（编号之外要求漏洞类型和官方名对得上，防"编号真、类型挂错"），配套 `node scripts/eval.mjs --selfcheck` 用 7 条合成样本钉住判分器本身——3 条必须判红（类型挂错、没提到该编号、旧日期未加限定）、4 条必须绿，不发网络请求；这条判据是**预防性收紧**，不是修已测到的缺陷：`node dev/check-title-criterion.mjs` 把四份留档那道题的 8 行逐行重算，判定翻转 0 行（一旦翻转会以非 0 退出码报出来）。留档 JSON 现在带 `meta.site / meta.modes / meta.questions / meta.rescore`：`--rescore` 生成的报告头部只认留档里的 `meta.site`（与本次 `SITE=` 不一致就打印警告并按留档写），因为 11-12 当天我们自己就用没带 `SITE=` 的 `--rescore` 把"本地 harness 闸门版"的留档标成了"线上已发布版本"——数字没错、来源声明错了。
- `node scripts/verify-suspects.mjs`：把评测标为可疑的安全编号逐条拿去 NVD / MITRE CWE / MITRE ATT&CK 验真（判据要求 CWE/T 的官方页面 200 **且正文含该编号**，MITRE 的 404 页同样返回 200）。
- `node scripts/verify-id-name-pairs.mjs`：验"编号 ↔ 名称"是否配对，机械抓同一条回答里一个编号挂多个名称、一个名称挂多个编号、以及英文名与官方名不符三类问题；编号真实不等于引用正确，这一步就是为此而加的。
- `node scripts/probe-online-kev.mjs`：线上（或 `SITE=http://127.0.0.1:8000` 本机）KEV 旗标题连跑 N 次（`N=` 可调，默认 6），逐次记录"给出编号 / 给出收录日期 / 类型对得上 / 是否降级表述 / 检索结果里本来有没有该编号"，留档 `docs/eval-archive/online-kev-<date>.json`，有不合规即退出码 1。判据与 `scripts/eval.mjs` 那道 KEV 题同源，不随结果松紧。**2026-11-14 线上实跑**：`N=3` 3/3 合规，按"任一次给出编号即扩样"再跑 `N=6` 仍 6/6 合规、`srcHasId` 6/6、`nSrc:5`、`nWeb:2`、退出码 0——即这道题当天线上是答对的，计划里"0/3 合规"的预期没有复现出来，我们也没有改判据去凑红。当天更早那条零编号回答的原始留档（`dev/online-kev-2026-11-14.json`，`dev/*.json` 不入库）显示它那 5 条来源是 `functions/lib/kb.ts:123` 的关键词兜底（`similarity` 恒 0.3、里面没有 CVE-2026-21509），所以根因是**语义检索空集→兜底→如实拒答**，不是"检索拿到了、回答没用上"；这条归因修正记在 `docs/competition-post.md` 第六节第 9 条缺陷。
- `supabase-retrieval-fix.sql`：向量检索召回修复。IVFFlat `lists=100` 默认只探 1 个 list，实测不限定分类时 `T1059` 返回 0 行、限定 `category='attack'` 返回 200 行；该脚本把 `ivfflat.probes` 提到 100 并把相似度阈值改成显式参数。
- `dev/probe-kev-on-batch.mjs [次数] [mode]`：把"2026 年被 CISA 确认在野利用的微软 Office 漏洞"这道题连采 N 次，逐次留档"是否列出 CVE-2026-21509 / 是否给出 KEV 收录日期 / 检索结果里有没有它 / 网络来源几条"（`dev/kev-on-batch.json`、`dev/kev-off-batch.json`）。作品帖里"10 次采样 2 次不照闸门说""`web_sources` 10 次全 0"这两句就是从这里来的。留档字段 `hasKevDate` 原来的正则只认 `2026-01-26`、漏掉"2026年1月26日"，会让"给了日期"被记成没给（6 次里只报 2 次），现改成两种写法都认。
- `dev/check-kev-samples.mjs`：不发网络请求，把上面那批留档（6 次批量 + 3 个 txt + 1 个 `--grep` 子集 + 4 次 `off`）按**回答正文**重新数一遍，输出"提到 21509 / 给出收录日期 / `web_sources` 条数"，并打印两份闸门版留档那道题的 `accuracy`。作品帖里"on 10 次全都列出并给出日期""10 次全 0""12 次采样 2 次不照闸门说"三句以它为准——2026-11-12 实跑：on 10/10、nWeb>0 0 次、off 4/4、run1 `accuracy=true`（结论被降级但旧判据放行）、run2 `accuracy=false`。
- `dev/probe-websearch-shape.mjs`：绕开本项目直接打 DashScope 原生协议，打印 `usage.plugins.search` 与 `output.search_info.search_results`，用来区分"上游搜索没执行"和"执行了但没返回来源清单"——第六节第 8 条缺陷的定性靠它。
- `dev/check-title-criterion.mjs`：新增判据（KEV 题的 `title`）离线重算四份留档那道题的 8 行，输出"判定翻转 N 行"，N≠0 时非 0 退出。加判据时必须先跑它，才能把"预防性收紧"和"修好了一个已测到的缺陷"分开写——2026-11-12 实跑结果 0 行翻转。

## 文档

- `docs/demo-script.md`：5 分钟演示视频分镜与口播稿
- `docs/competition-post.md`：天池作品帖初稿（踩坑记录与每个数字的出处）
- `docs/eval-report.md`：21 题 off/on 对照评测结果（含线上版与本地闸门版的对照表、时效题 ground truth 基准表）
- `docs/eval-archive/`：各轮评测的原始回答留档（`deployed-prompt-only-2026-11-12.json` = 线上"只改提示词"版，`local-guards-run1-2026-11-12.json` / `local-guards-run2-2026-11-12.json` = 加三道代码闸门的本地版两份独立采样，`online-kev-2026-11-14.json` = 线上 KEV 旗标题探针的 6 次逐次留档），判分争议都从这里回查原文
- `docs/superpowers/specs/2026-11-10-seccopilot-websearch-and-data-design.md`：联网检索与数据扩充的设计文档（含实测证据）

## 比赛信息

本项目参加 **2026 Qoder 高校创造力大赛**（StudyHack 学习科研赛道，天池赛题 532395）。

- 作品提交截止：2026-11-30 18:00
- 详细赛程与奖项以天池官网赛题页为准

## 许可证

MIT License
>>>>>>> 5772364 (chore: 建立 git 仓库与忽略规则，先挡住 data/.env 与 129 MB 数据目录)
