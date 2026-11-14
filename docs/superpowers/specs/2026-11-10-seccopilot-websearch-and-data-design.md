# SecCopilot 联网搜索与数据扩充设计

日期：2026-11-10 ｜ 状态：已与用户确认范围（Phase 1+2+3 全做，采集与导入由 agent 直接执行）
截止：2026-11-30 18:00 作品发布 ｜ 赛题：2026 Qoder 高校创造力大赛 · StudyHack 赛道

## 1. 问题定义

现状是一个已经跑通的 RAG 系统：870 条知识（867 ATT&CK + 3 CVE + 0 论文），Supabase pgvector 检索，DashScope 生成，Qoder Sites 公开访问，10/10 回归测试通过。

三个减分项，按严重性排序：

1. **宣称与实现不符**（最致命）。README 与 UI 都写"CVE 漏洞库 + 安全论文知识库"，统计页会把 `cve: 3 / paper: 0` 直接摊在评委面前。数据少是完成度问题，宣称不符是诚信问题。
2. **知识覆盖不足**，冷门 CVE 与论文类问题无源可引。
3. **无时效能力**。模型参数截止于 2024，问"2026 年新披露的漏洞"时不搜索会自信地否认 2026 年存在。

第三点已被实测证实（见 §3 证据），它同时是本次最出彩的改进方向。

## 2. 目标架构：三层知识来源

```
用户问题
   │
   ├─ 第 1 层 本地精编知识库（Supabase pgvector，1024 维）
   │          权威、可引用、有官方 URL：ATT&CK / KEV / CWE / arXiv
   │
   ├─ 第 2 层 结构化上游实时查询（Function 直连公开 API，不落库）
   │          NVD API 2.0（冷门 CVE 现查）、arXiv API（最新论文）
   │
   └─ 第 3 层 通用网页检索（DashScope 原生协议 enable_search）
              时效性问题、知识库外问题；来源标注"未经知识库校验"
```

设计原则：**不追求条目数量堆量，追求"权威 + 新鲜 + 分层可核验"**。42 万条 NVD 全量入库被否决——embedding 成本与检索噪声都不划算，且把实时数据变成静态快照恰好违背"时效性"这个真实需求。

## 3. 关键证据（2026-11-10 实测）

DashScope **原生协议**（`/api/v1/services/aigc/text-generation/generation`）开启联网搜索后：

| 调用 | input_tokens | search_info | 回答内容 |
| --- | --- | --- | --- |
| qwen-plus 不开搜索 | 45 | 无 | 坚称"现在是 2024 年，2026 尚未到来"，否认存在 2026 公告 |
| qwen-plus turbo + forced_search | 6,208 | 7 条来源 | 给出 CVE-2026-34477…34481、log4j 2.25.5 / 2.26.1 修复版本 |
| qwen-flash max | 4,703 | 有 | 正确说明 Issue #4255 未被分配 CVE |
| qwen-flash turbo + enable_citation | 5,609 | 7 条来源 | 正文带 `[1]` 角标 |

结论四条：

- 搜索确实发生（`usage.plugins.search.count = 1`，input_tokens 从 45 涨到 6,208）。
- 来源列表在 **`output.search_info.search_results`**，字段为 `index / title / url / site_name / icon`，可直接渲染成可点击引用。
- **compatible-mode 拿不到 `search_info`**（实测顶层与 choices 均无），必须走原生协议。现有 Function 的 embedding 调用已经在用原生协议，同一把 key、同一套 fetch，零新增依赖、零新增密钥。
- `enable_citation` + `citation_format: "[<number>]"` 让正文自带角标。

已知风险：默认搜索引擎返回的来源里 CSDN 博客占比高（实测 7 条中 5 条），安全场景下把博客当权威来源会掉可信度 → 见 §5 域名权重。

数据源可达性（本机直连与 Clash 代理均 200）：CISA KEV 1,773 条（其中 201 条为 CVE-2026 编号）、MITRE CWE `cwec_latest.xml.zip`、NVD API 2.0（全量 421,929，`keywordSearch=log4j` 返回 34）、arXiv API `cat:cs.CR`。

## 4. Phase 1：联网搜索

### 4.1 Function 分层

当前 `functions/index.ts` 单文件 266 行，且 `dev/function-local.ts` 引用的 `functions/handler.ts` 不存在（`npm run dev:function` 实际是坏的）。按 Sites 官方推荐的 entry/handler 拆分，同时修复本地开发链路：

| 文件 | 单一职责 | 依赖 |
| --- | --- | --- |
| `functions/index.ts` | 仅 `Deno.serve(handler)` | handler |
| `functions/handler.ts` | 路由分发（action → 各 handler），统一 JSON 响应与错误包装 | routes/* |
| `functions/lib/dashscope.ts` | embedding、生成、联网搜索三种上游调用 | 无 |
| `functions/lib/kb.ts` | Supabase 检索：向量、编号精确匹配、战术提示、ILIKE 兜底、NVD 实时补查 | 无 |
| `functions/lib/chat.ts` | chat 编排：本地优先 → 决定是否联网 → 合并上下文 → 组织 sources/web_sources | dashscope, kb |
| `functions/lib/routes.ts` | stats / cve / attack 三个只读端点 | kb |

对外契约保持向后兼容：`{answer, sources}` 字段不变，新增 `web_sources`、`search_used`、`mode`。旧前端不会被新后端打断，可分步发布。

### 4.2 联网触发策略（mode 三态）

- `auto`（默认）：本地命中不足 **或** 问题带时效信号时联网。判定必须可复现：**本地命中不足 = 合并后的本地来源不足 3 条，或最高相似度 < 0.35**；时效信号 = 出现"最新/最近/今年/本周/目前/当前/刚披露/POC/在野"等词，或问题中出现 CVE 编号且其年份 ≥ 当前年份。
- `on`：强制联网（评测与演示用）。
- `off`：只用本地库，保证可复现与零额外费用。

本地命中良好时**不联网**，这样既省钱，也避免搜索结果污染已有权威引用；本地不足时联网并明确告知"本地知识库未覆盖，以下为网络检索结果"。

### 4.3 引用合成与域名权重

上下文按 `[1..n]` 统一编号，本地知识来源在前、网络来源在后（网络来源上限 5 条，按权重排序）：

- 高权重：`nvd.nist.gov`、`cisa.gov`、`cve.mitre.org`、`attack.mitre.org`、`arxiv.org`、厂商安全公告域（`*.oracle.com`、`msrc.microsoft.com`、`logging.apache.org`、`www.microsoft.com` 等）
- 中权重：主流媒体、官方文档站
- 降权并默认过滤：`csdn.net`、`jianshu.com`、`blog.*`、`zhihu.com`、`bilibili` 等 UGC（除非本地与高权重均无命中，此时保留并在 UI 标注"社区内容，需自行核验"）

### 4.4 错误处理

| 失败点 | 行为 |
| --- | --- |
| embedding 上游失败 | 503 + `向量服务暂不可用`（沿用现有），chat 降级为纯联网回答而非直接失败 |
| 向量检索空 | 走精确编号 → 战术提示 → ILIKE → NVD 实时 → 仍空则联网 |
| 联网搜索上游失败 | 静默回退到仅本地上下文，`search_used: false`，绝不让整条回答失败 |
| LLM 全链 429 | 保留现有 qwen-flash → qwen-plus 降级，再失败返回明确文案而非空串 |

### 4.5 无 Deno 的本地类型检查

本机没有 Deno（`npm run check:function` 报"不是内部或外部命令"）。新增 `tsconfig.functions.json` + `functions/deno.d.ts`（声明 `Deno.env` / `Deno.serve` 最小面），把 `check:function` 改为 `tsc -p tsconfig.functions.json --noEmit`，从而在不安装任何系统依赖的前提下获得 Function 的真实类型检查。行为正确性仍由回归套件（打线上）负责。

## 5. Phase 2：数据扩充

新增三类记录，与现有 `knowledge_base` 表结构（id/title/content/category/embedding/metadata/source_url）和既有 RPC 完全兼容，不改 schema、不需要用户执行 SQL：

| 类别 | 来源 | 规模 | 价值 |
| --- | --- | --- | --- |
| `cve`（扩充） | CISA KEV JSON | ~1,773（含 201 条 2026 年） | 全部为真实在野利用，带厂商/产品/修复期限，权威 URL |
| `cwe` | MITRE CWE 官方 XML | ~900 | 支撑"漏洞→弱点→攻击技术→缓解"链条 |
| `paper` | arXiv `cat:cs.CR` 近两年 | ~1,800 | 让"论文知识库"宣称成立 |

合计从 870 → 约 5,300 条，全部有权威出处。metadata 必须是**嵌套字典**（JSONB 字符串标量会让 `metadata->>'key'` 恒为 NULL，这个坑已经踩过两次，`data/reimport.py` 已焊死写法）；embedding 必须用 pgvector 文本形式 `"[...]"` 提交。

配套改动：统计页分类扩展 cwe/paper；CVE 面板加"在野利用"徽标与 KEV 修复期限；CWE 条目展示与 ATT&CK 的关联；README 技术栈与实际对齐（DashScope embedding + qwen 生成，删除 DeepSeek/OpenAI 表述）。

## 6. Phase 3：可验证评测

交付物不是"感觉变好了"，而是一张对比表。

- 评测集 18–20 题，三类：知识库内（应本地命中）、时效性（必须联网才可能对）、知识库外（应明确说明未覆盖，考幻觉）。
- 两套运行：`mode=off` 与 `mode=on`，脚本自动打分：引用命中率（来源 URL 是否含期望标识）、时效题正确率（回答是否含期望 CVE 编号/版本号）、拒答正确率。
- 输出 `docs/eval-report.md` 表格，直接进作品帖和 PPT。
- 回归套件扩展：断言 `web_sources` 结构、时效题在 `on` 下答对、`off` 下不产生搜索调用。

## 7. 发布与回滚

每阶段独立可发布、可回滚：Phase 1 契约向后兼容（前端未上线时旧 UI 仍工作）；Phase 2 只加数据行与前端展示，出问题可删新行回到 870；Phase 3 纯新增文件。发布走既有 prepare_site → publish_site → get_publish_status → show_publish_confirmation 链路，actionId 每次换新 UUID，POST 需带站点 Origin 头。

## 8. 范围外（明确不做）

NVD 42 万条全量入库；自建向量索引服务；前端组件库重写；登录与多用户；论文 PDF 全文解析（只做摘要）；把系统改造成通用聊天机器人（保持"安全研究"定位，这是赛道契合度的来源）。

## 9. 备注

本仓库不是 git 仓库（`git rev-parse` 报 not a git repository），因此本文档无法按惯例提交到版本库；若需要 Git 提交历史作为参赛材料，需单独授权初始化。
