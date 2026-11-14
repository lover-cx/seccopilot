# dev/（脚本入库，留档不入库）

本目录混着两类东西：**可复现脚本**（`*.mjs`、`*.ts`，已入库）和**本机实测留档**
（`*.json`、`*.txt`、`*.log`、`*.md`，不入库）。区分它们是因为 `package.json` 的
`npm run dev:function` / `dev:function:node` 直接指向这里的 `function-local.ts` /
`function-node.ts`——挡掉整个目录的话，公开仓库的 README 就是一堆跑不通的命令。
需要长期作为证据的留档请落 `docs/eval-archive/`（已入库）。

| 脚本 | 输入 | 作用 | 需要的外部条件 |
| --- | --- | --- | --- |
| function-node.ts / function-local.ts | 仓库当前源码 | 本地 harness 入口（Node 与 Deno 两种跑法），同一份 Function 跑在 :8000 | Node 24 / Deno；代理见 README 的 NO_PROXY 行 |
| probe-kev-on-batch.mjs | 本地 harness :8000 | 同一 KEV 问题连跑 N 次，统计"提到 CVE-2026-21509 且给出收录日期" | 代理（Supabase）+ DashScope 不走代理 |
| probe-kevgate.mjs / probe-kevgate2.mjs | 本地 harness :8000 | 复现"检索里有 21509 但正文不提"那道题；作品帖第六节用它推翻过一条已发布结论 | 同上 |
| probe-kev-annotation.mjs | Supabase（`data/.env`） | 一次性核查指定几条 CVE（21509/124194/83542）本地正文是否带 `在野利用（CISA KEV）` 前缀——`kevFacts` 只认这个前缀 | 代理 + Supabase key |
| check-kev-samples.mjs | kev-on-batch.json / kev-off-batch.json / kev-on-*.txt | 离线重算 KEV 遵守率，区分"检索到"与"照着说" | 无网络 |
| check-title-criterion.mjs | docs/eval-archive/*.json | 核对 title 判据的判定翻转数（当前 8 行 0 翻转） | 无网络 |
| probe-websearch-shape.mjs | DashScope 原生协议 | 看 plugins/search 执行位与 search_info 来源数是否一致 | DashScope key |
| probe-nvd-desc.mjs | NVD API 2.0 | 核对 CVE 描述与 published 日期（时效题 ground 的来源） | NVD 可达，不走代理 |
| probe-attack-metadata.mjs | ATT&CK STIX | 拉技术名/阶段对照，`scripts/verify-id-name-pairs.mjs` 的 `dev/attack-names.json` 由它生成 | ATT&CK 可达 |
| probe-embed.mjs / probe-match-documents.mjs / probe-local-chat.mjs / probe-node-proxy.mjs | 见各文件头注释 | 检索召回、RPC、响应契约、代理路径的单项探针 | 视脚本而定 |

关于 `dev/test-run5.log`（README.md 与 docs/competition-post.md 都引用过它，`*.log` 不入库）：
它是 2026-11-12 第五轮 `SITE=http://127.0.0.1:8000 npm test` 的完整输出，**27/29**——
红的是两条：`stats 返回完整计数`（分类求和 956 ≠ total 5397，即作品帖第六节
"其一是真缺陷"那段说的 `catch { return 0 }` 静默归零）与 `chat：响应含联网搜索契约字段`
（上游网络来源变空后 `search_results` 为 `[]`，即第 8 条缺陷）。文档引用的是"这一轮红在哪两条、数字是多少"，
不是通过率承诺；要复核就照 `README.md` 的"30 秒复现"重跑同一命令，结果会随上游波动，
这正是那两篇文档刻意只写逐轮红项、不写单点分数的原因。
