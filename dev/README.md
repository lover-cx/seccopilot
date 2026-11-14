# dev/（未入库）

本目录是本机一次性探针与实测留档，体积大且部分含真实站点响应，默认不提交。
仓库里文档引用过的可复现脚本，输入与判据如下；重新生成请按此顺序：

| 脚本 | 输入 | 作用 | 需要的外部条件 |
| --- | --- | --- | --- |
| probe-kev-on-batch.mjs | 本地 harness :8000 | 同一 KEV 问题连跑 N 次，统计"提到 CVE-2026-21509 且给出收录日期" | 代理（Supabase）+ DashScope 不走代理 |
| check-kev-samples.mjs | kev-on-batch.json / kev-off-batch.json / kev-on-*.txt | 离线重算 KEV 遵守率，区分"检索到"与"照着说" | 无网络 |
| check-title-criterion.mjs | docs/eval-archive/*.json | 核对 title 判据的判定翻转数（当前 8 行 0 翻转） | 无网络 |
| probe-websearch-shape.mjs | DashScope 原生协议 | 看 plugins/search 执行位与 search_info 来源数是否一致 | DashScope key |
