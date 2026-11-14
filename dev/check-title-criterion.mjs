// 一次性核对：新增的 title 判据有没有改变任何一份留档里 KEV 那道题的判定。
// 为什么单独写这个脚本：作品帖里"重算三份留档、判定一个都没变"这句话必须能被别人重跑，
// 而不是停在终端输出里——这是我们今天要求每个结论都落文件的那条纪律本身。
// 判据只作用在带 title 期望的题目上（目前全套 21 题只有 KEV 那道有），所以核对范围就是那一道。
// 口径与 scripts/eval.mjs 的 timeAccuracy 一致：该题 expect 没有 failIf / admit，
// 于是"判定翻转"只可能出现在 hit=true 且 titleOk=false 这一种组合。
// 用法：node dev/check-title-criterion.mjs
import { readFile } from "node:fs/promises";

const FILES = [
  "docs/eval-archive/deployed-prompt-only-2026-11-12.json",
  "docs/eval-archive/local-guards-run1-2026-11-12.json",
  "docs/eval-archive/local-guards-run2-2026-11-12.json",
  "docs/eval-report.json",
];
const Q = "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";
const PAT = /CVE-2026-21509/i;
const TITLE = /Security Feature Bypass|安全功能绕过/i;

let rows = 0;
let flips = 0;
for (const f of FILES) {
  let data;
  try {
    data = JSON.parse(await readFile(f, "utf8"));
  } catch (e) {
    console.log(`跳过 ${f}（读不到：${e.message}）`);
    continue;
  }
  const list = data.results ?? data.rows ?? data;
  for (const r of list) {
    if (r.q !== Q && r.question !== Q) continue;
    const mode = r.mode ?? r.args?.mode ?? "?";
    const a = String(r.answer ?? "");
    const hit = PAT.test(a);
    const titleOk = TITLE.test(a);
    const passOld = hit; // 无 failIf / admit 时，旧口径 = hit
    const passNew = hit && titleOk;
    rows++;
    // 留档里的 accuracy 是当初那次运行写下的判定；新口径若与它不一致，才算真的改过分数。
    const stored = r.accuracy;
    if (passOld !== passNew) flips++;
    if (stored !== undefined && stored !== passNew) flips++;
    console.log(
      `${f}\n  mode=${mode} 提到21509=${hit} 类型对得上=${titleOk} 旧口径=${passOld} 新口径=${passNew} 留档accuracy=${stored}` +
        (passOld === passNew && (stored === undefined || stored === passNew) ? "" : "  ← 判定翻转"),
    );
  }
}
console.log(`\n共核对 ${rows} 行，判定翻转 ${flips} 行。`);
if (!rows) {
  console.log("一行都没核到——先确认留档字段名，别把空集当通过。");
  process.exit(1);
}
process.exit(flips ? 1 : 0);
