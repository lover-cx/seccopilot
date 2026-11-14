// 核对作品帖里关于 KEV 那道题的三句话：
//   ① "mode=on 采 10 次，10 次全都列出 CVE-2026-21509 并给出它的 KEV 收录日期"
//   ② "web_sources 10 次全是 0 条"
//   ③ "off 采 4 次也全部正确"（+ 两份闸门版留档里那 2 次不照闸门说 → 12 次采样 2 次不合规）
// 为什么单独写：这三句原来只在我终端里数过一遍。留档里的 `hasKevDate` 字段当时正则太窄
// （只认 ISO 写法，没认"2026年1月26日"），照字段数是 2/6，照回答正文数是 6/6——
// 字段错了但正文没错，所以必须写明"以回答正文为准"，并且让别人也能重算。
// 用法：node dev/check-kev-samples.mjs
import { readFileSync, existsSync } from "node:fs";

const ID = /CVE-2026-21509/i;
const DATE = /2026-01-26|2026年1月26日|2026\/01\/26/;

const samples = [];

// ① 批量探针留档
for (const f of ["dev/kev-on-batch.json", "dev/kev-off-batch.json"]) {
  if (!existsSync(f)) { console.log(`跳过缺失文件 ${f}`); continue; }
  const d = JSON.parse(readFileSync(f, "utf-8"));
  for (const r of d.rows ?? []) {
    samples.push({ src: `${f}#${r.i}`, mode: d.mode, answer: r.answer ?? "", nWeb: r.nWeb, srcHas: r.srcHas21509 });
  }
}

// ② 早前的单条 txt 留档：`--- web sources ---` 段落为空即 nWeb=0，可以一起计入"来源全 0"
for (const f of ["dev/kev-on-1.txt", "dev/kev-on-2.txt", "dev/kev-on-3.txt"]) {
  if (!existsSync(f)) { console.log(`跳过缺失文件 ${f}`); continue; }
  const t = readFileSync(f, "utf-8");
  const webBlock = (t.split("--- web sources ---")[1] ?? "").trim();
  const nWeb = webBlock ? webBlock.split(/\r?\n/).filter((l) => l.trim().startsWith("·")).length : 0;
  samples.push({ src: f, mode: "on", answer: t, nWeb, srcHas: null });
}

// ③ --grep 单题留档
if (existsSync("dev/eval-grep-check.json")) {
  for (const r of JSON.parse(readFileSync("dev/eval-grep-check.json", "utf-8")).rows ?? []) {
    samples.push({ src: "dev/eval-grep-check.json", mode: r.mode, answer: r.answer ?? "", nWeb: r.nWeb, srcHas: null });
  }
}

const tally = (mode) => {
  const rs = samples.filter((s) => s.mode === mode);
  const withId = rs.filter((s) => ID.test(s.answer));
  const withDate = withId.filter((s) => DATE.test(s.answer));
  const web = rs.filter((s) => typeof s.nWeb === "number");
  console.log(`mode=${mode}：样本 ${rs.length} 次，提到 21509 的 ${withId.length} 次，其中给出 KEV 收录日期的 ${withDate.length} 次`);
  if (web.length) {
    const nz = web.filter((s) => s.nWeb > 0);
    console.log(`  其中带 nWeb 字段的 ${web.length} 次，nWeb>0 的 ${nz.length} 次${nz.length === 0 ? "（→ 全 0）" : ""}`);
  }
  for (const s of rs) if (!ID.test(s.answer)) console.log(`  未提到 21509：${s.src}`);
  return rs.length;
};

console.log(`共读到 ${samples.length} 个样本\n`);
tally("on");
tally("off");

// 两份闸门版留档里那道题的判定（对应"12 次采样 2 次不照闸门说"）
// accuracy 只说明判分器怎么记的，不足以证明"不照闸门说"——所以这里同时看正文：
// run1 提了 21509 但把它降级成"资料未说明其在野利用"（判分器按包含关系放行），run2 干脆没提。
const Q = "2026 年被 CISA 确认在野利用的微软 Office 漏洞有哪些？";
const DOWNGRADE = /资料未说明|未说明其在野利用|未在野利用|不属于?在野利用|未明确标注/;
for (const f of ["docs/eval-archive/local-guards-run1-2026-11-12.json", "docs/eval-archive/local-guards-run2-2026-11-12.json"]) {
  const row = (JSON.parse(readFileSync(f, "utf-8")).rows ?? []).find((r) => r.q === Q && r.mode === "on");
  if (!row) { console.log(`${f}：没找到这道题的 on 记录——先确认留档字段，别当成"没有违规"`); continue; }
  const a = row.answer ?? "";
  const mentions = ID.test(a);
  const hedge = DOWNGRADE.test(a);
  const verdict = !mentions ? "整条未提及 21509" : hedge ? "提及但降级（判分器按包含关系放行）" : "按 KEV 证据列出";
  console.log(`${f.split("/").pop()} mode=on accuracy=${row.accuracy} nWeb=${row.nWeb} 正文=${verdict}`);
}
