// 可疑编号验真：把 docs/eval-report.json 里被判为"suspect"的安全编号逐条拿去权威源核对。
//
//   node scripts/verify-suspects.mjs            # 读当前报告
//   EVAL_JSON=dev/eval-report-local.json node scripts/verify-suspects.mjs   # 换一份留档来验
//   node scripts/verify-suspects.mjs --strict   # 有任何一条查不到就以非零码退出
//
// 为什么需要它：eval 的 suspect 只是保守告警——编号出现在模型回答里，却没出现在返回的
// 来源标题/URL 中。这可能是编造，也可能只是来源标题没带编号。不逐条验真，就不能把
// "本轮 42 次回答零编造"写进报告。判据必须落到**外部权威源**，不能落到本地库自己：
//   CVE-*  → NVD 官方 API（services.nvd.nist.gov）
//   CWE-*  → MITRE 官方 CWE 定义页（cwe.mitre.org/data/definitions/<n>.html）
//   T*     → MITRE ATT&CK 官方技术页（attack.mitre.org/techniques/<id>/）
// NVD 无 key 时限流 5 次/30 秒，所以 CVE 之间固定间隔，别并发打。
import { readFileSync } from "node:fs";

const STRICT = process.argv.includes("--strict");
const UA = { "User-Agent": "SecCopilot-eval/1.0 (verification script)" };

const rows = JSON.parse(readFileSync(process.env.EVAL_JSON ?? "docs/eval-report.json", "utf-8")).rows ?? [];
const ids = [...new Set(rows.flatMap((r) => r.suspect ?? []))].sort();
console.log(`可疑编号（去重）：${ids.length} 个\n`);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function checkNvd(id) {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, { headers: UA, signal: AbortSignal.timeout(30000) });
      if (res.status === 404) return { ok: false, why: "NVD 无此编号（404）" };
      if (res.status === 503) { await sleep(31000); continue; }
      if (res.status !== 200) return { ok: false, why: `HTTP ${res.status}` };
      const j = await res.json();
      const v = j.vulnerabilities?.[0]?.cve;
      if (!v) return { ok: false, why: "NVD 返回空 vulnerabilities" };
      const desc = (v.descriptions ?? []).find((d) => d.lang === "en")?.value ?? "";
      return { ok: true, name: (v.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? "") || "",
        vendor: v.vendorMetadata?.[0]?.name ?? "", title: desc.slice(0, 90), published: v.published?.slice(0, 10) };
    } catch (e) {
      if (attempt === 3) return { ok: false, why: String(e.message ?? e).slice(0, 60) };
      await sleep(6000);
    }
  }
  return { ok: false, why: "unreachable" };
}

async function checkMitrePage(url, id) {
  try {
    const res = await fetch(url, { headers: UA, signal: AbortSignal.timeout(30000), redirect: "follow" });
    if (res.status !== 200) return { ok: false, why: `HTTP ${res.status}` };
    const html = await res.text();
    // 页面里必须真的出现这个编号，避免被通用 404/跳转页蒙过去
    if (!html.toUpperCase().includes(id.toUpperCase())) return { ok: false, why: "页面 200 但正文不含该编号" };
    const t = (html.match(/<title>([^<]*)<\/title>/i)?.[1] ?? "").replace(/\s+/g, " ").trim();
    return { ok: true, title: t.slice(0, 90) };
  } catch (e) {
    return { ok: false, why: String(e.message ?? e).slice(0, 60) };
  }
}

const out = [];
let cveSeen = 0;
for (const id of ids) {
  if (/^CVE-\d{4}-\d{4,7}$/i.test(id)) {
    if (cveSeen++) await sleep(7000); // NVD 无 key：5 次/30 秒
    const r = await checkNvd(id);
    out.push({ id, src: "NVD", ...r });
  } else if (/^CWE-\d+$/i.test(id)) {
    const n = id.split("-")[1];
    const r = await checkMitrePage(`https://cwe.mitre.org/data/definitions/${n}.html`, id);
    out.push({ id, src: "MITRE CWE", ...r });
  } else if (/^T\d{4}(\.\d{3})?$/i.test(id)) {
    const r = await checkMitrePage(`https://attack.mitre.org/techniques/${id.replace(/\.\d+$/, "")}/`, id);
    out.push({ id, src: "MITRE ATT&CK", ...r });
  } else {
    out.push({ id, src: "?", ok: false, why: "编号形态无法识别" });
  }
  const last = out[out.length - 1];
  console.log(`${last.ok ? "真" : "查不到"} ${id.padEnd(16)} ${last.src.padEnd(14)} ${last.ok ? (last.title ?? last.published ?? "") : last.why}`);
}

const bad = out.filter((o) => !o.ok);
const bySrc = {};
for (const o of out) (bySrc[o.src] ??= []).push(o);
console.log("\n汇总：");
for (const [src, list] of Object.entries(bySrc)) {
  console.log(`  ${src}：${list.length} 个，${list.filter((o) => o.ok).length} 个在权威源命中`);
}
console.log(bad.length ? `\n未通过验真 ${bad.length} 个：${bad.map((b) => b.id).join(", ")}` : "\n全部编号在权威源命中，本轮回答零编造。");

if (STRICT && bad.length) process.exit(1);
