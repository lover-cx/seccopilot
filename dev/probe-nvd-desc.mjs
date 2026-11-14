// 临时：把可疑编号的 NVD 完整描述打出来，核对"编号真实"之外更要紧的一件事——
// 编号真实，但和回答里给它贴的产品/主题标签是否一致。
const ids = process.argv.slice(2);
const UA = { "User-Agent": "SecCopilot-eval/1.0" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
for (let i = 0; i < ids.length; i++) {
  if (i) await sleep(7000);
  const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${ids[i]}`, { headers: UA, signal: AbortSignal.timeout(30000) });
  const j = await r.json();
  const v = j.vulnerabilities?.[0]?.cve;
  if (!v) { console.log(ids[i], "NVD 无记录"); continue; }
  const d = (v.descriptions ?? []).find((x) => x.lang === "en")?.value ?? "";
  const cfg = (v.cveConfigurations?.nodes ?? []).flatMap((n) => n.cpeMatch ?? [])
    .slice(0, 3).map((m) => (m.criteria ?? "").split(":")[3] + "/" + (m.criteria ?? "").split(":")[4]).join(", ");
  console.log(`\n${ids[i]}  published=${v.published?.slice(0, 10)}  kev=${(v.cisaExploitAdd ?? "")}`);
  console.log("  desc:", d.slice(0, 260));
  console.log("  cpe :", cfg);
}
