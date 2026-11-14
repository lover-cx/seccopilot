// 核验"编号 ↔ 名称"配对，而不是只核验编号是否真实。
//
// 背景：verify-suspects.mjs 已证明这一轮评测里出现的编号在权威源都能查到。但"编号真实"
// 不等于"配对正确"——上一轮线上回答把 credential-access 的 T1214 塞进初始访问并编了个中文名，
// 本轮本地实测又出现同一条回答里 T1566 既叫"供应链攻击"又叫"网络钓鱼"（供应链攻击实为 T1195）。
// 前者靠人工发现，后者本脚本能机械抓出来：同一条回答里同一编号对应多个名称，必然至少有一个是错的。
//
// 用法：
//   node scripts/verify-id-name-pairs.mjs                      # 读 docs/eval-report.json
//   EVAL_JSON=dev/eval-report-local.json node scripts/verify-id-name-pairs.mjs
//   ATTACK_JSON=dev/attack-names.json node scripts/verify-id-name-pairs.mjs   # 离线复用已拉取的对照表
//
// 对照表来自本地知识库（category=attack，标题形如 "T1189 Drive-by Compromise"）。
// 拉取需要 Supabase，本机要过代理：
//   NODE_USE_ENV_PROXY=1 HTTPS_PROXY=http://127.0.0.1:7897 node scripts/verify-id-name-pairs.mjs
import { readFileSync, writeFileSync, existsSync } from "node:fs";

const ARCHIVE = process.env.EVAL_JSON ?? "docs/eval-report.json";
const CACHE = process.env.ATTACK_JSON ?? "dev/attack-names.json";

// ── 编号 ↔ 名称配对：把 answer 里的 "名称（T1234）" 和 "T1234 名称" 都收下来 ──────────
const PAIR_BEFORE = /([\u4e00-\u9fa5A-Za-z][\u4e00-\u9fa5A-Za-z \/／、,，-]{1,30}?)\*{0,2}\s*[（(]\s*(T\d{4}(?:\.\d{2,3})?)\s*[)）]/g;
const PAIR_AFTER = /\b(T\d{4}(?:\.\d{2,3})?)\*{0,2}\s*[—:：\-–]\s*([\u4e00-\u9fa5A-Za-z][\u4e00-\u9fa5A-Za-z ]{1,40})/g;

const norm = (s) => String(s).replace(/[\s\*（）()、，,：:]+/g, "").toLowerCase();

function pairsOf(answer) {
  const out = [];
  for (const m of String(answer).matchAll(PAIR_BEFORE)) out.push({ id: m[2].toUpperCase(), name: m[1].trim() });
  for (const m of String(answer).matchAll(PAIR_AFTER)) out.push({ id: m[1].toUpperCase(), name: m[2].trim() });
  return out;
}

// ── 本地知识库的权威编号 → 英文官方名 ────────────────────────────────────────────
async function attackNames() {
  if (existsSync(CACHE)) return JSON.parse(readFileSync(CACHE, "utf-8"));
  const env = Object.fromEntries(
    readFileSync(new URL("../data/.env", import.meta.url), "utf-8")
      .split(/\r?\n/).filter((l) => /^[A-Z_]+=/.test(l))
      .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim()]),
  );
  if (!env.SUPABASE_URL) throw new Error("缺 SUPABASE_URL，且没有 ATTACK_JSON 缓存");
  const rows = [];
  for (let from = 0; ; from += 1000) {
    const r = await fetch(
      `${env.SUPABASE_URL}/rest/v1/knowledge_base?select=title,metadata&category=eq.attack&order=id.asc&limit=1000&offset=${from}`,
      { headers: { apikey: env.SUPABASE_KEY, Authorization: `Bearer ${env.SUPABASE_KEY}` } },
    );
    if (!r.ok) throw new Error(`Supabase ${r.status}: ${(await r.text()).slice(0, 160)}`);
    const page = await r.json();
    rows.push(...page);
    if (page.length < 1000) break;
  }
  // knowledge_base 里 attack 行的 title 只是英文技术名，编号在 metadata.technique_id
  const map = {};
  for (const row of rows) {
    const id = String(row.metadata?.technique_id ?? "").toUpperCase();
    if (/^T\d{4}(?:\.\d{2,3})?$/.test(id)) map[id] ??= String(row.title).trim();
  }
  writeFileSync(CACHE, JSON.stringify(map, null, 1), "utf-8");
  return map;
}

const names = await attackNames();
const rows = JSON.parse(readFileSync(ARCHIVE, "utf-8")).rows ?? [];

const conflicts = [];
const idByName = [];
const unknown = [];
const englishChecked = [];

for (const r of rows) {
  const answer = r.answer ?? "";
  const byId = new Map();
  const byName = new Map();
  for (const p of pairsOf(answer)) {
    if (!byId.has(p.id)) byId.set(p.id, new Set());
    byId.get(p.id).add(p.name);
    const key = norm(p.name);
    if (!byName.has(key)) byName.set(key, new Map());
    byName.get(key).set(p.id, p.name);
  }
  for (const [id, set] of byId) {
    const list = [...set];
    if (list.length > 1) conflicts.push({ q: r.q, mode: r.mode, id, names: list });
    if (!names[id]) unknown.push({ q: r.q, mode: r.mode, id, names: list });
    for (const nm of list) {
      const official = names[id] ?? "";
      const ascii = nm.match(/[A-Za-z][A-Za-z &/'-]{3,}/g) ?? [];
      for (const a of ascii) {
        if (official && norm(a) !== norm(official) && norm(a).length > 6) {
          englishChecked.push({ q: r.q, mode: r.mode, id, given: a.trim(), official });
        }
      }
    }
  }
  // 同一个中文名挂到两个编号上：至少一个是错的（"供应链攻击"同时写成 T1195 与 T1566 就是这样）
  for (const [key, ids] of byName) {
    if (ids.size > 1) idByName.push({ q: r.q, mode: r.mode, name: [...ids.values()][0], ids: [...ids.keys()] });
  }
}

console.log(`留档：${ARCHIVE}（${rows.length} 条回答）｜本地 attack 编号：${Object.keys(names).length} 个`);
console.log(`\n── 同一条回答里同一编号对应多个名称（必有一个错）：${conflicts.length} 处`);
for (const c of conflicts) console.log(`  [${c.mode}] ${c.id} ← ${c.names.join(" ｜ ")}\n        问：${c.q.slice(0, 60)}`);

console.log(`\n── 同一条回答里同一名称对应多个编号（必有一个错）：${idByName.length} 处`);
for (const c of idByName) console.log(`  [${c.mode}] "${c.name}" ← ${c.ids.join(" ｜ ")}\n        问：${c.q.slice(0, 60)}`);

console.log(`\n── 回答里出现了本地库没有的 ATT&CK 编号（需查官方页）：${unknown.length} 处`);
for (const u of unknown) console.log(`  [${u.mode}] ${u.id} 写作 ${u.names.join(" / ")} ← ${u.q.slice(0, 50)}`);

console.log(`\n── 回答写了英文名但与本地库官方名不一致：${englishChecked.length} 处`);
for (const e of englishChecked) console.log(`  [${e.mode}] ${e.id} 答 "${e.given}" ≠ 库 "${e.official}" ← ${e.q.slice(0, 50)}`);

if (!conflicts.length && !idByName.length && !unknown.length && !englishChecked.length) console.log("\n没有抓到编号↔名称配对问题。");
