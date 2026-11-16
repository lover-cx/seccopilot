#!/usr/bin/env node
/**
 * Task 4 判据的反证工具（mutation 反证）：把新写的三条判据逐个改坏，
 * 证明回归套件里对应的断言真的会判红——否则那条用例只是"跟着实现走"的假绿。
 *
 * 用法（同一条命令，cmd / PowerShell / Git Bash 都一样）：
 *   node dev/mutate-t4.mjs apply 1     # 打第 1 处改动（备份到 dev/chat.ts.t4bak）
 *   npm run test:offline -- --test-name-pattern kevAssertedIds   # 必须判红
 *   node dev/mutate-t4.mjs restore     # 还原，然后再跑一次确认判绿
 *
 * 备份/还原都放在 dev/ 下，且这个脚本只碰 functions/lib/chat.ts 里列出的三处锚点：
 * 锚点找不到就直接退出 9，绝不"顺手"改成别的写法——静默改错位置的反证比没做更糟。
 */
import fs from "node:fs";

const FILE = "functions/lib/chat.ts";
const BAK = "dev/chat.ts.t4bak";

// 每条 mutation = [说明, 原文锚点, 改坏后的文本, 对应会被打红的用例]
const MUTATIONS = [
  [
    "kevAssertedIds：去掉“同句已给 KEV 日期即合格”的豁免",
    "    if (/20\\d\\d-\\d\\d-\\d\\d/.test(s)) continue;            // 同句已给日期：合格",
    "    // MUTATION 1（反证用）：日期豁免被删掉",
    "kevAssertedIds + kevCorrection 用例的第①组 deepEqual",
  ],
  [
    "kevCorrection：触发条件从“看 question”改回“看正文”（计划里明令禁止的第一版写法）",
    "  if (!KEV_HINT.test(String(question ?? \"\")) && kevAssertedIds(text).length === 0) {",
    "  if (!KEV_HINT.test(text) && kevAssertedIds(text).length === 0) {   // MUTATION 2（反证用）",
    "kevCorrection 用例的第①组（退化回答没有 KEV 字样 → 会被判成 not_kev 放行）",
  ],
  [
    "kevUnderCount：去掉“scope 非 product（回落集合）不得断言全集”的闸门",
    "  if (scope?.scope !== \"product\") return null; // 回落集合不是产品全集，不能据此数条目",
    "  // MUTATION 3（反证用）：回落集合也照样输出“共 M 条”",
    "kevUnderCount 用例的第③组（scope:null 必须返回 null）",
  ],
  [
    "kevUnderCount：去掉“命中集被 slice(0,12) 截断时 M 不是全集”的闸门",
    "  if ((scope.totalMatched ?? 0) > inYear.length) return null;   // 命中集被截断，M 不是全集",
    "  // MUTATION 4（反证用）：截断时也照样输出“共 M 条”",
    "kevUnderCount 用例的第④组（totalMatched 41 > entries 5 必须返回 null）",
  ],
];

const cmd = process.argv[2];
const id = Number(process.argv[3]);

if (cmd === "restore") {
  if (!fs.existsSync(BAK)) { console.log(`没有备份文件 ${BAK}，未做任何还原`); process.exit(0); }
  fs.copyFileSync(BAK, FILE);
  console.log(`已还原 ${FILE}（来自 ${BAK}）`);
  process.exit(0);
}

if (cmd !== "apply") { console.log("用法：node dev/mutate-t4.mjs apply <1-N> | restore"); process.exit(2); }
const mut = MUTATIONS[id - 1];
if (!mut) { console.log(`未知的 mutation 编号 ${id}，可用 1-${MUTATIONS.length}`); process.exit(2); }
if (!fs.existsSync(BAK)) { fs.copyFileSync(FILE, BAK); console.log(`备份 → ${BAK}`); }
const src = fs.readFileSync(BAK, "utf8");            // 总是从备份出发，避免叠加多处改动
if (!src.includes(mut[1])) { console.log(`锚点未找到：\n${mut[1]}`); process.exit(9); }
fs.writeFileSync(FILE, src.replace(mut[1], mut[2]));
console.log(`MUTATION ${id} 已应用：${mut[0]}`);
console.log(`预期判红的用例：${mut[3]}`);
