// 第二道题：Apache 产品在野利用（83542 过称那道）——闸门给的证据清单是什么？
import fs from "node:fs";
const env=Object.fromEntries(fs.readFileSync(new URL("../data/.env",import.meta.url),"utf8").split(/\r?\n/).filter(l=>/^\s*[A-Z]/.test(l)).map(l=>[l.split("=")[0].trim(),l.split("=").slice(1).join("=").trim()]));
const {embed}=await import("../functions/lib/dashscope.ts");
const {vector}=await import("../functions/lib/kb.ts");
const {kevFacts}=await import("../functions/lib/chat.ts");
const b={url:env.SUPABASE_URL,h:{apikey:env.SUPABASE_KEY,Authorization:`Bearer ${env.SUPABASE_KEY}`,"Content-Type":"application/json"}};
for(const q of ["最近有哪些已被确认在野利用的 Apache 产品漏洞？","CVE-2026-83542 是否已被确认在野利用？"]){
  const docs=await vector(b,await embed(env.DASHSCOPE_API_KEY,q),null,5);
  console.log("Q:",q,"\n  本地文档:",docs.map(d=>String(d.title).slice(0,44)).join(" | "));
  console.log("  kevFacts:",(kevFacts(q,docs)||"(空)").slice(0,240),"\n");
}
