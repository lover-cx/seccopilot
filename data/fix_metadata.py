#!/usr/bin/env python3
"""修复 knowledge_base.metadata：把 JSONB 字符串标量还原为 JSON 对象。
原因：knowledge_base.json 里 metadata 字段本身是字符串，直接 POST 会存成 JSONB string，
导致 metadata->>'technique_id' 为 NULL，ATT&CK 过滤全部失效。
"""
import json, os, requests


def _load_env(path):
    env = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


_ENV = _load_env(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
SB_URL = _ENV.get("SUPABASE_URL", "")
SB_KEY = _ENV.get("SUPABASE_KEY", "")
if not (SB_URL and SB_KEY):
    raise SystemExit("缺少 SUPABASE_URL / SUPABASE_KEY，请在 data/.env 中配置")
H = {
    "apikey": SB_KEY,
    "Authorization": f"Bearer {SB_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal",
}
PROXY = {"http": "http://127.0.0.1:7897", "https": "http://127.0.0.1:7897"}

fixed = skipped = failed = 0
offset = 0
while True:
    r = requests.get(
        f"{SB_URL}/rest/v1/knowledge_base?select=id,metadata&order=id.asc&limit=200&offset={offset}",
        headers=H, proxies=PROXY, timeout=30,
    )
    if not r.ok:
        print("读取失败", r.status_code, r.text[:200])
        break
    rows = r.json()
    if not rows:
        break
    for row in rows:
        meta = row["metadata"]
        if isinstance(meta, str):
            try:
                parsed = json.loads(meta)
            except Exception:
                failed += 1
                continue
            if not isinstance(parsed, dict):
                failed += 1
                continue
            pr = requests.patch(
                f"{SB_URL}/rest/v1/knowledge_base?id=eq.{row['id']}",
                headers=H, json={"metadata": parsed}, proxies=PROXY, timeout=30,
            )
            if pr.status_code in (200, 204):
                fixed += 1
            else:
                failed += 1
                if failed <= 3:
                    print("  patch 失败", row["id"], pr.status_code, pr.text[:150])
        else:
            skipped += 1
    print(f"offset={offset} 本页 {len(rows)} 行 | 已修复 {fixed} | 已是对象 {skipped} | 失败 {failed}")
    offset += 200

print(f"\n完成：修复 {fixed}，无需修复 {skipped}，失败 {failed}")
