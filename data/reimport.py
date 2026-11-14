#!/usr/bin/env python3
"""快速重新导入：从 knowledge_base.json 读取数据，生成 embedding，导入 Supabase"""
import json, os, time, requests


def _load_env(path):
    """密钥只从 data/.env 读取，不写进源码（此前这里硬编码过真实 key，已移除）"""
    env = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


_ENV = _load_env(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
DASHSCOPE_KEY = _ENV["DASHSCOPE_API_KEY"]
SB_URL = _ENV["SUPABASE_URL"]
SB_KEY = _ENV["SUPABASE_KEY"]
SB_HEADERS = {
    "apikey": SB_KEY,
    "Authorization": f"Bearer {SB_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}
PROXY = {"http": "http://127.0.0.1:7897", "https": "http://127.0.0.1:7897"}

# 1. 读取已有数据
print("读取 knowledge_base.json...")
with open("knowledge_base.json", "r", encoding="utf-8") as f:
    records = json.load(f)
print(f"共 {len(records)} 条记录")

# 2. 生成 embeddings
print("\n生成 embeddings...")
embeddings = []
batch_size = 10
texts = [r["content"] for r in records]

for i in range(0, len(texts), batch_size):
    batch = texts[i:i + batch_size]
    try:
        resp = requests.post(
            "https://dashscope.aliyuncs.com/api/v1/services/embeddings/text-embedding/text-embedding",
            headers={"Authorization": f"Bearer {DASHSCOPE_KEY}", "Content-Type": "application/json"},
            json={"model": "text-embedding-v3", "input": {"texts": batch}, "parameters": {"dimension": 1024}},
            timeout=60,
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("output", {}).get("embeddings", []):
                embeddings.append(item["embedding"])
            print(f"  {min(i + batch_size, len(texts))}/{len(texts)} OK")
        else:
            print(f"  错误 {resp.status_code}: {resp.text[:100]}")
            embeddings.extend([[0.0] * 1024 for _ in batch])
        time.sleep(0.5)
    except Exception as e:
        print(f"  异常: {e}")
        embeddings.extend([[0.0] * 1024 for _ in batch])

print(f"生成了 {len(embeddings)} 个向量")

# 3. 导入 Supabase
print("\n导入 Supabase...")
success = 0
errors = 0
for i, (record, embedding) in enumerate(zip(records, embeddings)):
    try:
        data = {
            "content": record["content"],
            "title": record["title"],
            "source_url": record["source_url"],
            "category": record["category"],
            "metadata": json.loads(record["metadata"]) if isinstance(record["metadata"], str) else record["metadata"],
            "embedding": "[" + ",".join(str(x) for x in embedding) + "]",  # pgvector 字符串格式
        }
        resp = requests.post(f"{SB_URL}/rest/v1/knowledge_base", headers=SB_HEADERS, json=data, timeout=30, proxies=PROXY)
        if resp.status_code in (200, 201):
            success += 1
        else:
            errors += 1
            if errors <= 3:
                print(f"  [{i}] 错误 {resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        errors += 1
        if errors <= 3:
            print(f"  [{i}] 异常: {e}")
    if (i + 1) % 50 == 0:
        print(f"  进度: {i + 1}/{len(records)}")

print(f"\n完成！成功 {success} 条，失败 {errors} 条")
