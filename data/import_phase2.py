#!/usr/bin/env python3
"""Phase2 入库：phase2_raw.json → DashScope embedding → Supabase knowledge_base

要点（每条都对应一个已经踩过的坑）：
- 密钥只从 data/.env 读取，绝不写进源码。
- Supabase 只走 Clash 代理；DashScope 不走代理（直连更快且代理会干扰）。
- embedding 以 pgvector 文本形式 "[...]" 提交；metadata 必须是嵌套 dict。
- 向量缓存 phase2_emb.jsonl 按语义主键存，中断后重跑不重复花钱。
- 入库前读取现有行的主键集合，跳过已存在的记录，因此可安全重跑。

用法：python data/import_phase2.py [--dry-run] [--limit N]
"""
import json, os, sys, time, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "phase2_raw.json")
CACHE = os.path.join(HERE, "phase2_emb.jsonl")
LOG = open(os.path.join(HERE, "import_phase2.log"), "w", encoding="utf-8")
PROXY = {"http": "http://127.0.0.1:7897", "https": "http://127.0.0.1:7897"}
DRY = "--dry-run" in sys.argv
LIMIT = next((int(sys.argv[i + 1]) for i, a in enumerate(sys.argv) if a == "--limit"), 0)


def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, file=LOG, flush=True)
    try:
        print(s.encode("gbk", "replace").decode("gbk"), flush=True)
    except Exception:
        print(s.encode("ascii", "replace").decode("ascii"), flush=True)


def load_env(path):
    env = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


ENV = load_env(os.path.join(HERE, ".env"))
DS_KEY = ENV.get("DASHSCOPE_API_KEY", "")
SB_URL = ENV.get("SUPABASE_URL", "")
SB_KEY = ENV.get("SUPABASE_KEY", "")
log(f"[env] DASHSCOPE={bool(DS_KEY)} SUPABASE={bool(SB_URL)} key={bool(SB_KEY)}")
if not (DS_KEY and SB_URL and SB_KEY):
    log("[env] 缺少必要密钥，退出")
    sys.exit(1)

SB_H = {"apikey": SB_KEY, "Authorization": f"Bearer {SB_KEY}", "Content-Type": "application/json"}

# urllib 的 urlopen 没有 proxies 参数（那是 requests 的写法），必须用 ProxyHandler 构造 opener
SB_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": PROXY["http"], "https": PROXY["https"]}))
DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def identity(r):
    m = r.get("metadata", {})
    for k in ("cve_id", "cwe_id", "arxiv_id"):
        if m.get(k):
            return f"{r['category']}|{m[k]}"
    return f"{r['category']}|{r['source_url']}"


def sb_request(path, method="GET", body=None, headers=None, rng=None, tries=4):
    url = f"{SB_URL}/rest/v1/{path}"
    h = dict(SB_H)
    if headers:
        h.update(headers)
    if rng:
        h["Range"] = rng
        h["Range-Unit"] = "items"
    data = json.dumps(body).encode() if body is not None else None
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, data=data, headers=h, method=method)
            with SB_OPENER.open(req, timeout=120) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else None), dict(resp.headers)
        except urllib.error.HTTPError as e:
            last = (e.code, e.read()[:300].decode("utf-8", "replace"))
            if e.code in (400, 401, 404, 409):
                break
        except Exception as e:
            last = repr(e)
        time.sleep(2 + attempt * 3)
    log(f"[sb] {method} {path} 失败 :: {last}")
    return 0, None, {}


# ── 1. 读取待导入数据 ────────────────────────────────────────────────────────
records = json.load(open(RAW, encoding="utf-8"))
log(f"[raw] 本地待导入 {len(records)} 条")

# ── 2. 现有库中的主键集合（跳过已存在，保证可重跑）─────────────────────────
existing = set()
start = 0
while True:
    st, rows, hdrs = sb_request(
        "knowledge_base?select=category,source_url,metadata&order=id.asc",
        rng=f"{start}-{start + 999}")
    if st != 200 or not rows:
        break
    for r in rows:
        m = r.get("metadata") or {}
        key = None
        for k, cat in (("cve_id", "cve"), ("cwe_id", "cwe"), ("arxiv_id", "paper")):
            if isinstance(m, dict) and m.get(k):
                key = f"{cat}|{m[k]}"
        existing.add(key or f"{r.get('category')}|{r.get('source_url')}")
    total = hdrs.get("content-range", "").split("/")[-1]
    start += len(rows)
    if len(rows) < 1000 or str(start) >= str(total):
        break
log(f"[db] 现有记录主键 {len(existing)} 个")

todo = [r for r in records if identity(r) not in existing]
skipped = len(records) - len(todo)
if LIMIT:
    todo = todo[:LIMIT]
log(f"[plan] 需新增 {len(todo)} 条，跳过已存在 {skipped} 条" + ("（dry-run，不写入）" if DRY else ""))
if DRY or not todo:
    LOG.close()
    sys.exit(0)

# ── 3. 向量缓存 ──────────────────────────────────────────────────────────────
emb = {}
if os.path.exists(CACHE):
    with open(CACHE, encoding="utf-8") as f:
        for line in f:
            try:
                o = json.loads(line)
                emb[o["k"]] = o["v"]
            except Exception:
                pass
log(f"[cache] 已缓存向量 {len(emb)} 个")


def embed_batch(texts):
    body = {"model": "text-embedding-v3", "input": {"texts": texts}, "parameters": {"dimension": 1024}}
    for attempt in range(4):
        try:
            req = urllib.request.Request(
                "https://dashscope.aliyuncs.com/api/v1/services/embeddings/text-embedding/text-embedding",
                data=json.dumps(body).encode(), method="POST",
                headers={"Authorization": f"Bearer {DS_KEY}", "Content-Type": "application/json"})
            with DIRECT_OPENER.open(req, timeout=90) as resp:  # 不经代理
                d = json.loads(resp.read())
            vecs = sorted(d["output"]["embeddings"], key=lambda x: x["text_index"])
            out = [v["embedding"] for v in vecs]
            if len(out) == len(texts) and all(len(v) == 1024 for v in out):
                return out
            log(f"[embed] 返回数量/维度异常 len={len(out)}")
        except Exception as e:
            log(f"[embed] 异常 {e!r}，等待重试")
        time.sleep(3 + attempt * 4)
    return None


need = [r for r in todo if identity(r) not in emb]
log(f"[embed] 需计算 {len(need)} 条（复用缓存 {len(todo) - len(need)} 条）")
with open(CACHE, "a", encoding="utf-8") as cf:
    for i in range(0, len(need), 10):
        chunk = need[i:i + 10]
        texts = [(r["title"] + "\n" + r["content"])[:1600] for r in chunk]
        vecs = embed_batch(texts)
        if not vecs:
            log(f"[embed] 批次 {i} 失败，跳过（后续重跑会补）")
            continue
        for r, v in zip(chunk, vecs):
            emb[identity(r)] = v
            cf.write(json.dumps({"k": identity(r), "v": v}) + "\n")
        if (i // 10) % 20 == 0:
            log(f"[embed] 进度 {min(i + 10, len(need))}/{len(need)}")
        cf.flush()
        time.sleep(0.35)
log(f"[embed] 完成，缓存共 {len(emb)} 条")

# ── 4. 批量写入 Supabase ────────────────────────────────────────────────────
ok, failed = 0, 0
BATCH = 25
ready = [r for r in todo if identity(r) in emb]
log(f"[insert] 准备写入 {len(ready)} 条，每批 {BATCH}")
for i in range(0, len(ready), BATCH):
    chunk = ready[i:i + BATCH]
    payload = [{
        "title": r["title"], "content": r["content"], "category": r["category"],
        "source_url": r["source_url"], "metadata": r["metadata"],
        "embedding": "[" + ",".join(f"{x:.6f}" for x in emb[identity(r)]) + "]",
    } for r in chunk]
    st, _, _ = sb_request("knowledge_base", method="POST", body=payload,
                          headers={"Prefer": "return=minimal"})
    if st in (200, 201):
        ok += len(chunk)
    else:
        failed += len(chunk)
        # 整批失败时退化为逐条，定位并保住可写入的部分
        for r in chunk:
            one = [{
                "title": r["title"], "content": r["content"], "category": r["category"],
                "source_url": r["source_url"], "metadata": r["metadata"],
                "embedding": "[" + ",".join(f"{x:.6f}" for x in emb[identity(r)]) + "]",
            }]
            st1, _, _ = sb_request("knowledge_base", method="POST", body=one, headers={"Prefer": "return=minimal"})
            if st1 in (200, 201):
                ok += 1
                failed -= 1
            else:
                log(f"[insert] 单条失败 {identity(r)}")
    if (i // BATCH) % 20 == 0:
        log(f"[insert] 进度 {min(i + BATCH, len(ready))}/{len(ready)} ok={ok} fail={failed}")
    time.sleep(0.25)

log(f"[done] 写入成功 {ok} 条，失败 {failed} 条")
st, cnt, _ = sb_request("knowledge_base?select=id", rng="0-0", headers={"Prefer": "count=exact", "Range": "0-0"})
LOG.close()
