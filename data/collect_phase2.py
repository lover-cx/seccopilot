#!/usr/bin/env python3
"""Phase2 采集：CISA KEV / MITRE CWE / arXiv cs.CR → data/phase2_raw.json

只采集、不联网入库、不算向量，因此可以反复低成本重跑。
记录形状与现有 knowledge_base 表完全一致：title/content/category/metadata/source_url。
metadata 必须是嵌套 dict（PostgREST 对 JSONB 字符串标量会让 metadata->>'key' 恒为 NULL）。

用法：python data/collect_phase2.py [kev|cwe|arxiv|all]
"""
import json, os, re, sys, time, io, zipfile, urllib.request, urllib.parse
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.join(HERE, "phase2_raw.json")
LOG = open(os.path.join(HERE, "collect_phase2.log"), "w", encoding="utf-8")


def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, file=LOG, flush=True)
    try:
        print(s.encode("gbk", "replace").decode("gbk"), flush=True)
    except Exception:
        print(s.encode("ascii", "replace").decode("ascii"), flush=True)


def fetch(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": "SecCopilot-KB/1.0 (research use)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def strip_html(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#xA;", " ")
    return re.sub(r"\s+", " ", s).strip()


def first_url(text):
    m = re.search(r"https?://[^\s,\"']+", text or "")
    return m.group(0).rstrip(".,;)") if m else ""


# ── 1. CISA KEV：真实在野利用漏洞 ────────────────────────────────────────────
def collect_kev():
    raw = json.loads(fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    catalog = raw.get("catalogVersion", "unknown")
    out = []
    for v in raw.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip()
        if not cve.startswith("CVE-"):
            continue
        notes = v.get("notes") or ""
        url = first_url(notes)
        if url.startswith("http://"):
            url = "https://" + url[len("http://"):]  # KEV 里少量厂商公告仍写 http，统一升级
        if not url.startswith("https://"):
            url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        cwes = v.get("cwes") or []
        content = "\n".join([
            f"在野利用（CISA KEV）｜厂商：{v.get('vendorProject', '')}｜产品：{v.get('product', '')}"
            f"｜KEV 收录：{v.get('dateAdded', '')}｜修复期限：{v.get('dueDate', '')}"
            f"｜勒索软件利用：{v.get('knownRansomwareCampaignUse', 'Unknown')}",
            strip_html(v.get("shortDescription", "")),
            f"要求措施：{strip_html(v.get('requiredAction', ''))}",
            (f"关联弱点：{', '.join(cwes)}" if cwes else ""),
            f"官方目录：https://www.cisa.gov/known-exploited-vulnerabilities-catalog（版本 {catalog}）",
        ])
        out.append({
            "title": f"{cve}: {strip_html(v.get('vulnerabilityName', ''))[:140]}",
            "content": re.sub(r"\n+", "\n", content).strip(),
            "category": "cve",
            "source_url": url,
            "metadata": {
                "cve_id": cve, "kev": True, "kev_catalog": catalog,
                "vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
                "kev_date_added": v.get("dateAdded", ""), "kev_due_date": v.get("dueDate", ""),
                "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                "required_action": strip_html(v.get("requiredAction", ""))[:200],
                "cwes": cwes,
            },
        })
    log(f"[KEV] 采集 {len(out)} 条（目录版本 {catalog}）")
    return out


# ── 2. MITRE CWE：弱点目录 ───────────────────────────────────────────────────
def collect_cwe():
    zf = zipfile.ZipFile(io.BytesIO(fetch("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip")))
    xml_name = [n for n in zf.namelist() if n.lower().endswith(".xml")][0]
    root = ET.fromstring(zf.read(xml_name))
    ns = root.tag.split("}")[0].strip("{")
    q = lambda tag: f"{{{ns}}}{tag}"
    version = root.get("Version", "")
    date = root.get("Date", "")

    out, skipped = [], 0
    for w in root.findall(f"{q('Weaknesses')}/{q('Weakness')}"):
        wid, name, status = w.get("ID"), w.get("Name"), w.get("Status", "")
        abstraction = w.get("Abstraction", "")
        if status == "Deprecated":
            skipped += 1
            continue
        desc = strip_html(w.findtext(q("Description"), ""))
        if len(desc) < 30:
            skipped += 1
            continue
        ext = strip_html(w.findtext(q("Extended_Description"), ""))[:1200]
        cons = []
        for c in w.findall(f"{q('Common_Consequences')}/{q('Consequence')}"):
            for t in c.findall(q("Consequence_Type")):
                if t.text and t.text.strip() not in cons:
                    cons.append(t.text.strip())
        mits = [strip_html(m.findtext(q("Description"), "")) for m in w.findall(f"{q('Potential_Mitigations')}/{q('Mitigation')}")]
        mits = [m for m in mits if len(m) > 15][:3]

        parts = [f"弱点抽象层级：{abstraction or '未标注'}｜目录状态：{status or 'Active'}｜CWE 目录版本 {version}（{date}）", desc]
        if ext:
            parts.append(ext)
        if cons:
            parts.append("常见后果：" + "、".join(cons[:6]))
        if mits:
            parts.append("缓解措施：\n" + "\n".join(f"- {m[:220]}" for m in mits))
        out.append({
            "title": f"CWE-{wid}: {name}",
            "content": "\n".join(parts).strip(),
            "category": "cwe",
            "source_url": f"https://cwe.mitre.org/data/definitions/{wid}.html",
            "metadata": {"cwe_id": f"CWE-{wid}", "name": name, "abstraction": abstraction,
                         "status": status or "Active", "cwe_version": version},
        })
    log(f"[CWE] 采集 {len(out)} 条，跳过（已废弃/描述过短）{skipped} 条，目录版本 {version}")
    return out


# ── 3. arXiv cs.CR：安全论文摘要 ─────────────────────────────────────────────
ARXIV_TARGET = int(os.environ.get("ARXIV_TARGET", "1800"))
ARXIV_PAGE = 200


def collect_arxiv():
    ns = {"a": "http://www.w3.org/2005/Atom", "os": "http://a9.com/-/spec/opensearch/1.1/"}
    out, seen = [], set()
    start = 0
    while len(out) < ARXIV_TARGET:
        params = urllib.parse.urlencode({
            "search_query": "cat:cs.CR", "start": start,
            "max_results": min(ARXIV_PAGE, ARXIV_TARGET - len(out)),
            "sortBy": "submittedDate", "sortOrder": "descending",
        })
        try:
            root = ET.fromstring(fetch(f"https://export.arxiv.org/api/query?{params}", timeout=120))
        except Exception as e:
            log(f"[arXiv] 第 {start} 条起请求失败：{e!r}，重试一次")
            time.sleep(10)
            try:
                root = ET.fromstring(fetch(f"https://export.arxiv.org/api/query?{params}", timeout=120))
            except Exception as e2:
                log(f"[arXiv] 仍失败，停止翻页：{e2!r}")
                break
        entries = root.findall("a:entry", ns)
        if not entries:
            log(f"[arXiv] start={start} 无更多结果，停止")
            break
        for e in entries:
            abs_url = (e.findtext("a:id", "", ns) or "").strip()
            aid = re.sub(r"v\d+$", "", abs_url.rsplit("/", 1)[-1])
            if not aid or aid in seen:
                continue
            seen.add(aid)
            title = " ".join((e.findtext("a:title", "", ns) or "").split())
            abstract = " ".join((e.findtext("a:summary", "", ns) or "").split())
            if len(abstract) < 80:
                continue
            authors = [x.findtext("a:name", "", ns).strip() for x in e.findall("a:author", ns)]
            cats = [x.get("term") for x in e.findall("a:category", ns)]
            primary = e.find("a:primary_category", ns)
            pub = (e.findtext("a:published", "", ns) or "")[:10]
            who = "、".join(authors[:3]) + (" 等" if len(authors) > 3 else "")
            out.append({
                "title": title[:200],
                "content": f"{pub} 提交｜arXiv:{aid}｜分类：{'、'.join(cats[:5])}｜作者：{who}\n{abstract}",
                "category": "paper",
                "source_url": abs_url.replace("http://", "https://"),
                "metadata": {"arxiv_id": aid, "published": pub, "authors": authors[:8],
                             "primary_category": primary.get("term") if primary is not None else "cs.CR",
                             "categories": cats},
            })
        log(f"[arXiv] 已取 {len(out)}/{ARXIV_TARGET}（start={start}，本页 {len(entries)} 条）")
        start += ARXIV_PAGE
        time.sleep(3.5)  # arXiv API 要求请求间隔
    log(f"[arXiv] 采集 {len(out)} 条")
    return out


def identity(r):
    """语义主键：同一漏洞/弱点/论文只应有一条记录。
    用 source_url 做键会因 URL 规范化（http→https、notes 顺序变化）产生重复行，实测踩过。"""
    m = r.get("metadata", {})
    for k in ("cve_id", "cwe_id", "arxiv_id"):
        if m.get(k):
            return f"{r['category']}|{m[k]}"
    return f"{r['category']}|{r['source_url']}"


def main():
    which = (sys.argv[1] if len(sys.argv) > 1 else "all").lower()
    records = []
    for key, fn in (("kev", collect_kev), ("cwe", collect_cwe), ("arxiv", collect_arxiv)):
        if which not in ("all", key):
            continue
        try:
            records.extend(fn())
        except Exception as e:
            log(f"[{key}] 整体失败：{e!r}")
    if os.path.exists(OUT_PATH):
        with open(OUT_PATH, encoding="utf-8") as f:
            old = json.load(f)
        new_keys = {identity(r) for r in records}
        keep = [r for r in old if identity(r) not in new_keys]
        records = keep + records
        log(f"[merge] 旧 {len(old)} + 新 → 合并后 {len(records)}")
    seen, deduped = set(), []
    for r in records:
        k = identity(r)
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)
    if len(deduped) != len(records):
        log(f"[dedupe] 去除 {len(records) - len(deduped)} 条同主键重复")
    records = deduped
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=1)
    by = {}
    for r in records:
        by[r["category"]] = by.get(r["category"], 0) + 1
    log(f"[done] 写入 {OUT_PATH} :: {by}")
    LOG.close()


if __name__ == "__main__":
    main()
