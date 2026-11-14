#!/usr/bin/env python3
"""
SecCopilot 数据准备脚本 (简化版 - 使用 requests 直接调用 Supabase REST API)
下载 CVE 漏洞数据和 MITRE ATT&CK 数据，生成向量并导入 Supabase
"""

import os
import json
import time
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any
import openai

# 加载 .env 文件
env_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(env_path):
    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ.setdefault(key.strip(), value.strip())

# ============ 配置 ============
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
if not (SUPABASE_URL and SUPABASE_KEY):
    raise SystemExit("缺少 SUPABASE_URL / SUPABASE_KEY，请在 data/.env 中配置（参考 data/.env.example）")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api2.cxnnn.cn/v1")
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# 配置代理 (Clash)
PROXY = os.getenv("HTTP_PROXY", "http://127.0.0.1:7897")
proxies = {
    "http": PROXY,
    "https": PROXY,
}

# 初始化 OpenAI
if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY
    openai.base_url = OPENAI_BASE_URL

# Supabase REST API headers
SUPABASE_HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}

# ============ 数据下载 ============

def download_cves(days: int = 365) -> List[Dict[str, Any]]:
    """下载最近 N 天的 CVE 数据"""
    print(f"正在下载最近 {days} 天的 CVE 数据...")
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    all_cves = []
    page = 0
    page_size = 2000
    
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": page_size,
                "startIndex": page * page_size,
            }
            
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers=headers,
                timeout=60,
                proxies=proxies,
            )
            
            if response.status_code == 404:
                print("  NVD API 返回 404，尝试使用备用数据源...")
                return download_cves_sample()
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d["lang"] == "en"),
                    ""
                )
                
                # 获取 CVSS 评分
                metrics = cve.get("metrics", {})
                cvss_data = (
                    metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
                )
                cvss_score = cvss_data.get("baseScore", 0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                
                # 获取 CWE
                weaknesses = cve.get("weaknesses", [])
                cwe = ""
                if weaknesses:
                    descriptions = weaknesses[0].get("description", [])
                    cwe = next((d["value"] for d in descriptions), "")
                
                # 获取发布时间
                published = cve.get("published", "")
                
                all_cves.append({
                    "cve_id": cve_id,
                    "title": f"{cve_id}: {description[:100]}...",
                    "content": description,
                    "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "category": "cve",
                    "metadata": {
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "cwe": cwe,
                        "published_date": published,
                    },
                })
            
            total_results = data.get("totalResults", 0)
            print(f"  已获取 {len(all_cves)} / {total_results} 条 CVE")
            
            if len(all_cves) >= total_results:
                break
            
            page += 1
            time.sleep(6)  # NVD API 速率限制
            
        except Exception as e:
            print(f"  下载出错 (尝试 {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(5)
            else:
                print("  使用示例数据继续...")
                return download_cves_sample()
    
    return all_cves


def download_cves_sample() -> List[Dict[str, Any]]:
    """使用示例 CVE 数据（当 API 不可用时）"""
    print("  使用示例 CVE 数据...")
    sample_cves = [
        {
            "cve_id": "CVE-2021-44228",
            "title": "CVE-2021-44228: Apache Log4j2 远程代码执行漏洞",
            "content": "Apache Log4j2 2.0-beta9 到 2.15.0（除 2.12.2 外）存在 JNDI 注入漏洞，当配置使用日志消息时，攻击者可通过构造恶意请求执行任意代码。",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "category": "cve",
            "metadata": {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "severity": "CRITICAL", "cwe": "CWE-502", "published_date": "2021-12-10"},
        },
        {
            "cve_id": "CVE-2023-46604",
            "title": "CVE-2023-46604: Apache ActiveMQ 远程代码执行漏洞",
            "content": "Apache ActiveMQ 5.18.0 之前版本存在 XML 反序列化漏洞，攻击者可通过构造恶意 XML 消息执行任意代码。",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-46604",
            "category": "cve",
            "metadata": {"cve_id": "CVE-2023-46604", "cvss_score": 9.8, "severity": "CRITICAL", "cwe": "CWE-502", "published_date": "2023-10-25"},
        },
        {
            "cve_id": "CVE-2024-3094",
            "title": "CVE-2024-3094: XZ Utils 后门漏洞",
            "content": "XZ Utils 5.6.0 和 5.6.1 中被植入后门，影响 liblzma，可通过 SSH 服务实现远程代码执行。",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
            "category": "cve",
            "metadata": {"cve_id": "CVE-2024-3094", "cvss_score": 10.0, "severity": "CRITICAL", "cwe": "CWE-506", "published_date": "2024-03-29"},
        },
    ]
    return sample_cves


def download_attacks() -> List[Dict[str, Any]]:
    """下载 MITRE ATT&CK 数据"""
    print("正在下载 MITRE ATT&CK 数据...")
    
    attacks = []
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            # 下载 ATT&CK STIX 数据
            response = requests.get(
                "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
                timeout=60,
                proxies=proxies,
            )
            response.raise_for_status()
            data = response.json()
            
            for obj in data.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                
                technique_id = obj.get("external_references", [{}])[0].get("external_id", "")
                if not technique_id or not technique_id.startswith("T"):
                    continue
                
                name = obj.get("name", "")
                description = obj.get("description", "")
                
                # 获取战术
                kill_chain_phases = obj.get("kill_chain_phases", [])
                tactics = [phase.get("phase_name", "") for phase in kill_chain_phases]
                
                attacks.append({
                    "technique_id": technique_id,
                    "title": name,
                    "content": description,
                    "source_url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                    "category": "attack",
                    "metadata": {
                        "technique_id": technique_id,
                        "tactic": tactics[0] if tactics else "",
                        "tactics": tactics,
                        "detection": "",
                        "mitigation": "",
                    },
                })
            
            print(f"  已获取 {len(attacks)} 条 ATT&CK 技术")
            return attacks
            
        except Exception as e:
            print(f"  下载出错 (尝试 {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(5)
    
    print("  使用示例 ATT&CK 数据...")
    return download_attacks_sample()


def download_attacks_sample() -> List[Dict[str, Any]]:
    """使用示例 ATT&CK 数据"""
    sample_attacks = [
        {
            "technique_id": "T1059",
            "title": "Command and Scripting Interpreter",
            "content": "攻击者可通过命令和脚本解释器执行恶意命令，如 PowerShell、Bash、Python 等。",
            "source_url": "https://attack.mitre.org/techniques/T1059/",
            "category": "attack",
            "metadata": {"technique_id": "T1059", "tactic": "Execution", "tactics": ["Execution"], "detection": "", "mitigation": ""},
        },
        {
            "technique_id": "T1059.001",
            "title": "PowerShell",
            "content": "攻击者滥用 PowerShell 执行命令、脚本、加载恶意模块，是 Windows 环境中最常见的攻击技术之一。",
            "source_url": "https://attack.mitre.org/techniques/T1059/001/",
            "category": "attack",
            "metadata": {"technique_id": "T1059.001", "tactic": "Execution", "tactics": ["Execution"], "detection": "", "mitigation": ""},
        },
        {
            "technique_id": "T1190",
            "title": "Exploit Public-Facing Application",
            "content": "攻击者利用面向互联网的应用程序漏洞获取初始访问权限，如 Web 应用、数据库服务等。",
            "source_url": "https://attack.mitre.org/techniques/T1190/",
            "category": "attack",
            "metadata": {"technique_id": "T1190", "tactic": "Initial Access", "tactics": ["Initial Access"], "detection": "", "mitigation": ""},
        },
        {
            "technique_id": "T1078",
            "title": "Valid Accounts",
            "content": "攻击者使用合法凭据访问系统，可能是窃取、购买或默认凭据。",
            "source_url": "https://attack.mitre.org/techniques/T1078/",
            "category": "attack",
            "metadata": {"technique_id": "T1078", "tactic": "Initial Access", "tactics": ["Initial Access", "Defense Evasion", "Persistence", "Privilege Escalation"], "detection": "", "mitigation": ""},
        },
    ]
    return sample_attacks


# ============ 向量生成与导入 ============

def generate_embeddings(texts: List[str]) -> List[List[float]]:
    """使用通义千问生成文本向量 (1024 维)"""
    print(f"正在生成 {len(texts)} 个向量...")
    
    if not DASHSCOPE_API_KEY:
        print("  警告：DASHSCOPE_API_KEY 未设置，使用零向量占位")
        return [[0.0] * 1024 for _ in texts]
    
    embeddings = []
    batch_size = 10  # 通义千问批量限制 (最大 10)
    
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        
        try:
            response = requests.post(
                "https://dashscope.aliyuncs.com/api/v1/services/embeddings/text-embedding/text-embedding",
                headers={
                    "Authorization": f"Bearer {DASHSCOPE_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "text-embedding-v3",
                    "input": {"texts": batch},
                    "parameters": {"dimension": 1024},
                },
                timeout=60,
            )
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get("output", {}).get("embeddings", []):
                    embeddings.append(item["embedding"])
            else:
                print(f"  向量生成出错 ({response.status_code}): {response.text[:200]}")
                # 添加零向量作为占位
                embeddings.extend([[0.0] * 1024 for _ in batch])
            
            print(f"  已生成 {min(i + batch_size, len(texts))} / {len(texts)} 个向量")
            time.sleep(1)
            
        except Exception as e:
            print(f"  向量生成出错：{e}")
            embeddings.extend([[0.0] * 1024 for _ in batch])
    
    return embeddings


def import_to_supabase(records: List[Dict[str, Any]], embeddings: List[List[float]]):
    """将数据导入 Supabase (使用 REST API)"""
    print(f"正在导入 {len(records)} 条记录到 Supabase...")
    
    success_count = 0
    error_count = 0
    
    for i, (record, embedding) in enumerate(zip(records, embeddings)):
        try:
            data = {
                "content": record["content"],
                "title": record["title"],
                "source_url": record["source_url"],
                "category": record["category"],
                "metadata": record["metadata"],  # 直接传 dict，让 requests 序列化为 JSON 对象
                "embedding": embedding,
            }
            
            response = requests.post(
                f"{SUPABASE_URL}/rest/v1/knowledge_base",
                headers=SUPABASE_HEADERS,
                json=data,
                timeout=30,
            )
            
            if response.status_code in (200, 201):
                success_count += 1
            else:
                error_count += 1
                if error_count <= 5:
                    print(f"  导入出错 ({response.status_code}): {response.text[:200]}")
            
            if (i + 1) % 100 == 0:
                print(f"  已导入 {i + 1} / {len(records)} 条记录")
                time.sleep(1)
            
        except Exception as e:
            error_count += 1
            if error_count <= 5:
                print(f"  导入出错：{e}")
    
    print(f"导入完成：成功 {success_count} 条，失败 {error_count} 条")


# ============ 主流程 ============

def main():
    print("=" * 60)
    print("SecCopilot 数据准备脚本")
    print("=" * 60)
    
    if not DASHSCOPE_API_KEY:
        print("警告：DASHSCOPE_API_KEY 未设置，将使用零向量（搜索功能不可用）")
        print("请访问 https://bailian.console.aliyun.com/ 开通并获取 API Key")
    
    # 1. 下载数据
    print("\n[1/3] 下载数据...")
    cves = download_cves(days=730)  # 最近 2 年
    attacks = download_attacks()
    
    all_records = cves + attacks
    print(f"\n共获取 {len(all_records)} 条记录 ({len(cves)} CVE + {len(attacks)} ATT&CK)")
    
    if not all_records:
        print("没有获取到数据，请检查网络连接")
        return
    
    # 2. 生成向量
    print("\n[2/3] 生成向量...")
    texts = [r["content"] for r in all_records]
    embeddings = generate_embeddings(texts)
    
    # 3. 导入 Supabase
    print("\n[3/3] 导入数据...")
    import_to_supabase(all_records, embeddings)
    
    print("\n" + "=" * 60)
    print("数据准备完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()
