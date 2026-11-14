# SecCopilot Supabase 数据库设置指南

## 步骤 1：打开 Supabase SQL Editor

1. 访问 https://supabase.com/dashboard
2. 选择你的项目：`hmbcuccbudrazccqmmrp`
3. 点击左侧菜单的 **SQL Editor**
4. 点击 **New query**

## 步骤 2：执行以下 SQL

复制并执行以下完整 SQL 脚本：

```sql
-- 启用 pgvector 扩展
CREATE EXTENSION IF NOT EXISTS vector;

-- 删除旧表（如果存在）
DROP TABLE IF EXISTS knowledge_base CASCADE;

-- 创建知识库表
CREATE TABLE knowledge_base (
  id BIGSERIAL PRIMARY KEY,
  content TEXT NOT NULL,
  title TEXT,
  source_url TEXT,
  category TEXT NOT NULL DEFAULT 'general',
  metadata JSONB DEFAULT '{}',
  embedding VECTOR(1536),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 创建向量索引
CREATE INDEX knowledge_base_embedding_idx 
  ON knowledge_base 
  USING ivfflat (embedding vector_cosine_ops)
  WITH (lists = 100);

-- 创建分类索引
CREATE INDEX knowledge_base_category_idx ON knowledge_base (category);

-- 创建匹配函数
CREATE OR REPLACE FUNCTION match_documents(
  query_embedding VECTOR(1536),
  match_count INT DEFAULT 5,
  category_filter TEXT DEFAULT NULL
)
RETURNS TABLE (
  id BIGINT,
  content TEXT,
  title TEXT,
  source_url TEXT,
  category TEXT,
  metadata JSONB,
  similarity FLOAT
)
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT
    kb.id, kb.content, kb.title, kb.source_url, kb.category, kb.metadata,
    1 - (kb.embedding <=> query_embedding) AS similarity
  FROM knowledge_base kb
  WHERE (category_filter IS NULL OR kb.category = category_filter)
  ORDER BY kb.embedding <=> query_embedding
  LIMIT match_count;
END;
$$;

-- 创建 CVE 查询函数
CREATE OR REPLACE FUNCTION search_cves(
  query_text TEXT,
  limit_count INT DEFAULT 10
)
RETURNS TABLE (
  id BIGINT,
  cve_id TEXT,
  title TEXT,
  content TEXT,
  severity TEXT,
  cvss_score FLOAT,
  source_url TEXT,
  published_date TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT
    kb.id,
    kb.metadata->>'cve_id' AS cve_id,
    kb.title,
    kb.content,
    kb.metadata->>'severity' AS severity,
    (kb.metadata->>'cvss_score')::FLOAT AS cvss_score,
    kb.source_url,
    kb.metadata->>'published_date' AS published_date
  FROM knowledge_base kb
  WHERE kb.category = 'cve' AND
    (to_tsvector('english', kb.content) @@ plainto_tsquery('english', query_text) OR
     kb.title ILIKE '%' || query_text || '%' OR
     kb.metadata->>'cve_id' ILIKE '%' || query_text || '%')
  ORDER BY CASE WHEN kb.metadata->>'cvss_score' IS NOT NULL 
           THEN (kb.metadata->>'cvss_score')::FLOAT ELSE 0 END DESC
  LIMIT limit_count;
END;
$$;

-- 创建 ATT&CK 查询函数
CREATE OR REPLACE FUNCTION search_attacks(
  tactic TEXT DEFAULT NULL,
  technique_id TEXT DEFAULT NULL,
  limit_count INT DEFAULT 20
)
RETURNS TABLE (
  id BIGINT,
  technique_id TEXT,
  technique_name TEXT,
  tactic TEXT,
  description TEXT,
  detection TEXT,
  mitigation TEXT,
  source_url TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT
    kb.id,
    kb.metadata->>'technique_id' AS technique_id,
    kb.title AS technique_name,
    kb.metadata->>'tactic' AS tactic,
    kb.content AS description,
    kb.metadata->>'detection' AS detection,
    kb.metadata->>'mitigation' AS mitigation,
    kb.source_url
  FROM knowledge_base kb
  WHERE kb.category = 'attack' AND
    (tactic IS NULL OR kb.metadata->>'tactic' = tactic) AND
    (technique_id IS NULL OR kb.metadata->>'technique_id' ILIKE '%' || technique_id || '%')
  ORDER BY kb.title
  LIMIT limit_count;
END;
$$;
```

## 步骤 3：验证表创建成功

执行以下查询验证：

```sql
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'knowledge_base'
ORDER BY ordinal_position;
```

应该看到这些列：
- id (bigint)
- content (text)
- title (text)
- source_url (text)
- category (text)
- metadata (jsonb)
- embedding (USER-DEFINED)
- created_at (timestamp with time zone)

## 步骤 4：获取通义千问 API Key

1. 访问 https://bailian.console.aliyun.com/
2. 登录阿里云账号
3. 开通百炼服务（新用户有免费额度）
4. 在 API Key 管理页面创建密钥
5. 复制 Key 到 `.env` 文件的 `DASHSCOPE_API_KEY` 字段

## 步骤 5：运行数据导入

```bash
cd F:\Qoder\seccopilot\data
python build_kb.py
```
