-- SecCopilot 知识库数据库架构
-- 在 Supabase SQL Editor 中执行此脚本

-- 启用 pgvector 扩展
CREATE EXTENSION IF NOT EXISTS vector;

-- 创建知识库表
CREATE TABLE IF NOT EXISTS knowledge_base (
  id BIGSERIAL PRIMARY KEY,
  content TEXT NOT NULL,
  title TEXT,
  source_url TEXT,
  category TEXT NOT NULL DEFAULT 'general', -- 'cve', 'attack', 'paper', 'general'
  metadata JSONB DEFAULT '{}',
  embedding VECTOR(1024),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 创建向量索引 (IVFFlat)
CREATE INDEX IF NOT EXISTS knowledge_base_embedding_idx 
  ON knowledge_base 
  USING ivfflat (embedding vector_cosine_ops)
  WITH (lists = 100);

-- 创建分类索引
CREATE INDEX IF NOT EXISTS knowledge_base_category_idx 
  ON knowledge_base (category);

-- 创建全文搜索索引
CREATE INDEX IF NOT EXISTS knowledge_base_content_idx 
  ON knowledge_base 
  USING GIN (to_tsvector('english', content));

-- 创建匹配函数 (用于向量相似度搜索)
-- 注意 SET ivfflat.probes = 100：IVFFlat 默认只探 1 个 list（本表 100 个 list，
-- 约 54 行），会让"不限定分类"的语义检索大面积漏召回（实测 "T1059" 返回 0 行，
-- 而限定 category='attack' 时能返回 200 行）。阈值写成显式参数，便于按评测结果调整。
-- 已建库的旧版函数用 supabase-retrieval-fix.sql 升级（含 DROP 旧签名，避免重载歧义）。
CREATE OR REPLACE FUNCTION match_documents(
  query_embedding VECTOR(1024),
  match_count INT DEFAULT 5,
  category_filter TEXT DEFAULT NULL,
  match_threshold FLOAT DEFAULT 0.30
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
STABLE
SET ivfflat.probes = 100
AS $$
BEGIN
  RETURN QUERY
  SELECT
    kb.id,
    kb.content,
    kb.title,
    kb.source_url,
    kb.category,
    kb.metadata,
    (1 - (kb.embedding <=> query_embedding))::FLOAT AS similarity
  FROM knowledge_base kb
  WHERE
    kb.embedding IS NOT NULL
    AND (category_filter IS NULL OR kb.category = category_filter)
    AND 1 - (kb.embedding <=> query_embedding) >= match_threshold
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
  WHERE 
    kb.category = 'cve' AND
    (
      to_tsvector('english', kb.content) @@ plainto_tsquery('english', query_text) OR
      kb.title ILIKE '%' || query_text || '%' OR
      kb.metadata->>'cve_id' ILIKE '%' || query_text || '%'
    )
  ORDER BY 
    COALESCE((NULLIF(kb.metadata->>'cvss_score', ''))::FLOAT, 0) DESC
  LIMIT limit_count;
END;
$$;

-- 创建 ATT&CK 查询函数
CREATE OR REPLACE FUNCTION search_attacks(
  p_tactic TEXT DEFAULT NULL,
  p_technique_id TEXT DEFAULT NULL,
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
DECLARE
  -- Normalize tactic: lowercase, replace spaces with hyphens
  normalized_tactic TEXT;
BEGIN
  IF p_tactic IS NOT NULL THEN
    normalized_tactic := LOWER(REPLACE(TRIM(p_tactic), ' ', '-'));
  ELSE
    normalized_tactic := NULL;
  END IF;

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
  WHERE
    kb.category = 'attack' AND
    (normalized_tactic IS NULL OR LOWER(kb.metadata->>'tactic') = normalized_tactic) AND
    (p_technique_id IS NULL OR kb.metadata->>'technique_id' ILIKE '%' || p_technique_id || '%')
  ORDER BY kb.title
  LIMIT limit_count;
END;
$$;

-- 插入示例数据 (可选，用于测试)
-- 注意：实际数据需要通过 Python 脚本批量导入
