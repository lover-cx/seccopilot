-- SecCopilot 检索召回修复（在 Supabase SQL Editor 执行，可重复执行）
--
-- 问题（2026-11-10 用脚本 ivf_probe3 实测，数据量 5,397 行）：
--   同一个向量，加不加分类过滤走的是不同执行计划，召回差别极大——
--     query="T1059"        category_filter=NULL    -> 0 行
--     query="T1059"        category_filter='attack'-> 200 行（最高相似度 0.4724）
--     query="量子纠缠 …"    category_filter=NULL    -> 8 行
--     query="量子纠缠 …"    category_filter='attack'-> 200 行
--   原因：向量索引是 IVFFlat WITH (lists = 100)，而 pgvector 默认 ivfflat.probes = 1，
--   即一次只扫 1 个 list（约 54 行）。带 category 等条件时优化器改用别的计划，
--   反而是全表精确扫描，所以出现"限定分类才搜得到"的反常现象。
--   线上 Function 靠"精确编号补齐 + ILIKE 兜底"掩盖了这一点，但纯语义检索一直在漏。
--
-- 修复：把 probes 提到与 lists 相同（等于全表精确检索），并把相似度门槛写成显式参数。
--   本表只有 5 千行、1024 维，精确检索在毫秒级；换成几十万行时再考虑 HNSW。

-- CREATE OR REPLACE 遇到参数列表不同时会新增一个重载而不是替换，
-- PostgREST 调用重载函数可能报 "ambiguous function"，因此先显式删掉旧签名。
DROP FUNCTION IF EXISTS match_documents(VECTOR(1024), INT, TEXT);
DROP FUNCTION IF EXISTS match_documents(VECTOR(1024), INT, TEXT, FLOAT);

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
-- 函数级 SET 只影响本次调用，不改全局配置
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
  WHERE kb.embedding IS NOT NULL
    AND (category_filter IS NULL OR kb.category = category_filter)
    AND 1 - (kb.embedding <=> query_embedding) >= match_threshold
  ORDER BY kb.embedding <=> query_embedding
  LIMIT match_count;
END;
$$;

-- 执行后自检：这两条都应有返回行（第二条以前在不限定分类时是 0 行）
-- SELECT count(*) FROM match_documents(
--   (SELECT embedding FROM knowledge_base WHERE metadata->>'technique_id' = 'T1059' LIMIT 1), 5, NULL);
-- SELECT title, similarity FROM match_documents(
--   (SELECT embedding FROM knowledge_base WHERE metadata->>'technique_id' = 'T1059' LIMIT 1), 5, 'attack');

-- 可选（数据再涨十倍时再做）：按 pgvector 建议 lists ≈ 行数/1000，重新建索引后把上面的
-- probes 调成同样的值即可保持精确召回：
--   DROP INDEX knowledge_base_embedding_idx;
--   CREATE INDEX knowledge_base_embedding_idx ON knowledge_base
--     USING ivfflat (embedding vector_cosine_ops) WITH (lists = 8);
