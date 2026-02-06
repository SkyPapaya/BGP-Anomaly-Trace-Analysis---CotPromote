import chromadb
import os
import json
import logging
from sentence_transformers import SentenceTransformer

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RAGManager")

class RAGManager:
    def __init__(self, db_path="./rag_db", collection_name="bgp_cases"):
        """
        初始化 Vector RAG 引擎
        :param db_path: 向量数据库持久化路径
        """
        self.client = chromadb.PersistentClient(path=db_path)
        self.collection = self.client.get_or_create_collection(name=collection_name)
        # 使用轻量级嵌入模型 (本地运行)
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        print(f"INFO:RAGManager:RAG 引擎就绪 | 数据库路径: {db_path}")

    def load_knowledge_base(self, json_path):
        """
        从 JSON/JSONL 文件加载知识库 (自动去重 + 兼容性修复)
        """
        if not os.path.exists(json_path):
            logger.error(f"文件未找到: {json_path}")
            return

        cases = []
        # 1. 读取数据 (兼容 JSON 和 JSONL)
        try:
            if json_path.endswith('.jsonl'):
                with open(json_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            cases.append(json.loads(line))
            else:
                with open(json_path, 'r', encoding='utf-8') as f:
                    cases = json.load(f)
        except Exception as e:
            logger.error(f"读取文件失败: {e}")
            return

        logger.info(f"正在导入 {len(cases)} 条数据...")
        
        ids = []
        documents = []
        metadatas = []
        seen_ids = set()

        for case in cases:
            # --- ID 处理 (防止重复) ---
            curr_id = case.get('id', f"auto_{len(ids)}")
            original_id = curr_id
            retry_count = 0
            while curr_id in seen_ids:
                retry_count += 1
                curr_id = f"{original_id}_{retry_count}"
            seen_ids.add(curr_id)

            # --- 文本内容 (Document) ---
            # 优先使用场景描述作为向量化的主体
            doc_text = case.get('scenario_desc', str(case))

            
            # 1. 兼容 analysis 字段名 (旧数据用 analysis, 新数据用 analysis_logic)
            analysis_text = case.get('analysis') or case.get('analysis_logic') or "N/A"
            
            # 2. 处理 conclusion (可能是字符串，也可能是字典)
            conclusion_val = case.get('conclusion', "N/A")
            if isinstance(conclusion_val, dict):
                # 如果是字典，转成 JSON 字符串存入 metadata (ChromaDB 不支持嵌套字典)
                conclusion_str = json.dumps(conclusion_val, ensure_ascii=False)
            else:
                conclusion_str = str(conclusion_val)

            meta = {
                "type": case.get('type', 'Unknown'),
                "analysis": str(analysis_text), # 确保是字符串
                "conclusion": conclusion_str,   # 确保是字符串
                "full_json": json.dumps(case, ensure_ascii=False) # 存完整副本
            }

            ids.append(curr_id)
            documents.append(doc_text)
            metadatas.append(meta)

        # 3. 批量写入 ChromaDB//生成向量
        if ids:
            try:
                embeddings = self.model.encode(documents).tolist()
                self.collection.upsert(
                    ids=ids,
                    documents=documents,
                    embeddings=embeddings,
                    metadatas=metadatas
                )
                logger.info(f"✅ 知识库导入完成！(共 {len(ids)} 条)")
            except Exception as e:
                logger.error(f"写入数据库失败: {e}")

    def _context_to_query(self, ctx):
        """将单条 context 转为查询文本"""
        if isinstance(ctx, dict):
            return f"BGP anomaly prefix {ctx.get('prefix', '')} path {ctx.get('as_path', '')} origin {ctx.get('detected_origin', '')}"
        return str(ctx)

    def _format_results(self, items):
        """将 (doc, meta, dist) 列表格式化为输出字符串"""
        snippets = []
        for i, (doc, meta, dist) in enumerate(items, 1):
            conclusion_display = meta.get('conclusion', 'N/A')
            try:
                conc_obj = json.loads(conclusion_display)
                conclusion_display = json.dumps(conc_obj, ensure_ascii=False, indent=2)
            except Exception:
                pass
            snippet = f"""
--- [参考案例 #{i} | 相关性: {1-dist:.2f}] ---
【类型】: {meta.get('type', 'Unknown')}
【场景】: {doc}
【分析逻辑】: {meta.get('analysis', 'N/A')}
【结论】: {conclusion_display}
"""
            snippets.append(snippet)
        return "\n".join(snippets)

    def search_similar_cases(self, query_context, k=2):
        """
        RAG 检索接口（单条）
        """
        query_text = self._context_to_query(query_context)
        results = self.collection.query(query_texts=[query_text], n_results=k)
        if not results['documents'][0]:
            return "（未找到相似历史案例）"
        items = list(zip(
            results['documents'][0],
            results['metadatas'][0],
            results['distances'][0],
        ))
        return self._format_results(items)

    def search_similar_cases_batch(self, updates_list, k=2):
        """
        批量 RAG 检索：汇总所有 updates 的信息分别查询，合并去重后取 top-k。
        多条 updates 可能含噪声，汇总检索可提升召回相关案例的覆盖面，降低单条噪声影响。
        """
        if not updates_list:
            return "（未找到相似历史案例）"
        if len(updates_list) == 1:
            return self.search_similar_cases(updates_list[0], k=k)

        # 对每条 update 分别查询，每条约取 2k 以增加候选
        seen = {}
        per_k = min(3, max(1, (k * 2 + len(updates_list) - 1) // len(updates_list)))
        for u in updates_list:
            query_text = self._context_to_query(u)
            try:
                res = self.collection.query(query_texts=[query_text], n_results=per_k)
                if not res['documents'][0]:
                    continue
                for j, doc_id in enumerate(res['ids'][0]):
                    dist = res['distances'][0][j]
                    if doc_id not in seen or seen[doc_id][2] > dist:
                        seen[doc_id] = (res['documents'][0][j], res['metadatas'][0][j], dist)
            except Exception as e:
                logger.debug(f"RAG batch query 单条失败: {e}")
                continue

        if not seen:
            return "（未找到相似历史案例）"
        items = sorted(seen.values(), key=lambda x: x[2])[:k]
        return self._format_results(items)

if __name__ == "__main__":
    # 简单自测
    rag = RAGManager()
    # 这里的路径改成你实际的文件路径，用于自测
    # rag.load_knowledge_base("data/forensics_cases.jsonl")