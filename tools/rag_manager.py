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

            # --- 元数据处理 (Metadata) [核心修复点] ---
            
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

        # 3. 批量写入 ChromaDB
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

    def search_similar_cases(self, query_context, k=2):
        """
        RAG 检索接口
        """
        # 将结构化的 Context 转换为自然语言查询
        if isinstance(query_context, dict):
            query_text = f"BGP anomaly prefix {query_context.get('prefix', '')} path {query_context.get('as_path', '')} origin {query_context.get('detected_origin', '')}"
        else:
            query_text = str(query_context)

        results = self.collection.query(
            query_texts=[query_text],
            n_results=k
        )

        knowledge_snippets = []
        if not results['documents'][0]:
            return "（未找到相似历史案例）"

        for i, doc in enumerate(results['documents'][0]):
            meta = results['metadatas'][0][i]
            dist = results['distances'][0][i]
            
            # 解析 Conclusion (如果是 JSON 串则还原)
            conclusion_display = meta['conclusion']
            try:
                # 尝试解析回来只是为了排版，如果不需要可以直接用字符串
                conc_obj = json.loads(conclusion_display)
                conclusion_display = json.dumps(conc_obj, ensure_ascii=False, indent=2)
            except:
                pass

            snippet = f"""
--- [参考案例 #{i+1} | 相关性: {1-dist:.2f}] ---
【类型】: {meta['type']}
【场景】: {doc}
【分析逻辑】: {meta['analysis']}
【结论】: {conclusion_display}
"""
            knowledge_snippets.append(snippet)
        
        return "\n".join(knowledge_snippets)

if __name__ == "__main__":
    # 简单自测
    rag = RAGManager()
    # 这里的路径改成你实际的文件路径，用于自测
    # rag.load_knowledge_base("data/forensics_cases.jsonl")