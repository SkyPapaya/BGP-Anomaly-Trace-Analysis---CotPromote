import os
# --- 强制使用 HF 镜像站 ---
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

import chromadb
from chromadb.utils import embedding_functions
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RAGManager")

class RAGManager:
    def __init__(self, db_path="./rag_db", collection_name="bgp_cases"):
        self.db_path = db_path
        self.collection_name = collection_name
        
        # 初始化持久化客户端
        self.client = chromadb.PersistentClient(path=db_path)
        
        # 初始化模型 (使用 all-MiniLM-L6-v2)
        self.ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            embedding_function=self.ef
        )
        logger.info(f"RAG 引擎就绪 | 数据库路径: {db_path}")

    # tools/rag_manager.py 中替换该函数

    def load_knowledge_base(self, json_path):
        if not os.path.exists(json_path):
            logger.error(f"文件未找到: {json_path}")
            return

        # 兼容 JSON 和 JSONL
        cases = []
        if json_path.endswith('.jsonl'):
            with open(json_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        cases.append(json.loads(line))
        else:
            with open(json_path, 'r', encoding='utf-8') as f:
                cases = json.load(f)

        logger.info(f"正在导入 {len(cases)} 条数据...")
        
        ids = []
        documents = []
        metadatas = []
        
        # --- 新增：ID 去重集合 ---
        seen_ids = set()

        for case in cases:
            # 获取原始 ID
            curr_id = case.get('id', f"auto_{len(ids)}")
            
            # --- 核心修复：如果 ID 已存在，自动添加随机后缀 ---
            original_id = curr_id
            retry_count = 0
            while curr_id in seen_ids:
                retry_count += 1
                curr_id = f"{original_id}_{retry_count}"
            
            seen_ids.add(curr_id)
            # -----------------------------------------------

            doc_text = f"{case['scenario_desc']}"
            
            meta = {
                "type": case['type'],
                "analysis": case['analysis'],
                "conclusion": case['conclusion'],
                "full_json": json.dumps(case, ensure_ascii=False) 
            }

            ids.append(curr_id)
            documents.append(doc_text)
            metadatas.append(meta)

        if ids:
            # 这里的 upsert 如果遇到数据库里已有的 ID 会覆盖，但在 ids 列表内部必须唯一
            self.collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
            logger.info(f"✅ 知识库导入完成！(共处理 {len(ids)} 条，已自动修复重复ID)")

    def search_similar_cases(self, alert_context, k=2):
        # 构建查询语句
        query_text = (
            f"Prefix: {alert_context.get('prefix')}, "
            f"Path: {alert_context.get('as_path')}, "
            f"Origin: AS{alert_context.get('detected_origin')}."
        )
        
        # 搜索
        results = self.collection.query(query_texts=[query_text], n_results=k)
        
        retrieved_texts = []
        if results['ids'] and len(results['ids'][0]) > 0:
            count = len(results['ids'][0])
            for i in range(count):
                meta = results['metadatas'][0][i]
                dist = results['distances'][0][i]
                
                # 只有距离小于 0.6 的才算相关，太远的不要瞎参考
                relevance = "高" if dist < 0.4 else "中"
                
                case_str = (
                    f"--- [参考案例 #{i+1} | 相关性: {relevance} (Dist: {dist:.4f})] ---\n"
                    f"【类型】: {meta['type']}\n"
                    f"【场景】: {results['documents'][0][i]}\n" # 显示原始场景描述
                    f"【分析】: {meta['analysis']}\n"
                    f"【结论】: {meta['conclusion']}\n"
                )
                retrieved_texts.append(case_str)
        
        if not retrieved_texts:
            return "（未找到相似历史案例）"
            
        return "\n".join(retrieved_texts)

if __name__ == "__main__":
    # 简单的自测
    rag = RAGManager()
    # 模拟查询
    test_q = {"prefix": "104.244.42.0/24", "as_path": "174 12389", "detected_origin": "12389"}
    print(rag.search_similar_cases(test_q))