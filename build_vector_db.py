import json
import os
import sys
import shutil

# 1. 确保能导入 tools 包 (解决路径问题)
sys.path.append(os.getcwd())

from tools.rag_manager import RAGManager

def build_db():
    # --- 配置区域 ---
    # 输入文件: 你刚才生成的 500 条大 JSON 文件
    # (如果你生成的文件名不同，请修改这里)
    json_path = "data/synthetic_cases_hijack.json" 
    
    # 输出数据库: Agent 读取的目录 

    db_path = "./rag_db" 

    # ----------------

    # 1. 检查数据源是否存在
    if not os.path.exists(json_path):
        print(f"❌ 错误: 找不到数据文件 {json_path}")
        print("   -> 请检查文件路径是否正确，或是否已运行生成脚本。")
        return

    # 2. 清理旧数据库 
    # (为了保证数据库里只有最新的 500 条数据，建议先删掉旧的)
    if os.path.exists(db_path):
        print(f"🧹 发现旧数据库，正在清理: {db_path}")
        try:
            shutil.rmtree(db_path)
        except Exception as e:
            print(f"⚠️ 清理失败 (可能是文件被占用): {e}")

    # 3. 初始化 RAG 引擎
    print(f"🔄 正在初始化 RAG 引擎，目标路径: {db_path}")
    # RAGManager 会自动创建新的数据库目录
    rag = RAGManager(db_path=db_path)
    
    # 4. 加载数据 (核心步骤)
    print(f"📖 开始读取并向量化: {json_path} ...")
    try:
        # 调用 rag_manager.py 里的加载逻辑
        # 它内部使用的是 json.load()，完美兼容你的缓存方案
        rag.load_knowledge_base(json_path)
        print("✅ Vector RAG 数据库构建成功！所有案例已存入 ChromaDB。")
    except Exception as e:
        print(f"❌ 构建过程中发生错误: {e}")
        return

    # 5. 简单验证 (确保能查出来)
    print("\n🔎 [自检] 尝试检索一条 Twitter 劫持相关的案例...")
    test_query = {
        "prefix": "104.244.42.0/24", 
        "as_path": "174 12389", 
        "detected_origin": "12389"
    }
    # 搜索最相似的 1 条
    res = rag.search_similar_cases(test_query, k=1)
    print(f"检索结果预览:\n{'-'*40}\n{res}\n{'-'*40}")

if __name__ == "__main__":
    build_db()