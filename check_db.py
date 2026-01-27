
import sys
import os
sys.path.append(os.getcwd())
from tools.rag_manager import RAGManager

def check():
    db_path = "./rag_db" # 👈 必须检查这个路径
    
    print(f"🔍 正在检查数据库: {db_path}")
    if not os.path.exists(db_path):
        print("❌ 目录不存在！请检查 build_vector_db.py 生成到哪里了。")
        return

    rag = RAGManager(db_path=db_path)
    count = rag.collection.count()
    print(f"📊 数据库当前包含数据量: {count} 条")
    
    if count == 0:
        print("❌ 数据库是空的！请重新运行 build_vector_db.py")
        return

    print("\n🔍 尝试检索 Twitter 案例...")
    query = {
        "prefix": "104.244.42.0/24",
        "as_path": "174 12389",
        "detected_origin": "12389"
    }
    # 强制打印检索结果
    results = rag.search_similar_cases(query, k=1)
    print(f"检索结果:\n{results}")

if __name__ == "__main__":
    check()