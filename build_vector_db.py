import os
import sys
import shutil

# 确保能导入 tools 包
sys.path.append(os.getcwd())
from tools.rag_manager import RAGManager

def build_db():
    # ================= 配置区域 =================
    # 1. 输入数据: 必须是你刚才生成的溯源数据 (.jsonl)
    json_path = "data/forensics_cases.jsonl"
    
    # 2. 输出路径: 必须与 bgp_agent.py 里的设置一致
    db_path = "./rag_db"
    # ===========================================

    # 检查输入文件
    if not os.path.exists(json_path):
        print(f"❌ 错误: 找不到数据文件 {json_path}")
        print("   -> 请先运行: python tools/gen_forensics_data.py")
        return

    # 清理旧数据库 (强制删除旧文件夹，防止脏数据干扰)
    if os.path.exists(db_path):
        print(f"🧹 清理旧数据库: {db_path}")
        try:
            shutil.rmtree(db_path)
        except Exception as e:
            print(f"⚠️ 清理失败: {e}")

    # 初始化 RAG
    print(f"🔄 初始化数据库: {db_path}")
    rag = RAGManager(db_path=db_path)
    
    # 开始构建
    print(f"📖 读取并写入数据: {json_path} ...")
    try:
        rag.load_knowledge_base(json_path)
        
        # 验证一下数据量
        count = rag.collection.count()
        print(f"\n✅ 构建成功! 数据库现包含 {count} 条案例。")
        
        # 简单的检索测试
        print("🔎 自检测试 (Search Test):")
        test_res = rag.search_similar_cases({"prefix": "1.2.3.0/24", "as_path": "174 12389"}, k=1)
        print(test_res[:200] + "...") # 只打印前200字符

    except Exception as e:
        print(f"\n❌ 构建崩溃: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    build_db()