# test_all_tools.py
import sys
import os

# 确保当前目录在 Python 路径中 (解决 Import 问题)
sys.path.append(os.getcwd())

from tools.bgp_toolkit import BGPToolKit

def run_comprehensive_test():
    print("🚀 启动 BGP 工具箱全量测试...")
    toolkit = BGPToolKit()
    
    # 定义测试场景：Twitter 被劫持
    # Prefix: 104.244.42.0/24 (Twitter)
    # Origin: 12389 (Rostelecom) - 劫持者
    context = {
        "prefix": "104.244.42.0/24",
        "as_path": "174 12389",
        "timestamp": 1648474800
    }

    tools = [
        "authority_check",
        "geo_check",
        "neighbor_check",
        "topology_check",
        "stability_analysis",
        "graph_analysis" # <--- 测试新工具
    ]

    for tool_name in tools:
        print(f"\n🛠️  正在测试: [{tool_name}]")
        print("-" * 40)
        
        try:
            result = toolkit.call_tool(tool_name, context)
            print(f"📄 输出: {result}")

            if "SYSTEM_ERROR" in result:
                print("❌ 失败: 工具注册失败")
            elif "TOOL_ERROR" in result:
                print("❌ 失败: 工具内部崩溃")
            else:
                print("✅ 成功")

        except Exception as e:
            print(f"❌ 严重错误: {e}")

if __name__ == "__main__":
    run_comprehensive_test()