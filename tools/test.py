# test_toolkit.py
import json
from bgp_toolkit import BGPToolKit

def run_test():
    toolkit = BGPToolKit()
    
    # 定义一个标准测试用例 (Twitter 被劫持案例)
    context = {
        "prefix": "104.244.42.0/24",
        "as_path": "174 12389",
        "timestamp": 1648474800
    }

    print(">>> 开始 BGP 工具箱全面体检 <<<\n")

    # 1. 打印所有已注册的工具
    # 我们需要去 bgp_toolkit.py 里看 tool_map，这里直接测试调用
    tools_to_test = [
        "authority_check", 
        "geo_check", 
        "neighbor_check", 
        "topology_check",
        # "stability_analysis" # 如果你还没写这个，先注释掉
    ]

    for tool_name in tools_to_test:
        print(f"🛠️  正在测试工具: [{tool_name}] ... ", end="")
        
        try:
            result = toolkit.call_tool(tool_name, context)
            
            # 检查是否返回了 SYSTEM_ERROR (说明工具未注册)
            if "SYSTEM_ERROR" in result:
                print("❌ 失败! (未注册/名称错误)")
                print(f"    -> {result}")
            elif "TOOL_ERROR" in result:
                print("⚠️ 报错! (代码逻辑错误)")
                print(f"    -> {result}")
            else:
                print("✅ 成功!")
                # 只打印前100个字符避免刷屏
                print(f"    -> 返回预览: {result[:100]}...")
                
        except Exception as e:
            print(f"❌ 严重崩溃: {e}")
            
    print("\n>>> 体检结束 <<<")

if __name__ == "__main__":
    run_test()