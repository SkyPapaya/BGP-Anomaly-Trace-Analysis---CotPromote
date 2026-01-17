#统一调用接口
# bgp_toolkit.py
from authority import AuthorityValidator
from geo import GeoConflictChecker
from topology import TopologyInspector
from neighbor import NeighborPropagator
from stability import StabilityAnalyzer

class BGPToolKit:
    def __init__(self):
        # 初始化所有工具实例
        self.authority = AuthorityValidator()
        self.geo = GeoConflictChecker()
        self.topology = TopologyInspector()
        self.neighbor = NeighborPropagator()
        self.stability = StabilityAnalyzer()

    def update_state(self, prefix):
        """仅稳定性分析工具需要持续更新状态"""
        self.stability.update_state(prefix)

    def call_tool(self, tool_name, context):
        """
        统一调用接口
        tool_name: AI 请求的工具名称
        context: 包含 prefix, as_path 等信息的字典
        """
        tool_map = {
            "authority_check": self.authority,
            "geo_check": self.geo,
            "topology_check": self.topology,
            "neighbor_check": self.neighbor,
            "stability_analysis": self.stability
        }
        
        tool = tool_map.get(tool_name)
        if not tool:
            return f"SYSTEM_ERROR: 工具 '{tool_name}' 不存在。"
        
        try:
            # 执行工具逻辑
            result_str = tool.run(context)
            return f"[{tool_name.upper()}]: {result_str}"
        except Exception as e:
            return f"TOOL_ERROR: 运行 {tool_name} 时发生错误 - {str(e)}"

# 测试代码
if __name__ == "__main__":
    # 模拟一个测试场景：Rostelecom 劫持 Twitter
    fake_context = {
        "prefix": "104.244.42.0/24", 
        "as_path": "174 12389" 
    }
    
    toolkit = BGPToolKit()
    print("正在测试工具调用 (将会联网请求 RIPEstat)...")
    
    print(toolkit.call_tool("authority_check", fake_context))
    print(toolkit.call_tool("geo_check", fake_context))
    print(toolkit.call_tool("neighbor_check", fake_context))