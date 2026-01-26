# tools/bgp_toolkit.py
from .authority import AuthorityValidator
from .geo import GeoConflictChecker
from .topology import TopologyInspector
from .neighbor import NeighborPropagator
from .stability import StabilityAnalyzer
from .graph_rag import BGPGraphRAG # 这里的引用不需要变，因为类名没变

class BGPToolKit:
    def __init__(self):
        self.authority = AuthorityValidator()
        self.geo = GeoConflictChecker()
        self.topology = TopologyInspector()
        self.neighbor = NeighborPropagator()
        self.stability = StabilityAnalyzer()
        
        # 初始化 Neo4j RAG (会自动连接数据库并注入数据)
        self.graph = BGPGraphRAG() 

    def update_state(self, prefix):
        self.stability.update_state(prefix)

    def call_tool(self, tool_name, context):
        tool_map = {
            "authority_check": self.authority,
            "geo_check": self.geo,
            "topology_check": self.topology,
            "neighbor_check": self.neighbor,
            "stability_analysis": self.stability,
            "graph_analysis": self.graph
        }
        
        tool = tool_map.get(tool_name)
        if not tool:
            return f"SYSTEM_ERROR: 工具 '{tool_name}' 不存在。"
        
        try:
            result_str = tool.run(context)
            return f"[{tool_name.upper()}]: {result_str}"
        except Exception as e:
            return f"TOOL_ERROR: 运行 {tool_name} 时发生错误 - {str(e)}"
        
  # 1. 拉取并启动 Neo4j 容器
# 设置密码为 "password" (生产环境请改复杂密码)

