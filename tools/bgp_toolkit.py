import os
import json
import sys

# 尝试导入 Graph RAG 模块 (用于连接 Neo4j)
# 确保 tools 目录在 python 路径下
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from tools.graph_rag import BGPGraphRAG
    GRAPH_RAG_AVAILABLE = True
except ImportError:
    GRAPH_RAG_AVAILABLE = False
    print("⚠️ [Warning] graph_rag.py 未找到，Graph Analysis 将使用模拟模式。")

class BGPToolKit:
    def __init__(self):
        """
        初始化 BGP 工具箱
        """
        # 如果环境中有 Neo4j 且代码存在，初始化图分析引擎
        if GRAPH_RAG_AVAILABLE:
            try:
                # 注意：确保这里的密码和你 Docker 设置的一致 (whm161122309)
                self.graph_engine = BGPGraphRAG(password="whm161122309")
            except Exception as e:
                print(f"❌ [Error] Neo4j 连接失败: {e}")
                self.graph_engine = None
        else:
            self.graph_engine = None

    def call_tool(self, tool_name, context):
        """
        统一工具调用入口
        :param tool_name: 工具名称 (字符串)
        :param context: 告警上下文 (字典)
        """
        # 1. 清洗工具名称 (防止 AI 输出带空格或大小写不一致)
        tool_name = str(tool_name).lower().strip()
        
        # 2. 工具分发
        if tool_name == "path_forensics":
            return self.path_forensics(context)
        
        elif tool_name == "graph_analysis":
            return self.graph_analysis(context)
        
        elif tool_name == "authority_check":
            return self.authority_check(context)
        
        elif tool_name == "geo_check":
            return self.geo_check(context)
        
        elif tool_name == "neighbor_check":
            return self.neighbor_check(context)
            
        elif tool_name == "topology_check":
            return self.topology_check(context)
        
        else:
            return f"Error: Tool '{tool_name}' is not supported."

    # ==========================================
    # 🔍 [NEW] 核心溯源工具
    # ==========================================
    def path_forensics(self, context):
        """
        【溯源核心】解析 AS Path，识别 Origin，并锁定攻击者
        模仿 Google May 2005 报告的分析逻辑
        """
        as_path = context.get("as_path", "")
        expected_origin = context.get("expected_origin", "")
        
        if not as_path:
            return "ERROR: AS_PATH is empty in context."

        try:
            # 1. 提取路径中的各个 AS (处理逗号或空格分隔)
            parts = as_path.replace(",", " ").split()
            # 过滤掉非数字字符 (防止 AS_SET 括号等干扰)
            path_list = [p.strip() for p in parts if p.strip().isdigit()]
            
            if not path_list:
                return "ERROR: No valid ASNs found in path."

            # 2. 锁定 Origin (最右侧的 AS)
            observed_origin = path_list[-1]
            
            # 3. 锁定上游 (倒数第二个，用于分析 Route Leak)
            upstream_neighbor = path_list[-2] if len(path_list) > 1 else "None (Direct Peer)"

            # 4. 构建取证分析报告
            report = f"[Path Forensics Report]\n"
            report += f"- Analyzed Path sequence: {path_list}\n"
            report += f"- Observed Origin (Last Hop): AS{observed_origin}\n"
            report += f"- Expected Owner: AS{expected_origin}\n"
            
            # 5. 核心判断逻辑
            if str(observed_origin) != str(expected_origin):
                report += f"\n🚨 [CRITICAL FINDING]: Origin Mismatch!\n"
                report += f"The prefix is being originated by AS{observed_origin}, but belongs to AS{expected_origin}.\n"
                report += f"-> CONCLUSION: AS{observed_origin} is the PRIMARY SUSPECT (Attacker).\n"
                report += f"-> ACTION: Check if AS{observed_origin} has valid authorization (ROA). If not, this is a Hijack."
            else:
                report += f"\n✅ [STATUS]: Origin matches expected owner.\n"
                report += f"-> NEXT STEP: Check for Route Leak. The Upstream is AS{upstream_neighbor}.\n"
                report += f"   If AS{upstream_neighbor} is a Peer/Customer leaking routes to a Provider, then AS{upstream_neighbor} is the culprit."

            return report

        except Exception as e:
            return f"Error in path forensics analysis: {str(e)}"

    # ==========================================
    # 🕸️ Graph RAG (图谱分析)
    # ==========================================
    def graph_analysis(self, context):
        """
        调用 Neo4j 检查 Origin 和 Owner 之间的真实拓扑距离
        """
        if self.graph_engine:
            try:
                # 调用真实的 Neo4j 逻辑
                print("⚡ [Toolkit] Calling Neo4j Graph Engine...")
                return self.graph_engine.run_analysis(context)
            except Exception as e:
                return f"Graph Engine Error: {str(e)}"
        else:
            # 如果没连接数据库，返回模拟数据 (仅供测试)
            observed = context.get("detected_origin", "Unknown")
            expected = context.get("expected_origin", "Unknown")
            return f"[MOCK Graph Result] No direct business relationship found between AS{observed} and AS{expected}. Topology distance is infinite (disconnected)."

    # ==========================================
    # 🛡️ 基础检测工具 (模拟实现，可对接外部API)
    # ==========================================
    def authority_check(self, context):
        """检查 RPKI 状态"""
        detected = context.get("detected_origin")
        expected = context.get("expected_origin")
        if str(detected) != str(expected):
            return f"RPKI Status: INVALID. AS{detected} is NOT authorized to announce this prefix."
        return "RPKI Status: VALID."

    def geo_check(self, context):
        """简单检查 AS 地理位置是否冲突"""
        # 这里可以使用 GeoIP 库，这里做简单模拟
        return "Geo Check: No obvious country-level conflict detected (Simulation)."

    def neighbor_check(self, context):
        """检查上游邻居信誉"""
        path = context.get("as_path", "")
        if "12389" in path: # 例子：针对俄罗斯 ISP
             return "Neighbor Risk: HIGH. Path contains AS12389 (Rostelecom), known for past incidents."
        return "Neighbor Risk: LOW."

    def topology_check(self, context):
        """检查 Valley-Free 商业原则"""
        # 简单逻辑：如果路径包含 Tier-1 互联问题
        path = context.get("as_path", "")
        if "174" in path and "3356" in path:
            return "Topology Warning: Path traverses multiple Tier-1 ISPs, possible leak."
        return "Topology Status: Normal."