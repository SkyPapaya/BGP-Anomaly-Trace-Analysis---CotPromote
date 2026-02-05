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

try:
    from tools.data_provider import BGPDataProvider
    from tools.authority import AuthorityValidator
    from tools.geo import GeoConflictChecker
    from tools.topology import TopologyInspector
    from tools.config_loader import get_risk_asns
    ONLINE_AVAILABLE = True
except ImportError:
    ONLINE_AVAILABLE = False

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

    def call_tool(self, tool_name, context, is_batch=False):
        """
        统一工具调用入口
        :param tool_name: 工具名称 (字符串)
        :param context: 告警上下文 (字典)，批量时为 {updates: [...], time_window: {...}}
        :param is_batch: 是否为批量模式（多条 updates 综合溯源）
        """
        tool_name = str(tool_name).lower().strip()

        if tool_name == "path_forensics":
            return self.path_forensics(context, is_batch=is_batch)

        elif tool_name == "graph_analysis":
            return self.graph_analysis(context, is_batch=is_batch)

        elif tool_name == "authority_check":
            return self.authority_check(context, is_batch=is_batch)

        elif tool_name == "geo_check":
            return self.geo_check(context, is_batch=is_batch)

        elif tool_name == "neighbor_check":
            return self.neighbor_check(context, is_batch=is_batch)

        elif tool_name == "topology_check":
            return self.topology_check(context, is_batch=is_batch)

        else:
            return f"Error: Tool '{tool_name}' is not supported."

    # ==========================================
    # 🔍 [NEW] 核心溯源工具
    # ==========================================
    def path_forensics(self, context, is_batch=False):
        """
        【溯源核心】解析 AS Path，识别 Origin，并锁定攻击者。
        批量模式：对每条 update 分析，汇总统计各 AS 作为嫌疑人的频次。
        """
        if is_batch:
            return self._path_forensics_batch(context)

        as_path = context.get("as_path", "")
        expected_origin = context.get("expected_origin", "")

        if not as_path:
            return "ERROR: AS_PATH is empty in context."

        try:
            parts = as_path.replace(",", " ").split()
            path_list = [p.strip() for p in parts if p.strip().isdigit()]

            if not path_list:
                return "ERROR: No valid ASNs found in path."

            observed_origin = path_list[-1]
            upstream_neighbor = path_list[-2] if len(path_list) > 1 else "None (Direct Peer)"

            report = f"[Path Forensics Report]\n"
            report += f"- Analyzed Path sequence: {path_list}\n"
            report += f"- Observed Origin (Last Hop): AS{observed_origin}\n"
            report += f"- Expected Owner: AS{expected_origin}\n"

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

    def _path_forensics_batch(self, context):
        """批量 updates 路径取证：逐条分析 + 汇总统计"""
        updates = context.get("updates", [])
        if not updates:
            return "ERROR: updates 为空。"

        reports = []
        suspect_counts = {}  # AS -> 作为嫌疑人出现的次数
        leak_suspect_counts = {}  # AS -> 作为 Route Leak 嫌疑人的次数
        benign_count = 0

        for i, u in enumerate(updates):
            as_path = u.get("as_path", "")
            expected_origin = u.get("expected_origin", "")

            if not as_path:
                reports.append(f"[Update {i+1}] ERROR: AS_PATH 为空")
                continue

            try:
                parts = as_path.replace(",", " ").split()
                path_list = [p.strip() for p in parts if p.strip().isdigit()]
                if not path_list:
                    reports.append(f"[Update {i+1}] ERROR: 无有效 ASN")
                    continue

                observed_origin = path_list[-1]
                upstream = path_list[-2] if len(path_list) > 1 else None

                prefix = u.get("prefix", "?")
                line = f"[Update {i+1}] prefix={prefix} | path={path_list} | origin=AS{observed_origin} | expected=AS{expected_origin}"

                if str(observed_origin) != str(expected_origin):
                    line += " -> 🚨 SUSPECT: AS" + observed_origin
                    suspect_counts[observed_origin] = suspect_counts.get(observed_origin, 0) + 1
                else:
                    if upstream:
                        line += f" -> ⚠️ LEAK_CHECK: 上游 AS{upstream} 可能是 Leaker"
                        leak_suspect_counts[upstream] = leak_suspect_counts.get(upstream, 0) + 1
                    else:
                        line += " -> ✅ BENIGN"
                        benign_count += 1

                reports.append(line)
            except Exception as e:
                reports.append(f"[Update {i+1}] Error: {e}")

        # 汇总统计
        agg = "\n\n[📊 汇总统计 - 用于综合判断最有可能是攻击者的 AS]\n"
        agg += "-" * 50 + "\n"
        if suspect_counts:
            sorted_suspects = sorted(suspect_counts.items(), key=lambda x: -x[1])
            agg += "作为 Origin 且与合法 Owner 不符的 AS（嫌疑人）:\n"
            for asn, cnt in sorted_suspects:
                agg += f"  AS{asn}: 出现 {cnt} 次 (占比 {cnt}/{len(updates)})\n"
        if leak_suspect_counts:
            sorted_leak = sorted(leak_suspect_counts.items(), key=lambda x: -x[1])
            agg += "\nRoute Leak 情境下的上游嫌疑 AS:\n"
            for asn, cnt in sorted_leak:
                agg += f"  AS{asn}: {cnt} 次\n"
        agg += f"\n良性 update 数量: {benign_count}/{len(updates)}\n"
        agg += "\n建议: 出现频次最高的嫌疑 AS 最有可能是攻击者；若多条指向同一 AS，置信度更高。"

        return "\n".join(reports) + agg

    # ==========================================
    # 🕸️ Graph RAG (图谱分析)
    # ==========================================
    def graph_analysis(self, context, is_batch=False):
        """
        调用 Neo4j 检查 Origin 和 Owner 之间的真实拓扑距离。
        批量模式：对第一条 update 进行分析（或可扩展为对最可疑的 update 分析）
        """
        ctx = context
        if is_batch:
            updates = context.get("updates", [])
            ctx = updates[0] if updates else context
        if self.graph_engine:
            try:
                print("⚡ [Toolkit] Calling Neo4j Graph Engine...")
                return self.graph_engine.run_analysis(ctx)
            except Exception as e:
                return f"Graph Engine Error: {str(e)}"
        else:
            observed = ctx.get("detected_origin", "Unknown")
            expected = ctx.get("expected_origin", "Unknown")
            return (f"[Graph 离线] Neo4j 未连接，无法查询真实拓扑。"
                    f"建议运行 tools/import_real_word.py 导入 CAIDA 数据后启用 Neo4j。"
                    f" Observed AS{observed} vs Expected AS{expected}。")

    # ==========================================
    # 🛡️ 基础检测工具 (模拟实现，可对接外部API)
    # ==========================================
    def authority_check(self, context, is_batch=False):
        """检查 RPKI 状态，优先联网查询 RIPEstat API。批量模式：对每条 update 检查并汇总"""
        if is_batch:
            return self._authority_check_batch(context)
        if ONLINE_AVAILABLE:
            return AuthorityValidator().run(context)
        detected = context.get("detected_origin")
        expected = context.get("expected_origin")
        if str(detected) != str(expected):
            return f"RPKI Status: INVALID. AS{detected} is NOT authorized (offline fallback)."
        return "RPKI Status: VALID."

    def _authority_check_batch(self, context):
        """批量 RPKI 检查，联网查询"""
        updates = context.get("updates", [])
        if not updates:
            return "无 updates"
        validator = AuthorityValidator() if ONLINE_AVAILABLE else None
        lines = []
        invalid_asns = {}
        for i, u in enumerate(updates):
            if validator:
                res = validator.run(u)
                lines.append(f"[Update {i+1}] {res}")
                if "INVALID" in res:
                    origin = u.get("detected_origin", u.get("as_path", "").split()[-1] if u.get("as_path") else "?")
                    invalid_asns[origin] = invalid_asns.get(origin, 0) + 1
            else:
                detected = u.get("detected_origin")
                expected = u.get("expected_origin")
                prefix = u.get("prefix", "?")
                if str(detected) != str(expected):
                    lines.append(f"[Update {i+1}] INVALID: AS{detected} 非法宣告 {prefix}")
                    invalid_asns[detected] = invalid_asns.get(detected, 0) + 1
                else:
                    lines.append(f"[Update {i+1}] VALID: AS{detected}")
        if invalid_asns:
            lines.append(f"\n汇总: 非法 Origin AS 出现频次: {dict(invalid_asns)}")
        return "\n".join(lines)

    def geo_check(self, context, is_batch=False):
        """检查 AS 地理位置冲突，联网查询 RIPEstat MaxMind/Whois"""
        ctx = context.get("updates", [{}])[0] if is_batch and context.get("updates") else context
        if ONLINE_AVAILABLE:
            return GeoConflictChecker().run(ctx)
        return "Geo Check: 需要联网获取地理位置数据 (RIPEstat API)。"

    def neighbor_check(self, context, is_batch=False):
        """检查上游邻居信誉，联网获取 AS 信息，风险 AS 从知识库读取"""
        ctx = context.get("updates", [{}])[0] if is_batch and context.get("updates") else context
        path = ctx.get("as_path", "")
        if not path:
            return "EMPTY: 无路径信息"
        parts = path.replace(",", " ").split()
        first_hop = parts[0] if parts else ""
        if ONLINE_AVAILABLE:
            info = BGPDataProvider.get_as_info(first_hop)
            holder = info.get("holder", "Unknown ISP")
            risk_asns = get_risk_asns()
            if first_hop in risk_asns:
                r = risk_asns[first_hop]
                return f"Neighbor Risk: HIGH. [{holder} (AS{first_hop})] - {r.get('reason', 'known incidents')}."
            return f"INFO: 该异常路由由 [{holder} (AS{first_hop})] 传播。"
        risk = get_risk_asns()
        if first_hop in risk:
            return f"Neighbor Risk: HIGH. AS{first_hop} 在知识库中标记为风险 AS。"
        return "Neighbor Risk: LOW (无知识库风险标记)。"

    def topology_check(self, context, is_batch=False):
        """检查 Valley-Free 商业原则，Tier-1 从知识库加载，联网获取 AS 信息"""
        ctx = context.get("updates", [{}])[0] if is_batch and context.get("updates") else context
        if ONLINE_AVAILABLE:
            return TopologyInspector().run(ctx)
        return "Topology Check: 需要 TopologyInspector (联网 AS 信息)。"