#拓扑与泄露检测
# tools/topology.py
from data_provider import BGPDataProvider

class TopologyInspector:
    # 知名 Tier-1 AS 列表 (硬编码以提高速度)
    TIER_1_ASNS = {
        "174", "209", "286", "701", "1239", "1299", "2914", "3257", "3320", 
        "3356", "3491", "5511", "6453", "6461", "6762", "6830", "7018", "12956", "6939"
    }

    def run(self, context):
        as_path = context.get('as_path', "").split(" ")
        if len(as_path) < 3:
            return "NORMAL: 路径过短，无需检查。"

        for i in range(1, len(as_path) - 1):
            prev = as_path[i-1]
            curr = as_path[i]
            next_as = as_path[i+1]
            
            # 检测 Tier1 -> 非Tier1 -> Tier1 的泄露模式
            if prev in self.TIER_1_ASNS and next_as in self.TIER_1_ASNS and curr not in self.TIER_1_ASNS:
                info = BGPDataProvider.get_as_info(curr)
                name = info.get('holder', curr)
                return f"ROUTE_LEAK: 疑似路由泄露！流量穿透了非骨干网 AS [{name} (AS{curr})]。"
                
        return "NORMAL: 未发现明显的 Valley-Free 违规或泄露模式。"