# 拓扑与泄露检测
from .data_provider import BGPDataProvider
from .config_loader import get_tier1_asns

class TopologyInspector:
    """Valley-Free 违规检测，Tier-1 列表从知识库加载"""

    def run(self, context):
        as_path = context.get('as_path', "").split(" ")
        if len(as_path) < 3:
            return "NORMAL: 路径过短，无需检查。"

        tier1 = get_tier1_asns()
        for i in range(1, len(as_path) - 1):
            prev = as_path[i-1]
            curr = as_path[i]
            next_as = as_path[i+1]
            if prev in tier1 and next_as in tier1 and curr not in tier1:
                info = BGPDataProvider.get_as_info(curr)
                name = info.get('holder', curr)
                return f"ROUTE_LEAK: 疑似路由泄露！流量穿透了非骨干网 AS [{name} (AS{curr})]。"
                
        return "NORMAL: 未发现明显的 Valley-Free 违规或泄露模式。"