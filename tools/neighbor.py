# 邻居传播分析
from .data_provider import BGPDataProvider

class NeighborPropagator:
    def run(self, context):
        as_path = context.get('as_path', "").split(" ")
        if not as_path: return "EMPTY: 无路径信息"

        first_hop = as_path[0]
        info = BGPDataProvider.get_as_info(first_hop)
        holder_name = info.get('holder', 'Unknown ISP')
        
        return f"INFO: 该异常路由是由 [{holder_name} (AS{first_hop})] 传播给采集器的。"