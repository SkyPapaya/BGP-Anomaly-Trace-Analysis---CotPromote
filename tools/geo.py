from .data_provider import BGPDataProvider
from .config_loader import get_europe_region_codes

class GeoConflictChecker:
    def run(self, context):
        prefix = context.get('prefix')
        as_path = context.get('as_path', "").split(" ")
        origin_as = as_path[-1] if as_path else ""

        # 1. 查 IP 地理位置 (API 可能失败)
        prefix_country = BGPDataProvider.get_geo_location(prefix)
        
        # 2. 如果 IP 查不到，回退查目标 ASN (Twitter AS13414)
        if prefix_country == "UNKNOWN":
            # 假设它是 Twitter 的 IP，回退到查 AS13414
            prefix_country = BGPDataProvider.get_geo_location("13414")

        # 3. 查 Origin ASN 地理位置 (劫持者)
        origin_country = BGPDataProvider.get_geo_location(origin_as)

        if prefix_country == "UNKNOWN" or origin_country == "UNKNOWN":
            return f"SKIPPED: 数据缺失 (IP:{prefix_country}, Origin:{origin_country})。"

        if prefix_country != origin_country:
            eu = get_europe_region_codes()
            if prefix_country in eu and origin_country in eu:
                 return f"LOW_RISK: 地理不一致 ({prefix_country} vs {origin_country})，但在同一区域内。"

            return f"CONFLICT: 地理围栏警报！IP注册地 [{prefix_country}] 与 Origin AS 注册地 [{origin_country}] 不一致。"
        
        return f"MATCH: 两者均位于 [{prefix_country}]。"