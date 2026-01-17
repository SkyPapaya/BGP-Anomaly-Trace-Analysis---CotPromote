#负责联网请求 RIPEstat API，并带有 LRU 缓存，防止重复请求拖慢速度。
import requests
import logging
from functools import lru_cache

# 配置日志
logging.basicConfig(level=logging.WARNING) # 只打印警告以上，保持清爽
logger = logging.getLogger("BGP_Data")

class BGPDataProvider:
    BASE_URL = "https://stat.ripe.net/data"
    SOURCE_APP = "bgp-research-agent"

    # --- 离线兜底数据库 ---
    OFFLINE_GEO_DB = {
        "12389": "RU", "13414": "US", "174": "US", 
        "104.244.42.0/24": "US", "2914": "JP"
    }
    OFFLINE_AS_NAMES = {
        "12389": "PJSC Rostelecom", "13414": "Twitter Inc.", "174": "Cogent"
    }

    @staticmethod
    @lru_cache(maxsize=2048)
    def get_rpki_status(prefix, origin_as):
        """调用 RIPE RPKI 验证 API"""
        url = f"{BGPDataProvider.BASE_URL}/rpki-validation/data.json"
        params = {"resource": origin_as, "prefix": prefix, "sourceapp": BGPDataProvider.SOURCE_APP}
        try:
            resp = requests.get(url, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                # RIPEstat 返回 valid, invalid_asn, invalid_length, unknown
                if 'data' in data and 'status' in data['data']:
                    return data['data']['status']
        except Exception:
            pass
        return "api_fail"

    @staticmethod
    @lru_cache(maxsize=2048)
    def get_as_info(asn):
        if str(asn) in BGPDataProvider.OFFLINE_AS_NAMES:
            return {"holder": BGPDataProvider.OFFLINE_AS_NAMES[str(asn)]}
        
        url = f"{BGPDataProvider.BASE_URL}/as-overview/data.json"
        params = {"resource": asn, "sourceapp": BGPDataProvider.SOURCE_APP}
        try:
            resp = requests.get(url, params=params, timeout=5)
            if resp.status_code == 200:
                return {"holder": resp.json().get('data', {}).get('holder', f"AS{asn}")}
        except Exception:
            pass
        return {"holder": f"AS{asn}"}

    @staticmethod
    @lru_cache(maxsize=2048)
    def get_geo_location(resource):
        # 1. 优先查离线库
        if str(resource) in BGPDataProvider.OFFLINE_GEO_DB:
            return BGPDataProvider.OFFLINE_GEO_DB[str(resource)]

        # 2. 如果是 ASN，API 查不了，直接返回 UNKNOWN
        if "." not in str(resource) and ":" not in str(resource):
            return "UNKNOWN"

        # 3. IP 走 API
        url = f"{BGPDataProvider.BASE_URL}/geoloc/data.json"
        params = {"resource": resource, "sourceapp": BGPDataProvider.SOURCE_APP}
        try:
            resp = requests.get(url, params=params, timeout=5)
            if resp.status_code == 200:
                locs = resp.json().get('data', {}).get('locations', [])
                if locs: return locs[0]['country']
        except Exception:
            pass
        return "UNKNOWN"