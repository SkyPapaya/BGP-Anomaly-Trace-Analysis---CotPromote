import requests
import logging
from functools import lru_cache

# 配置日志
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("RIPEstat_Data")

class BGPDataProvider:
    """
    RIPEstat Data API 接口层 (修复缓存 Bug 版)
    """
    BASE_URL = "https://stat.ripe.net/data"
    SOURCE_APP = "bgp-anomaly-analysis-tool"

    @staticmethod
    # [关键修改] 移除了这里的 @lru_cache，因为它不能处理 dict 参数
    def _fetch(endpoint, params):
        """
        通用 HTTP 请求器
        """
        url = f"{BGPDataProvider.BASE_URL}/{endpoint}/data.json"
        
        # 注入 SourceApp 标识
        if params is None: params = {}
        params['sourceapp'] = BGPDataProvider.SOURCE_APP
        
        try:
            resp = requests.get(url, params=params, timeout=15)
            if resp.status_code == 200:
                json_body = resp.json()
                return json_body.get('data', {})
            else:
                logger.warning(f"API Error [{endpoint}]: HTTP {resp.status_code} - {resp.url}")
        except Exception as e:
            logger.error(f"Connection Failed [{endpoint}]: {e}")
        return {}

    @staticmethod
    def _format_asn(asn, needs_prefix=False):
        """辅助函数：处理 ASN 格式"""
        asn_str = str(asn).upper().strip()
        if asn_str.startswith("AS"):
            clean_asn = asn_str[2:]
        else:
            clean_asn = asn_str
            
        if needs_prefix:
            return f"AS{clean_asn}"
        return clean_asn

    @staticmethod
    @lru_cache(maxsize=1024) # [保留] 这里参数是字符串，可以缓存
    def get_rpki_status(prefix, origin_as):
        """
        Endpoint: rpki-validation
        """
        # RPKI 接口通常使用纯数字 ASN
        fmt_asn = BGPDataProvider._format_asn(origin_as, needs_prefix=False)
        
        params = {
            "resource": fmt_asn,
            "prefix": prefix
        }
        data = BGPDataProvider._fetch("rpki-validation", params)
        return data.get("status", "unknown")

    @staticmethod
    @lru_cache(maxsize=1024) # [保留] 这里参数是字符串，可以缓存
    def get_as_info(asn):
        """
        Endpoint: as-overview
        """
        # AS Overview 接口通常需要 AS 前缀
        fmt_asn = BGPDataProvider._format_asn(asn, needs_prefix=True)
        
        params = {"resource": fmt_asn}
        data = BGPDataProvider._fetch("as-overview", params)
        
        holder = data.get("holder", f"{fmt_asn}")
        return {"holder": holder}

    @staticmethod
    @lru_cache(maxsize=1024) # [保留] 缓存地理位置查询结果
    def get_geo_location(resource):
        """
        Geo 统一入口
        """
        res_str = str(resource).strip()
        
        # 判断 ASN (AS开头 或 纯数字且无点冒号)
        is_asn = res_str.upper().startswith("AS") or (res_str.isdigit() and "." not in res_str and ":" not in res_str)
        
        if is_asn:
            fmt_res = BGPDataProvider._format_asn(res_str, needs_prefix=True)
            return BGPDataProvider._get_asn_country_via_whois(fmt_res)
        else:
            return BGPDataProvider._get_ip_country_via_maxmind(res_str)

    @staticmethod
    def _get_ip_country_via_maxmind(ip_resource):
        params = {"resource": ip_resource}
        data = BGPDataProvider._fetch("maxmind-geo-lite", params)
        
        try:
            resources = data.get("located_resources", [])
            if resources:
                locs = resources[0].get("locations", [])
                if locs:
                    return locs[0].get("country", "UNKNOWN")
        except Exception:
            pass
        return "UNKNOWN"

    @staticmethod
    def _get_asn_country_via_whois(asn_resource):
        params = {"resource": asn_resource}
        data = BGPDataProvider._fetch("whois", params)
        
        try:
            records = data.get("records", [])
            for block in records:
                for attr in block:
                    if attr.get("key", "").lower() == "country":
                        return attr.get("value", "UNKNOWN").upper()
        except Exception:
            pass
        return "UNKNOWN"

# --- 验证代码 ---
if __name__ == "__main__":
    print(">>> 开始 RIPEstat 接口格式验证 (Fix Cache Bug) <<<")
    
    # 1. RPKI
    print("\n[Test 1] RPKI Validation")
    rpki = BGPDataProvider.get_rpki_status("1.1.1.0/24", "13335")
    print(f"   Result: {rpki}")
    
    # 2. AS Overview
    print("\n[Test 2] AS Overview")
    as_info = BGPDataProvider.get_as_info("13335")
    print(f"   Result: {as_info['holder']}")

    # 3. Geo IP
    print("\n[Test 3] Geo (IP)")
    geo_ip = BGPDataProvider.get_geo_location("8.8.8.8")
    print(f"   Result: {geo_ip}")
    
    # 4. Geo ASN
    print("\n[Test 4] Geo (ASN)")
    geo_asn = BGPDataProvider.get_geo_location("AS12389")
    print(f"   Result: {geo_asn}")
    
    print("\n>>> 验证完成 <<<")