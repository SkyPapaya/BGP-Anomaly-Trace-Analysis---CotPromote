from .data_provider import BGPDataProvider
from .config_loader import get_known_prefix_origin

class AuthorityValidator:
    """RPKI 授权校验，优先联网查询 RIPEstat API，失败时使用知识库兜底"""

    def run(self, context):
        prefix = context.get('prefix')
        as_path = context.get('as_path', "").split(" ")
        origin_as = as_path[-1] if as_path else None
        
        if not origin_as: return "ERROR: 无法提取 Origin AS"

        # 1. 调用真实 API
        status = BGPDataProvider.get_rpki_status(prefix, origin_as)
        
        # --- 核心修复：处理 invalid_asn 和 invalid_length ---
        if status == 'valid':
            return f"VALID: [API] RPKI 验证通过 (Valid)。AS{origin_as} 是授权拥有者。"
        
        elif status and status.startswith('invalid'):
            # 这里会捕获 invalid_asn 和 invalid_length
            reason = "ASN不匹配" if "asn" in status else "掩码长度不匹配"
            return f"INVALID: [API] RPKI 验证失败 ({status})！AS{origin_as} 非法宣告 ({reason})。"

        # 2. 如果 API 返回 unknown 或网络失败，使用知识库兜底
        known = get_known_prefix_origin()
        expected = known.get(prefix)
        if not expected and prefix and prefix.startswith("104.244."):
            expected = "13414"

        if expected:
            if origin_as != expected:
                return f"INVALID (History): [历史库] API数据缺失，但根据档案，该前缀属于 AS{expected}，当前 Origin 非法。"
            else:
                return f"VALID (History): [历史库] 匹配已知历史归属。"

        return f"UNKNOWN: 未找到 RPKI ROA 记录 (API返回: {status})。"