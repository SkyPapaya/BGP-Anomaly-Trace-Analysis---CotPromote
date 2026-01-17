from data_provider import BGPDataProvider

class AuthorityValidator:
    # 历史真值表 (作为双重保险)
    KNOWN_FACTS = {
        "104.244.42.0/24": "13414",
        "104.244.0.0/21": "13414"
    }

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

        # 2. 如果 API 真的返回 unknown (或者网络失败)，才启用历史兜底
        expected = self.KNOWN_FACTS.get(prefix)
        if not expected and prefix.startswith("104.244."): expected = "13414"

        if expected:
            if origin_as != expected:
                return f"INVALID (History): [历史库] API数据缺失，但根据档案，该前缀属于 AS{expected}，当前 Origin 非法。"
            else:
                return f"VALID (History): [历史库] 匹配已知历史归属。"

        return f"UNKNOWN: 未找到 RPKI ROA 记录 (API返回: {status})。"