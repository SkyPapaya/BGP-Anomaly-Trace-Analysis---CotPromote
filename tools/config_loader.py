"""
知识库与配置加载器
从 config/knowledge_base.json 读取，避免硬编码。
"""
import os
import json
import logging

logger = logging.getLogger("ConfigLoader")
_CONFIG = None
_CONFIG_PATH = None


def _default_path():
    """获取默认配置文件路径"""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "config", "knowledge_base.json")


def load_config(path=None):
    """加载知识库配置"""
    global _CONFIG, _CONFIG_PATH
    if path is None:
        path = _default_path()
    _CONFIG_PATH = path
    if not os.path.exists(path):
        logger.warning(f"知识库文件不存在: {path}，使用空配置")
        _CONFIG = {"entities": {}, "known_prefix_origin": {}, "tier1_asns": [], "risk_asns": {}, "europe_region_codes": []}
        return _CONFIG
    try:
        with open(path, "r", encoding="utf-8") as f:
            _CONFIG = json.load(f)
        return _CONFIG
    except Exception as e:
        logger.error(f"加载知识库失败: {e}")
        _CONFIG = {}
        return _CONFIG


def get_config(path=None):
    """获取配置（懒加载）"""
    global _CONFIG
    if _CONFIG is None:
        load_config(path)
    return _CONFIG


def get_entities():
    """获取实体列表，供数据生成器使用"""
    cfg = get_config()
    entities = cfg.get("entities", {})
    return {
        "VICTIMS": entities.get("victims", []),
        "ATTACKERS": entities.get("attackers", []),
        "TRANSIT": entities.get("transit", []),
        "LEGACY": entities.get("legacy_entities", []),
    }


def get_known_prefix_origin():
    """获取已知前缀归属（API 失败时的兜底）"""
    return get_config().get("known_prefix_origin", {})


def get_tier1_asns():
    """获取 Tier-1 AS 列表"""
    return set(get_config().get("tier1_asns", []))


def get_risk_asns():
    """获取风险 AS 列表（历史事件相关）"""
    return get_config().get("risk_asns", {})


def get_europe_region_codes():
    """获取欧洲地区代码（地理冲突判断用）"""
    return set(get_config().get("europe_region_codes", []))
